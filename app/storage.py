"""Доступ к фотографиям: SMB-шара Windows (боевой режим) или локальная папка (разработка).

Наружу (в браузер) пути не отдаются и обратно не принимаются: клиент знает
только непрозрачные id из индекса. Поэтому path traversal невозможен
по построению; проверки здесь — второй рубеж."""
from __future__ import annotations

import errno
import logging
import os
import socket
import stat as statmod
from pathlib import Path
from typing import BinaryIO, Iterator

log = logging.getLogger("photocloud.storage")

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif"}
VIDEO_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".webm"}
MEDIA_EXT = IMAGE_EXT | VIDEO_EXT
SKIP_NAMES = {"$recycle.bin", "system volume information", "thumbs.db", "desktop.ini", "@eadir", ".thumbnails"}
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# (относительный путь через '/', размер, mtime)
Item = tuple[str, int, float]


_FATAL_ERRNO = {errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTDIR, errno.EISDIR}


def _not_connection_error(e: BaseException) -> bool:
    """Ошибки, которые НЕ лечатся переподключением (нет файла, нет прав)."""
    return isinstance(e, ValueError) or getattr(e, "errno", None) in _FATAL_ERRNO


def _skip(name: str) -> bool:
    return name.startswith(".") or name.lower() in SKIP_NAMES


def _is_media(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in MEDIA_EXT


def _check_rel(rel: str) -> list[str]:
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") or "\\" in p or "\x00" in p or ":" in p for p in parts):
        raise ValueError("bad path")
    return parts


class LocalStorage:
    """ТОЛЬКО ДЛЯ ТЕСТОВ: фото из локальной папки. В проде будет удалено."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()

    def reachable(self) -> bool:
        return self.root.is_dir()

    def walk(self) -> Iterator[Item]:
        stack = [("", self.root)]
        while stack:
            prefix, d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError as e:
                log.warning("scandir %s: %s", prefix or "/", e)
                continue
            with it:
                for e in it:
                    if _skip(e.name) or e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                        continue
                    rel = f"{prefix}/{e.name}" if prefix else e.name
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    # Windows: скрытые, системные и точки повторной обработки пропускаем
                    if getattr(st, "st_file_attributes", 0) & (
                            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT):
                        continue
                    if statmod.S_ISDIR(st.st_mode):
                        stack.append((rel, e.path))
                    elif statmod.S_ISREG(st.st_mode) and _is_media(e.name):
                        yield rel, st.st_size, st.st_mtime

    def local_path(self, rel: str) -> Path:
        rp = self.root.joinpath(*_check_rel(rel)).resolve()
        if self.root not in rp.parents:
            raise PermissionError("outside root")
        return rp

    def open(self, rel: str) -> BinaryIO:
        return open(self.local_path(rel), "rb")


class SMBStorage:
    def __init__(self, s):
        import smbclient  # noqa: импорт здесь, чтобы локальный режим не требовал библиотеку
        self._smb = smbclient
        self.host, self.port = s.smb_host, s.smb_port
        self.base = f"\\\\{s.smb_host}\\{s.smb_share}"
        if s.smb_subdir:
            self.base += "\\" + s.smb_subdir.replace("/", "\\")
        self._creds = dict(username=s.smb_user, password=s.smb_password, port=s.smb_port,
                           encrypt=s.smb_encrypt, connection_timeout=5, require_signing=True)
        self._registered = False

    def reachable(self, timeout: float = 1.5) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False

    def _session(self) -> None:
        if not self._registered:
            self._smb.register_session(self.host, **self._creds)
            self._registered = True

    def reset(self) -> None:
        """После сна ПК соединение мёртвое — сбрасываем кэш подключений."""
        try:
            self._smb.reset_connection_cache(fail_on_error=False)
        except Exception:  # noqa: BLE001
            pass
        self._registered = False

    def _retry(self, fn):
        self._session()
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — smbprotocol кидает свои исключения
            if _not_connection_error(e):
                raise
            log.info("SMB: переподключение (%s)", type(e).__name__)
            self.reset()
            self._session()
            return fn()

    def walk(self) -> Iterator[Item]:
        # собираем список целиком внутри _retry, чтобы переподключение было атомарным
        def run() -> list[Item]:
            out: list[Item] = []
            stack = [("", self.base)]
            while stack:
                prefix, d = stack.pop()
                try:
                    entries = list(self._smb.scandir(d))
                except OSError as e:
                    if not _not_connection_error(e):
                        raise
                    log.warning("scandir %s: %s", prefix or "/", type(e).__name__)
                    continue
                for e in entries:
                    if _skip(e.name):
                        continue
                    info = e.smb_info
                    attrs = info.file_attributes
                    # точки повторной обработки (junction/symlink) пропускаем:
                    # они могут вести за пределы шары на стороне Windows
                    if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SYSTEM):
                        continue
                    rel = f"{prefix}/{e.name}" if prefix else e.name
                    if e.is_dir():
                        stack.append((rel, f"{d}\\{e.name}"))
                    elif _is_media(e.name) and not attrs & FILE_ATTRIBUTE_HIDDEN:
                        mtime = info.last_write_time.timestamp()
                        out.append((rel, int(info.end_of_file), mtime))
            return out

        yield from self._retry(run)

    def open(self, rel: str) -> BinaryIO:
        path = self.base + "\\" + "\\".join(_check_rel(rel))
        return self._retry(lambda: self._smb.open_file(path, mode="rb", share_access="rw"))


def make_storage(s):
    if s.storage == "local":
        return LocalStorage(s.local_root)
    return SMBStorage(s)
