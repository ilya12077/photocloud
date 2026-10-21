"""Доступ к фотографиям: SMB-шара Windows (боевой режим) или локальная папка (разработка).

Наружу (в браузер) пути не отдаются и обратно не принимаются: клиент знает
только непрозрачные id из индекса. Поэтому path traversal невозможен
по построению; проверки здесь — второй рубеж."""
from __future__ import annotations

import errno
import logging
import os
import threading
import time
import socket
import stat as statmod
from pathlib import Path
from typing import BinaryIO, Iterator

log = logging.getLogger("photocloud.storage")

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif"}
VIDEO_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".webm", ".mts", ".m2ts", ".avi"}
# браузер умеет играть только эти; остальные (видеокамеры AVCHD, старые AVI) — эскиз + скачать
PLAYABLE_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".webm"}
MEDIA_EXT = IMAGE_EXT | VIDEO_EXT
SKIP_NAMES = {"$recycle.bin", "system volume information", "thumbs.db", "desktop.ini", "@eadir", ".thumbnails"}
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# (относительный путь через '/', размер, mtime)
Item = tuple[str, int, float]


_FATAL_ERRNO = {errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTDIR, errno.EISDIR}


# NtStatus, при которых соединение/сессия действительно умерли — тогда переподключаемся
_RECONNECT_NT = {
    0xC0000203,  # STATUS_USER_SESSION_DELETED
    0xC000035C,  # STATUS_NETWORK_SESSION_EXPIRED
    0xC00000C9,  # STATUS_NETWORK_NAME_DELETED
    0xC000020C,  # STATUS_CONNECTION_DISCONNECTED
    0xC000013B,  # STATUS_LOCAL_DISCONNECT
    0xC000013C,  # STATUS_REMOTE_DISCONNECT
    0xC0000241,  # STATUS_CONNECTION_ABORTED
    0xC0000236,  # STATUS_CONNECTION_REFUSED
}
NT_REQUEST_NOT_ACCEPTED = 0xC00000D0   # Windows: исчерпан лимит входящих SMB-подключений


def _ntstatus(e: BaseException) -> int | None:
    v = getattr(e, "ntstatus", None)
    if v is None and e.__cause__ is not None:
        v = getattr(e.__cause__, "status", None)
    return v


def _not_connection_error(e: BaseException) -> bool:
    """Ошибки, которые НЕ лечатся переподключением: нет файла, нет прав, нет шары,
    файл занят и т.п. Раньше любой такой ответ Windows вызывал полное переподключение —
    при параллельных запросах это плодило сессии до лимита Windows («REQUEST_NOT_ACCEPTED»)."""
    if isinstance(e, ValueError) or getattr(e, "errno", None) in _FATAL_ERRNO:
        return True
    nt = _ntstatus(e)
    return nt is not None and nt not in _RECONNECT_NT


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


# Одно SMB-соединение обслуживает все потоки. Windows выдаёт ему ограниченное число
# «кредитов» на одновременные запросы; если запросов больше, smbprotocol не ждёт, а
# падает с «Request requires 1 credits but only 0 credits are available». Поэтому
# одновременных сетевых операций — не больше SMB_PARALLEL, а нехватку кредитов
# пережидаем короткой паузой (это не обрыв связи — переподключаться нельзя).
SMB_PARALLEL = 6
_gate = threading.BoundedSemaphore(SMB_PARALLEL)


def _is_credit_error(e: BaseException) -> bool:
    return "credits" in str(e) and "available" in str(e)


_active: dict[int, float] = {}          # операция -> когда началась (для сторожа)
_active_mu = threading.Lock()
GATE_WAIT = 30                          # дольше не ждём свободного слота — отдаём ошибку, клиент повторит
HANG_AFTER = 40                         # сетевая операция дольше — считаем, что SMB завис


def _gated(fn, *a, **kw):
    for attempt in range(6):
        if not _gate.acquire(timeout=GATE_WAIT):
            raise TimeoutError("SMB: все слоты заняты")
        key = id(threading.current_thread()) ^ int(time.monotonic() * 1e6)
        with _active_mu:
            _active[key] = time.monotonic()
        try:
            return fn(*a, **kw)
        except Exception as e:  # noqa: BLE001
            if not _is_credit_error(e) or attempt == 5:
                raise
        finally:
            with _active_mu:
                _active.pop(key, None)
            _gate.release()
        time.sleep(0.05 * (attempt + 1))


class _SMBFile:
    """Файл с шары: каждое чтение и закрытие проходит через общий «шлюз»."""

    def __init__(self, f):
        self._f = f

    def read(self, n: int = -1) -> bytes:
        return _gated(self._f.read, n)

    def seek(self, *a):
        return self._f.seek(*a)            # локальная операция, сеть не трогает

    def tell(self) -> int:
        return self._f.tell()

    def close(self) -> None:
        try:
            _gated(self._f.close)
        except Exception:  # noqa: BLE001 — закрытие после обрыва связи не должно ронять запрос
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


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
        self._mu = threading.RLock()
        self._reset_at = 0.0
        self._warned = 0.0
        threading.Thread(target=self._watchdog, name="smb-watchdog", daemon=True).start()

    def _watchdog(self) -> None:
        """Если Windows перестала отвечать посреди запроса, smbprotocol ждёт ответа вечно,
        и занятые слоты блокируют всё приложение. Сторож рвёт такое соединение — зависшие
        вызовы получают ошибку, клиенты повторяют запрос уже по новому подключению."""
        while True:
            time.sleep(5)
            with _active_mu:
                oldest = min(_active.values(), default=None)
            if oldest is not None and time.monotonic() - oldest > HANG_AFTER:
                log.warning("SMB: запрос висит дольше %d с — сбрасываю соединение", HANG_AFTER)
                with self._mu:
                    self._reset_locked()
                with _active_mu:
                    _active.clear()

    def reachable(self, timeout: float = 1.5) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False

    def reset(self) -> None:
        """После сна ПК соединение мёртвое — сбрасываем кэш подключений."""
        with self._mu:
            self._reset_locked()

    def _reset_locked(self) -> None:
        try:
            self._smb.reset_connection_cache(fail_on_error=False)
        except Exception:  # noqa: BLE001
            pass
        self._registered = False
        self._reset_at = time.time()

    def _session(self) -> None:
        with self._mu:
            if not self._registered:
                self._smb.register_session(self.host, **self._creds)
                self._registered = True

    def _retry(self, fn):
        self._session()
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — smbprotocol кидает свои исключения
            if _ntstatus(e) == NT_REQUEST_NOT_ACCEPTED:
                now = time.time()
                if now - self._warned > 60:
                    self._warned = now
                    log.warning("SMB: компьютер не принимает новые подключения (REQUEST_NOT_ACCEPTED). "
                                "Windows 10/11 допускает ~20 входящих SMB-сессий — закрой лишние "
                                "подключения к шаре или перезагрузи ПК")
                raise
            if _not_connection_error(e) or _is_credit_error(e):
                raise
            # переподключаемся не чаще раза в 10 с и одним потоком: остальные просто повторяют
            with self._mu:
                if time.time() - self._reset_at > 10:
                    log.info("SMB: переподключение (%s)", type(e).__name__)
                    self._reset_locked()
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
                    entries = _gated(lambda: list(self._smb.scandir(d, port=self.port)))
                except OSError as e:
                    # корень шары недоступен (нет шары, нет прав, лимит подключений) — это ошибка
                    # индексации целиком; недоступная подпапка — просто пропускаем её
                    if not prefix or not _not_connection_error(e) or _ntstatus(e) == NT_REQUEST_NOT_ACCEPTED:
                        raise
                    log.warning("scandir %s: %s", prefix, type(e).__name__)
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
        return _SMBFile(self._retry(
            lambda: _gated(self._smb.open_file, path, mode="rb", share_access="rw", port=self.port)))


def make_storage(s):
    if s.storage == "local":
        return LocalStorage(s.local_root)
    return SMBStorage(s)
