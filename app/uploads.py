"""Прямой потоковый приём медиа с сайта в Restored на ПК.

Сервер НЕ сохраняет медиа в DATA_DIR, SQLite или временных файлах:
отдельные HTTP-блоки сразу записываются в SMB-шару Restored.
Только на ПК остаются полученные файлы и маленькие JSON-квитанции.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from .storage import MEDIA_EXT

UPLOAD_PREFIX = "PhotoCloud-Uploads"
CHUNK_MAX = 4 * 1024 * 1024
FILE_MAX = 4 * 1024**3
UPLOAD_MAX = 3000
ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_BAD_WINDOWS = re.compile(r"^(?:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$", re.I)


def windows_component(value: str) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 200:
        raise ValueError("недопустимое имя")
    if (value in (".", "..") or value.endswith((".", " ")) or
            any(ord(c) < 32 or c in '\\/:*?"<>|' for c in value) or _BAD_WINDOWS.fullmatch(value)):
        raise ValueError("недопустимое имя Windows")
    return value


def media_name(value: str) -> str:
    name = windows_component(value)
    if Path(name).suffix.lower() not in MEDIA_EXT:
        raise ValueError("формат не поддерживается")
    return name


def destination_folder(value: str) -> str:
    if not isinstance(value, str) or len(value) > 1500:
        raise ValueError("папка слишком длинная")
    if not value:
        return ""                 # корень архива
    parts = value.split("/")
    if len(parts) > 24:
        raise ValueError("слишком глубокая вложенность папок")
    for part in parts:
        windows_component(part)
        if part.casefold() in ("restored", ".photocloud", UPLOAD_PREFIX.casefold()):
            raise ValueError("служебная папка недоступна")
    return "/".join(parts)


def import_path(folder: str, name: str) -> str:
    return (destination_folder(folder) + "/" if folder else "") + media_name(name)



def duplicate_status(size: int, existing: int | None) -> str:
    """Имя совпало: меньший/равный — дубль, больший — решение администратора."""
    if existing is None:
        return "new"
    return "larger" if size > existing else "duplicate"


class UploadQueue:
    """Активные передачи только в RAM, готовые файлы + манифесты только на ПК."""

    def __init__(self, writer):
        self.writer = writer
        self.mu = threading.RLock()
        self.active = {}
        self.received = {}
        self.last_refresh = 0.0
        self.done = {}

    def _validate_id(self, ident):
        if not isinstance(ident, str) or not ID_PATTERN.fullmatch(ident):
            raise ValueError("неверный идентификатор")
        return ident

    def _roots(self, ident, name):
        self._validate_id(ident)
        media_name(name)
        rel = f"{UPLOAD_PREFIX}/{ident}/{name}"
        if self.writer.local:
            parent = self.writer.storage.root / "Restored" / UPLOAD_PREFIX / ident
            return parent, parent / name, parent / (name + ".photocloud-part")
        root = self.writer.root + "\\" + UPLOAD_PREFIX + "\\" + ident
        return root, root + "\\" + name, root + "\\" + name + ".photocloud-part"

    def _open_source(self, path):
        if self.writer.local:
            return open(path, "rb")
        return self.writer._smb.open_file(path, mode="rb", share_access="rw", **self.writer._kw)

    def _remove(self, path):
        if self.writer.local:
            Path(path).unlink(missing_ok=True)
        else:
            self.writer._smb.remove(path, **self.writer._kw)

    def _write_json(self, path, data):
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > 8 * 1024:
            raise ValueError("метаданные слишком большие")
        tmp = str(path) + ".photocloud-part"
        if self.writer.local:
            with open(tmp, "xb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        else:
            with self.writer._smb.open_file(tmp, mode="xb", **self.writer._kw) as f:
                f.write(raw)
            self.writer._smb.rename(tmp, path, **self.writer._kw)

    def start(self, user: str, name: str, folder: str, size: int, mtime: float) -> dict:
        """Создать временный файл СРАЗУ на ПК, до принятия первого HTTP-блока."""
        name, folder = media_name(name), destination_folder(folder)
        if type(size) is not int or not 0 < size <= FILE_MAX:
            raise ValueError("недопустимый размер файла")
        if not isinstance(mtime, (int, float)) or not 0 < mtime < time.time() + 7*86400:
            mtime = time.time()
        if not self.writer.enabled:
            raise ConnectionError("папка Restored недоступна для записи")
        with self.mu:
            # Брошенные браузером передачи: закрыть SMB-файлы через 30 минут
            # отсутствия блоков. Удаляем только частичные файлы на ПК.
            stale = [key for key, obj in self.active.items()
                     if obj["state"] == "uploading"
                     and time.monotonic() - obj["last_activity"] > 1800]
            for key in stale:
                self._abort_unlocked(key)
            if len(self.active) >= 10:
                raise ValueError("слишком много одновременных передач")
            ident = secrets.token_hex(16)
            parent, target, tmp = self._roots(ident, name)
            if self.writer.local:
                parent.mkdir(parents=True, exist_ok=False)
                stream = open(tmp, "xb")
            else:
                smb, kw = self.writer._smb, self.writer._kw
                smb.register_session(self.writer.host, **kw)
                self.writer._mkdirs(self.writer.root, [UPLOAD_PREFIX, ident])
                stream = smb.open_file(tmp, mode="xb", **kw)
            self.active[ident] = {
                "user": user, "id": ident, "name": name, "folder": folder,
                "size": size, "mtime": float(mtime), "offset": 0,
                "shaobj": hashlib.sha256(), "stream": stream, "tmp": tmp,
                "target": target, "parent": parent, "state": "uploading",
                "created": time.time(), "last_activity": time.monotonic(),
            }
            return {"id": ident, "offset": 0, "size": size}

    def chunk(self, ident: str, user: str, offset: int, data: bytes) -> int:
        if not data or len(data) > CHUNK_MAX or type(offset) is not int:
            raise ValueError("неверный блок передачи")
        with self.mu:
            item = self.active.get(ident)
            if not item or item["user"] != user or item["state"] != "uploading":
                raise ValueError("загрузка недоступна")
            if offset != item["offset"] or offset + len(data) > item["size"]:
                raise ValueError("неправильное смещение блока")
            try:
                written = item["stream"].write(data)
                if written is not None and written != len(data):
                    raise OSError("неполная запись на ПК")
                item["stream"].flush()
                item["shaobj"].update(data)
                item["offset"] += len(data)
                item["last_activity"] = time.monotonic()
            except BaseException:
                self._abort_unlocked(ident)
                raise
            return item["offset"]

    def _abort_unlocked(self, ident):
        item = self.active.pop(ident, None)
        if not item:
            return
        try:
            item["stream"].close()
        except OSError:
            pass
        for path in (item["tmp"], item["target"] if item.get("promoted") else None):
            if path is not None:
                try:
                    self._remove(path)
                except OSError:
                    pass

    def cancel(self, ident, user):
        with self.mu:
            item = self.active.get(ident)
            if not item or item["user"] != user:
                return False
            self._abort_unlocked(ident)
            return True

    def finish(self, ident: str, user: str) -> dict:
        with self.mu:
            item = self.active.get(ident)
            if not item or item["user"] != user or item["state"] != "uploading":
                raise ValueError("передача файла не найдена")
            if item["offset"] != item["size"]:
                raise ValueError("не все блоки получены")
            item["state"] = "finishing"
            try:
                item["stream"].close()
                sha = item["shaobj"].hexdigest()
                # Прочитать копию непосредственно с ПК, чтобы подтвердить
                # целостность SMB-записи; никаких буферов всего файла на сервере.
                remote_hash = hashlib.sha256()
                remote_size = 0
                with self._open_source(item["tmp"]) as inp:
                    while True:
                        chunk = inp.read(CHUNK_MAX)
                        if not chunk:
                            break
                        remote_size += len(chunk)
                        if remote_size > item["size"]:
                            raise OSError("файл на ПК больше исходного")
                        remote_hash.update(chunk)
                if remote_size != item["size"] or remote_hash.hexdigest() != sha:
                    raise OSError("файл на ПК не прошёл проверку SHA-256")
                if self.writer.local:
                    os.utime(item["tmp"], (item["mtime"], item["mtime"]))
                    os.rename(item["tmp"], item["target"])
                else:
                    self.writer._smb.utime(item["tmp"], times=(item["mtime"], item["mtime"]), **self.writer._kw)
                    self.writer._smb.rename(item["tmp"], item["target"], **self.writer._kw)
                item["promoted"] = True
                manifest = {key: item[key] for key in ("id", "user", "name", "folder", "size", "mtime", "created")}
                manifest.update({"sha": sha,
                                 "staged": f"{UPLOAD_PREFIX}/{ident}/{item['name']}",
                                 "state": "ready"})
                manifest_path = (item["parent"] / "manifest.json" if self.writer.local
                                 else item["parent"] + "\\manifest.json")
                self._write_json(manifest_path, manifest)
                self.active.pop(ident, None)
                self.received[ident] = manifest
                self.last_refresh = time.monotonic()
                return dict(manifest)
            except BaseException:
                self._abort_unlocked(ident)
                raise

    def _read_manifest(self, ident):
        parent, _, _ = self._roots(ident, "x.jpg")
        path = parent / "manifest.json" if self.writer.local else parent + "\\manifest.json"
        try:
            with self._open_source(path) as f:
                raw = f.read(8193)
        except (FileNotFoundError, OSError):
            return None
        if len(raw) > 8192:
            return None
        try:
            item = json.loads(raw)
            if (not isinstance(item, dict) or item.get("id") != ident or
                    item.get("state") != "ready" or
                    item.get("name") != media_name(item.get("name")) or
                    item.get("folder") != destination_folder(item.get("folder")) or
                    item.get("staged") != f"{UPLOAD_PREFIX}/{ident}/{item['name']}" or
                    not isinstance(item.get("size"), int) or not 0 < item["size"] <= FILE_MAX or
                    not re.fullmatch("[0-9a-f]{64}", item.get("sha", ""))):
                return None
            return item
        except (TypeError, KeyError, ValueError, json.JSONDecodeError):
            return None

    def _list_received(self):
        if self.writer.local:
            base = self.writer.storage.root / "Restored" / UPLOAD_PREFIX
            if not base.exists():
                return []
            names = [entry.name for entry in base.iterdir() if entry.is_dir()]
        else:
            smb = self.writer._smb
            base = self.writer.root + "\\" + UPLOAD_PREFIX
            try:
                names = smb.listdir(base, **self.writer._kw)
            except OSError:
                return []
        result = []
        for ident in names[:UPLOAD_MAX]:
            if ID_PATTERN.fullmatch(ident):
                item = self._read_manifest(ident)
                if item:
                    result.append(item)
        return result

    def list(self, states=("ready",)):
        # Только подтверждённые, уже реально находящиеся на ПК файлы.
        with self.mu:
            if time.monotonic() - self.last_refresh > 15:
                items = self._list_received()
                self.received = {item["id"]: item for item in items}
                self.last_refresh = time.monotonic()
            return [dict(item) for item in sorted(self.received.values(), key=lambda x: x["created"], reverse=True)
                    if item["state"] in states][:UPLOAD_MAX]

    def pending_sizes(self) -> dict[tuple[str, str], int]:
        """Сравниваем с уже полученными в Restored и текущими загрузками.

        Максимальный размер учитывает все экземпляры имени в одной папке.
        """
        existing = {}
        items = self.list(("ready",))
        with self.mu:
            items.extend(dict(x) for x in self.active.values())
        for item in items:
            if item.get("state") not in ("ready", "uploading", "finishing"):
                continue
            key = (item["folder"].casefold(), item["name"].casefold())
            existing[key] = max(existing.get(key, -1), int(item["size"]))
        return existing

    def get(self, ident):
        self._validate_id(ident)
        with self.mu:
            item = self.received.get(ident)
            if not item:
                item = self._read_manifest(ident)
                if item:
                    self.received[ident] = item
            return dict(item) if item else None

    def open_received(self, ident):
        item = self.get(ident)
        if not item:
            raise FileNotFoundError("загрузка отсутствует")
        _parent, target, _tmp = self._roots(item["id"], item["name"])
        return item, self._open_source(target)

    def iter_media(self, ident, chunk_size=256*1024):
        _item, source = self.open_received(ident)
        with source:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def discard(self, ident: str, sha: str) -> bool:
        """Стереть ТОЛЬКО подтверждённую веб-загрузку из Restored.

        Отдельный ID и SHA защищают от устаревшего выбора; имя и путь берём
        исключительно из проверенного манифеста на ПК, не из запроса клиента.
        Ни исходные файлы галереи, ни другие копии из Restored не затрагиваем.
        """
        import stat
        self._validate_id(ident)
        if not isinstance(sha, str) or not re.fullmatch("[0-9a-f]{64}", sha):
            raise ValueError("некорректная контрольная сумма")
        with self.mu:
            item = self.get(ident)
            if not item or item["state"] != "ready" or item["sha"] != sha:
                raise ValueError("файл больше не ожидает переноса или версия изменилась")
            parent, media, _part = self._roots(ident, item["name"])
            manifest = (parent / "manifest.json" if self.writer.local
                        else parent + "\\manifest.json")
            # Проверяем ТЕКУЩИЙ манифест непосредственно на ПК, а не
            # старый кэш (удаление не допускает доверия к локальному списку).
            current = self._read_manifest(ident)
            if not current or current["sha"] != sha or current["name"] != item["name"]:
                raise ValueError("манифест изменился — обновите список")
            try:
                if self.writer.local:
                    # Не следовать junction/symlink в каталоге отдельной загрузки.
                    root = self.writer.storage.root.resolve()
                    base = root / "Restored" / UPLOAD_PREFIX
                    if (base.is_symlink() or parent.is_symlink()
                            or (getattr(parent.lstat(), "st_file_attributes", 0) & 0x400)
                            or parent.resolve() != base.resolve() / ident):
                        raise ValueError("папка загрузки была перенаправлена")
                    info = media.lstat()
                    if (not stat.S_ISREG(info.st_mode) or media.is_symlink()
                            or getattr(info, "st_file_attributes", 0) & 0x400):
                        raise ValueError("загруженный файл больше не является обычным файлом")
                    actual_size = info.st_size
                else:
                    info = self.writer._smb.stat(media, **self.writer._kw)
                    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        raise ValueError("загруженный файл больше не является обычным файлом")
                    actual_size = info.st_size
                if actual_size != item["size"]:
                    raise ValueError("файл изменился; удаление заблокировано")
            except FileNotFoundError:
                # Не оставить осиротевший манифест, если медиа уже отсутствует.
                pass
            else:
                self._remove(media)          # удаляем только Restored/PhotoCloud-Uploads/{id}/{name}
            self._remove(manifest)           # после медиа: при сбое возможен безопасный повтор
            self.received.pop(ident, None)
            self.last_refresh = 0.0
            try:
                if self.writer.local:
                    parent.rmdir()
                else:
                    self.writer._smb.rmdir(parent, **self.writer._kw)
            except OSError:
                pass
            return True

    def completed(self, ident, destination):
        with self.mu:
            item = self.get(ident)
            if not item:
                return self.done.get(ident) == destination
            destination_folder(destination.rpartition("/")[0])
            media_name(destination.rpartition("/")[2])
            parent, _, _ = self._roots(ident, item["name"])
            manifest = parent / "manifest.json" if self.writer.local else parent + "\\manifest.json"
            self._remove(manifest)
            self.received.pop(ident, None)
            self.done[ident] = destination
            self.last_refresh = time.monotonic()
            return True
