"""Приём медиа в DATA_DIR и очередь переноса через Restored на основном ПК.

Единственное SMB-место записи — Restored/PhotoCloud-Uploads. Архив не
перезаписывается сервером; локальный клиент ПК решает, куда импортировать файлы.
"""
from __future__ import annotations

import hashlib
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



def thumbnail(path: Path, name: str) -> bytes:
    """Безопасный компактный WebP для очереди загруженных изображений."""
    import io
    from PIL import Image, ImageOps
    if Path(name).suffix.lower() not in {
        ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif"
    }:
        return b""
    try:
        with Image.open(path) as img:
            if img.width * img.height > 75_000_000:
                return b""
            img = ImageOps.exif_transpose(img)
            img.thumbnail((380, 380))
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")
            out = io.BytesIO()
            img.save(out, "WEBP", quality=72, method=2)
            return out.getvalue()
    except Exception:
        return b""

class UploadQueue:
    """Одна БД на сервере, и на каждый запрос ровно одна SQLite-операция под DB.mu."""
    def __init__(self, db, root: Path):
        self.db = db
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.mu = threading.RLock()
        db.run("""CREATE TABLE IF NOT EXISTS uploads (
            id TEXT PRIMARY KEY, user TEXT NOT NULL, name TEXT NOT NULL,
            folder TEXT NOT NULL, size INTEGER NOT NULL, mtime REAL NOT NULL,
            offset INTEGER NOT NULL DEFAULT 0, sha TEXT NOT NULL DEFAULT '',
            staged TEXT NOT NULL DEFAULT '', state TEXT NOT NULL,
            created REAL NOT NULL, completed REAL NOT NULL DEFAULT 0,
            destination TEXT NOT NULL DEFAULT ''
        )""")
        db.run("CREATE INDEX IF NOT EXISTS uploads_state ON uploads(state,created)")
        # В случае перезапуска посреди SMB-передачи пробуем снова.
        db.run("UPDATE uploads SET state='queued' WHERE state='staging'")

    def path(self, ident: str) -> Path:
        if not isinstance(ident, str) or not ID_PATTERN.fullmatch(ident):
            raise ValueError("неверный идентификатор")
        return self.root / (ident + ".part")

    def _row(self, ident: str):
        rows = self.db.run("""SELECT id,user,name,folder,size,mtime,offset,sha,staged,state,created,completed,destination
                              FROM uploads WHERE id=?""", (ident,))
        return dict(zip(("id","user","name","folder","size","mtime","offset","sha","staged",
                         "state","created","completed","destination"), rows[0])) if rows else None

    def get(self, ident: str):
        return self._row(ident) if isinstance(ident, str) and ID_PATTERN.fullmatch(ident) else None

    def list(self, states=("queued","staging","ready")):
        allowed = tuple(s for s in states if s in ("queued","staging","ready","done","uploading"))
        if not allowed:
            return []
        cols = ("id","user","name","folder","size","mtime","offset","sha","staged",
                "state","created","completed","destination")
        rows = self.db.run("SELECT " + ",".join(cols) + " FROM uploads WHERE state IN ("
                           + ",".join("?" for _ in allowed)
                           + ") ORDER BY created DESC LIMIT 3000", allowed)
        return [dict(zip(cols, row)) for row in rows]

    def start(self, user: str, name: str, folder: str, size: int, mtime: float) -> dict:
        name, folder = media_name(name), destination_folder(folder)
        if type(size) is not int or not 0 < size <= FILE_MAX:
            raise ValueError("недопустимый размер файла")
        if not isinstance(mtime, (int,float)) or not 0 < mtime < time.time() + 86400 * 7:
            mtime = time.time()
        with self.mu:
            count = self.db.run("SELECT count(*) FROM uploads WHERE state != 'done'")[0][0]
            if count >= UPLOAD_MAX:
                raise ValueError("очередь загрузки заполнена")
            ident = secrets.token_hex(16)
            with self.path(ident).open("xb"):
                pass
            try:
                self.db.run("""INSERT INTO uploads(id,user,name,folder,size,mtime,state,created)
                               VALUES(?,?,?,?,?,?,'uploading',?)""",
                            (ident,user,name,folder,size,float(mtime),time.time()))
            except BaseException:
                self.path(ident).unlink(missing_ok=True)
                raise
            return {"id":ident,"offset":0,"size":size}

    def chunk(self, ident: str, user: str, offset: int, data: bytes) -> int:
        if not data or len(data) > CHUNK_MAX or type(offset) is not int:
            raise ValueError("неверный блок загрузки")
        with self.mu:
            item=self.get(ident)
            if not item or item["user"] != user or item["state"] != "uploading":
                raise ValueError("загрузка недоступна")
            if offset != item["offset"] or offset+len(data) > item["size"]:
                raise ValueError("смещение блока не совпадает")
            path=self.path(ident)
            with path.open("r+b") as f:
                if f.seek(0, os.SEEK_END) != offset:
                    raise ValueError("размер временного файла изменился")
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.db.run("UPDATE uploads SET offset=? WHERE id=? AND offset=?",
                        (offset+len(data),ident,offset))
            return offset+len(data)

    def finish(self, ident: str, user: str) -> dict:
        with self.mu:
            item=self.get(ident)
            if not item or item["user"] != user:
                raise ValueError("загрузка недоступна")
            if item["state"] != "uploading":
                if item["state"] in ("queued","staging","ready"):
                    return item
                raise ValueError("загрузка уже закрыта")
            p=self.path(ident)
            if item["offset"] != item["size"] or p.stat().st_size != item["size"]:
                raise ValueError("переданы не все части файла")
            h=hashlib.sha256()
            with p.open("rb") as f:
                for part in iter(lambda: f.read(4*1024*1024), b""):
                    h.update(part)
            sha=h.hexdigest()
            self.db.run("UPDATE uploads SET state='queued',sha=? WHERE id=? AND state='uploading'",
                        (sha,ident))
            return self.get(ident)

    def cancel(self, ident: str, user: str) -> bool:
        with self.mu:
            item=self.get(ident)
            if not item or item["user"] != user or item["state"] != "uploading":
                return False
            self.db.run("DELETE FROM uploads WHERE id=? AND state='uploading'", (ident,))
            self.path(ident).unlink(missing_ok=True)
            return True

    def next_to_stage(self):
        rows = self.db.run("SELECT id FROM uploads WHERE state='queued' ORDER BY created LIMIT 1")
        return self.get(rows[0][0]) if rows else None

    def stage_one(self, writer) -> dict | None:
        """Блокировать только переход состояния; SMB работает вне mutex."""
        with self.mu:
            item = self.next_to_stage()
            if item is None:
                return None
            if not writer.enabled:
                raise OSError("учётная запись записи в Restored не настроена")
            p = self.path(item["id"])
            if p.stat().st_size != item["size"]:
                raise OSError("временный файл загрузки изменился")
            rel = f"{UPLOAD_PREFIX}/{item['id']}/{item['name']}"
            self.db.run("UPDATE uploads SET state='staging' WHERE id=? AND state='queued'",
                        (item["id"],))
        try:
            staged = writer.write(rel, p, item["mtime"], item["sha"])
        except BaseException:
            with self.mu:
                self.db.run("UPDATE uploads SET state='queued' WHERE id=? AND state='staging'",
                            (item["id"],))
            raise
        with self.mu:
            self.db.run("""UPDATE uploads SET staged=?,state='ready'
                           WHERE id=? AND state='staging'""", (staged,item["id"]))
            return self.get(item["id"])

    def completed(self, ident: str, destination: str) -> bool:
        with self.mu:
            item=self.get(ident)
            if not item:
                return False
            if item["state"] == "done":
                return item["destination"] == destination
            if item["state"] != "ready":
                return False
            destination_folder(destination.rpartition("/")[0])
            media_name(destination.rpartition("/")[2])
            self.db.run("""UPDATE uploads SET state='done',destination=?,completed=?
                           WHERE id=? AND state='ready'""",
                        (destination,time.time(),ident))
            self.path(ident).unlink(missing_ok=True)
            return True
