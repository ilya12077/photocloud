"""SQLite-хранилище в DATA_DIR/photocloud.db: сессии и кэш дат съёмки.
(Позже сюда же лягут хэши файлов для резервного копирования.)

Один файл, без сервера; WAL — чтение не блокирует запись. Все обращения через
один connection под замком: нагрузка маленькая, а так нет гонок между потоками."""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from pathlib import Path

log = logging.getLogger("photocloud.db")

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS sessions (
         key TEXT PRIMARY KEY,          -- SHA-256 токена (сам токен не хранится)
         user TEXT NOT NULL, ip TEXT NOT NULL,
         created REAL NOT NULL, last_seen REAL NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user)",
    """CREATE TABLE IF NOT EXISTS dates (
         key TEXT PRIMARY KEY,          -- путь \\0 размер \\0 mtime
         ts REAL NOT NULL)              -- дата съёмки, 0 = в файле её нет
       WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS info (
         key TEXT PRIMARY KEY,          -- путь \\0 размер \\0 mtime (как у дат)
         data TEXT NOT NULL)            -- JSON: размеры, камера, координаты
       WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS geo (
         key TEXT PRIMARY KEY,          -- «широта,долгота» с точностью ~10 м
         addr TEXT NOT NULL,            -- адрес по-русски; '' — не нашёлся
         ts REAL NOT NULL)
       WITHOUT ROWID""",
]


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.mu = threading.Lock()
        self.con = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        for q in SCHEMA:
            self.con.execute(q)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def run(self, sql: str, args=()):
        with self.mu:
            return self.con.execute(sql, args).fetchall()

    def many(self, sql: str, rows) -> None:
        with self.mu:
            self.con.execute("BEGIN")
            try:
                self.con.executemany(sql, rows)
                self.con.execute("COMMIT")
            except BaseException:
                self.con.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------ кэш дат

    def dates_load(self) -> dict[str, float]:
        return dict(self.run("SELECT key, ts FROM dates"))

    def dates_put(self, items: list[tuple[str, float]]) -> None:
        if items:
            self.many("INSERT OR REPLACE INTO dates(key, ts) VALUES(?, ?)", items)

    def dates_prune(self, keep: set[str]) -> int:
        """Удалить записи о файлах, которых больше нет (переименованы, удалены, изменены)."""
        have = [k for (k,) in self.run("SELECT key FROM dates")]
        gone = [(k,) for k in have if k not in keep]
        if gone:
            self.many("DELETE FROM dates WHERE key = ?", gone)
        return len(gone)

    # ------------------------------------------------------------ кэш адресов (обратное геокодирование)

    def geo_get(self, key: str) -> str | None:
        r = self.run("SELECT addr FROM geo WHERE key = ?", (key,))
        return r[0][0] if r else None

    def geo_put(self, key: str, addr: str) -> None:
        import time
        self.run("INSERT OR REPLACE INTO geo(key, addr, ts) VALUES(?, ?, ?)", (key, addr, time.time()))

    # ------------------------------------------------------------ подробности снимка (EXIF)

    def info_get(self, key: str) -> str | None:
        r = self.run("SELECT data FROM info WHERE key = ?", (key,))
        return r[0][0] if r else None

    def info_put(self, key: str, data: str) -> None:
        self.run("INSERT OR REPLACE INTO info(key, data) VALUES(?, ?)", (key, data))

    def info_keys(self) -> set[str]:
        return {k for (k,) in self.run("SELECT key FROM info")}

    def info_put_many(self, items: list[tuple[str, str]]) -> None:
        if items:
            self.many("INSERT OR REPLACE INTO info(key, data) VALUES(?, ?)", items)

    def info_prune(self, keep: set[str]) -> int:
        gone = [(k,) for k in self.info_keys() if k not in keep]
        if gone:
            self.many("DELETE FROM info WHERE key = ?", gone)
        return len(gone)
