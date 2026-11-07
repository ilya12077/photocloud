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
    """CREATE TABLE IF NOT EXISTS hashes (
         key TEXT PRIMARY KEY,          -- путь \\0 размер \\0 mtime (как у дат)
         sha TEXT NOT NULL,             -- SHA-256 содержимого, hex
         checked REAL NOT NULL DEFAULT 0)   -- когда хеш последний раз сверяли с файлом
       WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS damaged (
         path TEXT PRIMARY KEY,         -- файл на ПК, испорченный без смены размера и даты (или не читается)
         key TEXT NOT NULL,             -- путь \\0 размер \\0 mtime на момент обнаружения
         size INTEGER NOT NULL, mtime INTEGER NOT NULL,
         sha_good TEXT NOT NULL,        -- правильный хеш (каким файл был)
         sha_bad TEXT NOT NULL,         -- каким стал ('' — не читается)
         found REAL NOT NULL, updated REAL NOT NULL,
         state TEXT NOT NULL,           -- found | nosource | restored | lost | fixed | accepted | changed | gone
         restored TEXT NOT NULL DEFAULT '',   -- путь копии внутри Restored
         note TEXT NOT NULL DEFAULT '')
       WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS kv (
         key TEXT PRIMARY KEY, value TEXT NOT NULL)   -- служебные отметки (даты проверок и т.п.)
       WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS backup_tokens (
         key TEXT PRIMARY KEY,          -- SHA-256 токена (сам токен не хранится)
         id TEXT NOT NULL UNIQUE,       -- короткий id для админки
         name TEXT NOT NULL, user TEXT NOT NULL,
         created REAL NOT NULL, last_seen REAL NOT NULL DEFAULT 0, last_ip TEXT NOT NULL DEFAULT '',
         report TEXT NOT NULL DEFAULT '{}', stale_sent INTEGER NOT NULL DEFAULT 0)""",
    # скрытые из галереи: у каждого пользователя свои (файлы на ПК остаются)
    """CREATE TABLE IF NOT EXISTS user_hidden (
        user TEXT NOT NULL, path TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY (user, path))
       WITHOUT ROWID""",
    # помеченные «удалить окончательно» (со страницы скрытых). Сами файлы пока не трогаются:
    # удалять с ПК будет отдельный клиент, он же решает. key (путь+размер+mtime) и sha —
    # каким файл был при пометке: изменившийся после пометки файл удалять нельзя
    """CREATE TABLE IF NOT EXISTS delete_marks (
        path TEXT PRIMARY KEY, key TEXT NOT NULL, sha TEXT, by TEXT NOT NULL, at REAL NOT NULL)""",
    # группы (стопки): в ленте — одна обложка, по нажатию раскрывается. У каждого свои.
    """CREATE TABLE IF NOT EXISTS user_groups (
        user TEXT NOT NULL, path TEXT NOT NULL, gid TEXT NOT NULL, cover INTEGER NOT NULL DEFAULT 0, at REAL NOT NULL,
        PRIMARY KEY (user, path)) WITHOUT ROWID""",
    # самые маленькие эскизы видео (ffmpeg долгий): ключ файла (путь+размер+mtime), формат, байты
    """CREATE TABLE IF NOT EXISTS vthumbs (
        key TEXT PRIMARY KEY, fmt TEXT NOT NULL, data BLOB NOT NULL) WITHOUT ROWID""",
    # избранное: у каждого пользователя своё
    """CREATE TABLE IF NOT EXISTS starred (
        user TEXT NOT NULL, path TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY (user, path))
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
        self._migrate()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _migrate(self) -> None:
        ver = self.con.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            # до 1.5.5 у JPEG с большими служебными блоками в начале (HONOR/Huawei)
            # подробности не читались — забываем пустые записи, их соберут заново
            n = self.con.execute("DELETE FROM info WHERE data NOT LIKE '%\"width\"%'").rowcount
            if n:
                log.info("подробности: %d пустых записей будут собраны заново", n)
            self.con.execute("PRAGMA user_version = 1")
        if ver < 2:
            cols = {r[1] for r in self.con.execute("PRAGMA table_info(hashes)")}
            if "checked" not in cols:               # таблица из 1.6.0-beta: дата проверки хеша
                self.con.execute("ALTER TABLE hashes ADD COLUMN checked REAL NOT NULL DEFAULT 0")
                self.con.execute("UPDATE hashes SET checked = ?", (__import__("time").time(),))
            self.con.execute("PRAGMA user_version = 2")
        if ver < 3:
            # 1.8.0-beta.1…6: скрытые были общими (таблица hidden) — теперь у каждого свои:
            # скрытое переходит к тому, кто скрыл
            if self.con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hidden'").fetchone():
                self.con.execute("INSERT OR IGNORE INTO user_hidden (user, path, at) SELECT by, path, at FROM hidden")
                self.con.execute("DROP TABLE hidden")
            self.con.execute("PRAGMA user_version = 3")

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

    # ------------------------------------------------------------ хеши файлов (для бэкапа)

    def hashes_load(self) -> dict[str, str]:
        return dict(self.run("SELECT key, sha FROM hashes"))

    def hash_get(self, key: str) -> str | None:
        r = self.run("SELECT sha FROM hashes WHERE key = ?", (key,))
        return r[0][0] if r else None

    def hashes_count(self) -> int:
        return self.run("SELECT count(*) FROM hashes")[0][0]

    def hashes_put_many(self, items: list[tuple[str, str]]) -> None:
        """Только что посчитанные хеши — они же и проверенные."""
        if items:
            import time
            now = time.time()
            self.many("INSERT OR REPLACE INTO hashes(key, sha, checked) VALUES(?, ?, ?)",
                      [(k, h, now) for k, h in items])

    def hashes_checked_count(self, since: float) -> tuple[int, int]:
        """(сверено с момента since, всего хешей) — ход прерванной проверки."""
        n, total = self.run("SELECT coalesce(sum(checked >= ?), 0), count(*) FROM hashes", (since,))[0]
        return int(n), int(total)

    def hashes_unchecked(self, since: float) -> dict[str, str]:
        """Хеши, которые не сверяли с файлом с момента since (начало текущей проверки)."""
        return dict(self.run("SELECT key, sha FROM hashes WHERE checked < ?", (since,)))

    def hashes_checked_many(self, rows: list[tuple[str, float, str]]) -> None:
        """rows: (sha, checked, key) — после сверки (sha мог поменяться)."""
        if rows:
            self.many("UPDATE hashes SET sha = ?, checked = ? WHERE key = ?", rows)

    # ------------------------------------------------------------ повреждённые файлы на ПК

    _DMG = "path, key, size, mtime, sha_good, sha_bad, found, updated, state, restored, note"
    ACTIVE = ("found", "nosource", "restored", "lost")

    def damaged_list(self, active_only: bool = False) -> list[dict]:
        cols = [c.strip() for c in self._DMG.split(",")]
        q = f"SELECT {self._DMG} FROM damaged"
        if active_only:
            q += " WHERE state IN ('found', 'nosource', 'restored', 'lost')"
        return [dict(zip(cols, r)) for r in self.run(q + " ORDER BY found DESC")]

    def damaged_get(self, path: str) -> dict | None:
        cols = [c.strip() for c in self._DMG.split(",")]
        r = self.run(f"SELECT {self._DMG} FROM damaged WHERE path = ?", (path,))
        return dict(zip(cols, r[0])) if r else None

    def damaged_put(self, d: dict) -> None:
        cols = [c.strip() for c in self._DMG.split(",")]
        self.run(f"INSERT OR REPLACE INTO damaged({self._DMG}) VALUES({', '.join('?' * len(cols))})",
                 tuple(d[c] for c in cols))

    def damaged_delete(self, path: str) -> None:
        self.run("DELETE FROM damaged WHERE path = ?", (path,))

    def damaged_prune(self, before: float) -> int:
        """Закрытые записи (исправлен, принят, удалён, изменён), закрытые раньше before."""
        q = ("FROM damaged WHERE state NOT IN ('found', 'nosource', 'restored', 'lost') AND updated < ?")
        n = self.run("SELECT count(*) " + q, (before,))[0][0]
        if n:
            self.run("DELETE " + q, (before,))
        return n

    # ------------------------------------------------------------ скрытые файлы

    def hidden_load(self) -> dict[str, dict[str, float]]:
        """пользователь -> {путь: когда скрыл}"""
        out: dict[str, dict[str, float]] = {}
        for u, p, at in self.run("SELECT user, path, at FROM user_hidden"):
            out.setdefault(u, {})[p] = at
        return out

    def hidden_put(self, user: str, paths: list[str]) -> None:
        now = __import__("time").time()
        self.many("INSERT OR IGNORE INTO user_hidden (user, path, at) VALUES (?, ?, ?)", [(user, p, now) for p in paths])

    def hidden_delete(self, user: str, paths: list[str]) -> None:
        self.many("DELETE FROM user_hidden WHERE user = ? AND path = ?", [(user, p) for p in paths])

    def hidden_count(self) -> int:
        return self.run("SELECT count(*) FROM user_hidden")[0][0]

    # ------------------------------------------------------------ пометки на удаление

    def marks_load(self) -> dict[str, tuple[str, float]]:
        return {p: (by, at) for p, by, at in self.run("SELECT path, by, at FROM delete_marks")}

    def marks_put(self, rows: list[tuple[str, str, str | None]], by: str) -> None:
        """rows: (путь, ключ, sha). Повторная пометка обновляет ключ, sha, кто и когда."""
        now = __import__("time").time()
        self.many("INSERT OR REPLACE INTO delete_marks (path, key, sha, by, at) VALUES (?, ?, ?, ?, ?)",
                  [(p, k, h, by, now) for p, k, h in rows])

    def marks_delete(self, paths: list[str]) -> None:
        self.many("DELETE FROM delete_marks WHERE path = ?", [(p,) for p in paths])

    # ------------------------------------------------------------ группы

    def groups_load(self) -> dict[str, dict[str, tuple[str, bool]]]:
        """пользователь -> {путь: (группа, обложка?)}"""
        out: dict[str, dict[str, tuple[str, bool]]] = {}
        for u, p, g, c in self.run("SELECT user, path, gid, cover FROM user_groups"):
            out.setdefault(u, {})[p] = (g, bool(c))
        return out

    def groups_set(self, user: str, gid: str, paths: list[str], cover: str) -> None:
        """Новая группа: файлы уходят из прежних групп; группы, где остался один файл, — распускаем."""
        now = __import__("time").time()
        with self.mu:
            self.con.execute("BEGIN")
            try:
                self.con.executemany("DELETE FROM user_groups WHERE user = ? AND path = ?", [(user, p) for p in paths])
                self.con.executemany("INSERT INTO user_groups (user, path, gid, cover, at) VALUES (?, ?, ?, ?, ?)",
                                     [(user, p, gid, int(p == cover), now) for p in paths])
                self.con.execute("DELETE FROM user_groups WHERE user = ? AND gid IN (SELECT gid FROM user_groups "
                                 "WHERE user = ? GROUP BY gid HAVING count(*) < 2)", (user, user))
                self.con.execute("COMMIT")
            except Exception:
                self.con.execute("ROLLBACK")
                raise

    def groups_drop(self, user: str, gids: list[str]) -> None:
        self.many("DELETE FROM user_groups WHERE user = ? AND gid = ?", [(user, g) for g in gids])

    def user_forget(self, user: str) -> None:
        """Пользователя удалили: его скрытые, группы и избранное больше не нужны."""
        for t in ("user_hidden", "user_groups", "starred"):
            self.run(f"DELETE FROM {t} WHERE user = ?", (user,))

    # ------------------------------------------------------------ эскизы видео

    def vthumb_get(self, key: str, fmt: str) -> bytes | None:
        r = self.run("SELECT data FROM vthumbs WHERE key = ? AND fmt = ?", (key, fmt))
        return r[0][0] if r else None

    def vthumb_put(self, key: str, fmt: str, data: bytes) -> None:
        self.run("INSERT OR REPLACE INTO vthumbs (key, fmt, data) VALUES (?, ?, ?)", (key, fmt, data))

    def vthumb_keys(self, fmt: str) -> set[str]:
        return {k for (k,) in self.run("SELECT key FROM vthumbs WHERE fmt = ?", (fmt,))}

    def vthumb_stats(self) -> tuple[int, int]:
        n, b = self.run("SELECT count(*), coalesce(sum(length(data)), 0) FROM vthumbs WHERE fmt != 'audio'")[0]
        return int(n), int(b)

    def vthumbs_prune(self, keep: set[str]) -> int:
        """Эскизы файлов, которых больше нет (переименованы, удалены, изменены)."""
        gone = [(k,) for (k,) in self.run("SELECT key FROM vthumbs") if k not in keep]
        if gone:
            self.many("DELETE FROM vthumbs WHERE key = ?", gone)
        return len(gone)

    # ------------------------------------------------------------ избранное

    def starred_load(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for u, p in self.run("SELECT user, path FROM starred"):
            out.setdefault(u, set()).add(p)
        return out

    def starred_put(self, user: str, paths: list[str]) -> None:
        now = __import__("time").time()
        self.many("INSERT OR IGNORE INTO starred (user, path, at) VALUES (?, ?, ?)", [(user, p, now) for p in paths])

    def starred_delete(self, user: str, paths: list[str]) -> None:
        self.many("DELETE FROM starred WHERE user = ? AND path = ?", [(user, p) for p in paths])

    # ------------------------------------------------------------ служебные отметки

    def kv_get(self, key: str) -> str | None:
        r = self.run("SELECT value FROM kv WHERE key = ?", (key,))
        return r[0][0] if r else None

    def kv_set(self, key: str, value) -> None:
        if value is None:
            self.run("DELETE FROM kv WHERE key = ?", (key,))
        else:
            self.run("INSERT OR REPLACE INTO kv(key, value) VALUES(?, ?)", (key, str(value)))

    def hashes_prune(self, keep: set[str]) -> int:
        gone = [(k,) for (k,) in self.run("SELECT key FROM hashes") if k not in keep]
        if gone:
            self.many("DELETE FROM hashes WHERE key = ?", gone)
        return len(gone)

    # ------------------------------------------------------------ токены клиентов бэкапа

    _TOKEN_COLS = "key, id, name, user, created, last_seen, last_ip, report, stale_sent"

    def tokens_load(self) -> list[tuple]:
        return self.run(f"SELECT {self._TOKEN_COLS} FROM backup_tokens ORDER BY created")

    def token_add(self, key: str, tid: str, name: str, user: str, created: float) -> None:
        self.run("INSERT INTO backup_tokens(key, id, name, user, created) VALUES(?, ?, ?, ?, ?)",
                 (key, tid, name, user, created))

    def token_delete(self, tid: str) -> None:
        self.run("DELETE FROM backup_tokens WHERE id = ?", (tid,))

    def token_delete_user(self, user: str) -> None:
        self.run("DELETE FROM backup_tokens WHERE user = ?", (user,))

    def token_save(self, rows: list[tuple]) -> None:
        """rows: (last_seen, last_ip, report, stale_sent, id)"""
        if rows:
            self.many("UPDATE backup_tokens SET last_seen = ?, last_ip = ?, report = ?, stale_sent = ? WHERE id = ?",
                      rows)
