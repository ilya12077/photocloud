"""Токены клиентов бэкапа.

Клиент (скрипт на другом компьютере) ходит со своим токеном в заголовке
`Authorization: Bearer …` и получает права пользователя, к которому токен привязан:
те же папки и то же разрешение будить ПК, только чтение. Токен показывается один раз
при создании; на сервере (и в базе) лежит только его SHA-256."""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time

PREFIX = "pcb_"
MAX_TOKENS = 20
FLUSH_EVERY = 60          # с: время «на связи» пишем в базу не чаще


def _key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


class Token:
    __slots__ = ("key", "id", "name", "user", "created", "last_seen", "last_ip", "report", "stale_sent", "dirty")

    def __init__(self, key, tid, name, user, created, last_seen=0.0, last_ip="", report="{}", stale_sent=0):
        self.key, self.id, self.name, self.user, self.created = key, tid, name, user, created
        self.last_seen, self.last_ip, self.stale_sent = last_seen, last_ip, int(stale_sent)
        try:
            self.report = json.loads(report) if isinstance(report, str) else dict(report)
        except ValueError:
            self.report = {}
        self.dirty = False

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "user": self.user, "created": int(self.created),
                "last_seen": int(self.last_seen), "last_ip": self.last_ip, "report": self.report}


class TokenStore:
    def __init__(self, db):
        self.db = db
        self.mu = threading.Lock()
        self.by_key: dict[str, Token] = {t[0]: Token(*t) for t in db.tokens_load()}
        self._flushed = time.monotonic()

    def any(self) -> bool:
        return bool(self.by_key)

    def list(self) -> list[dict]:
        return [t.public() for t in sorted(self.by_key.values(), key=lambda t: t.created)]

    def all(self) -> list[Token]:
        return list(self.by_key.values())

    def create(self, name: str, user: str) -> tuple[str, Token]:
        name = " ".join(name.split())[:40]
        if not name:
            raise ValueError("нужно название")
        with self.mu:
            if len(self.by_key) >= MAX_TOKENS:
                raise ValueError(f"не больше {MAX_TOKENS} токенов")
            token = PREFIX + secrets.token_urlsafe(32)
            t = Token(_key(token), secrets.token_hex(6), name, user, time.time())
            self.db.token_add(t.key, t.id, t.name, t.user, t.created)
            self.by_key[t.key] = t
        return token, t

    def get(self, token: str | None) -> Token | None:
        if not token or not token.startswith(PREFIX) or len(token) > 100:
            return None
        return self.by_key.get(_key(token))

    def revoke(self, tid: str) -> Token | None:
        with self.mu:
            t = next((x for x in self.by_key.values() if x.id == tid), None)
            if t:
                self.db.token_delete(tid)
                del self.by_key[t.key]
            return t

    def revoke_user(self, user: str) -> int:
        with self.mu:
            gone = [k for k, t in self.by_key.items() if t.user == user]
            for k in gone:
                del self.by_key[k]
            if gone:
                self.db.token_delete_user(user)
            return len(gone)

    def seen(self, t: Token, ip: str) -> None:
        t.last_seen, t.last_ip, t.stale_sent, t.dirty = time.time(), ip, 0, True
        if time.monotonic() - self._flushed > FLUSH_EVERY:
            self.flush()

    def set_report(self, t: Token, report: dict) -> None:
        """Во время копирования клиент шлёт отчёт раз в 10 с: в памяти — сразу (админка видит),
        в базу — при смене состояния или вместе с «на связи» раз в минуту."""
        changed = report.get("state") != t.report.get("state")
        t.report, t.dirty = report, True
        if changed or time.monotonic() - self._flushed > FLUSH_EVERY:
            self.flush()

    def flush(self) -> None:
        self._flushed = time.monotonic()
        with self.mu:
            rows = [(t.last_seen, t.last_ip, json.dumps(t.report, ensure_ascii=False), t.stale_sent, t.id)
                    for t in self.by_key.values() if t.dirty]
            for t in self.by_key.values():
                t.dirty = False
        self.db.token_save(rows)
