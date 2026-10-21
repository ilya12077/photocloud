"""Пароли (argon2id), серверные сессии, ограничение перебора."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()
# хэш-пустышка: для несуществующего пользователя тоже тратим время на verify,
# чтобы по времени ответа нельзя было понять, есть ли такой логин
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
ROLES = ("admin", "user")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
MIN_PASSWORD = 12


class UserError(ValueError):
    pass


class UserStore:
    """Пользователи в DATA_DIR/users.json: {"users": {name: {"hash", "role", "created"}}}.
    Пароли — только argon2id-хэши. Запись атомарная (tmp + replace)."""

    def __init__(self, path: Path):
        self.path = path
        self._u: dict[str, dict] = {}
        self._mu = threading.Lock()
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            for name, rec in (raw.get("users") or {}).items():
                if USER_RE.match(name) and isinstance(rec, dict) and str(rec.get("hash", "")).startswith("$argon2") \
                        and rec.get("role") in ROLES:
                    g = rec.get("google")
                    self._u[name] = {"hash": rec["hash"], "role": rec["role"], "created": float(rec.get("created", 0)),
                                     "google": g.lower() if isinstance(g, str) and EMAIL_RE.match(g) else None}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"users": self._u}, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def empty(self) -> bool:
        return not self._u

    def role(self, name: str) -> str | None:
        rec = self._u.get(name)
        return rec["role"] if rec else None

    def list(self) -> list[dict]:
        return [{"user": n, "role": r["role"], "created": int(r["created"]), "google": r.get("google")}
                for n, r in sorted(self._u.items())]

    def by_google(self, email: str) -> tuple[str, str] | None:
        email = email.lower()
        for n, r in self._u.items():
            if r.get("google") == email:
                return n, r["role"]
        return None

    def set_google(self, name: str, email: str | None) -> None:
        if email:
            email = email.strip().lower()
            if not EMAIL_RE.match(email):
                raise UserError("неверный email")
        with self._mu:
            if name not in self._u:
                raise UserError("нет такого пользователя")
            if email and any(r.get("google") == email for n, r in self._u.items() if n != name):
                raise UserError("этот Google-аккаунт уже привязан к другому пользователю")
            self._u[name]["google"] = email or None
            self._save()

    def verify(self, username: str, password: str) -> str | None:
        """Роль при верном пароле, иначе None. Время ответа не зависит от наличия логина."""
        rec = self._u.get(username)
        h = rec["hash"] if rec else _DUMMY_HASH
        try:
            _ph.verify(h, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return None
        if rec is None:
            return None
        if _ph.check_needs_rehash(h):
            with self._mu:
                rec["hash"] = _ph.hash(password)
                self._save()
        return rec["role"]

    @staticmethod
    def _check(name: str, password: str | None, role: str | None) -> None:
        if not USER_RE.match(name or ""):
            raise UserError("логин: 1–32 символа, латиница, цифры, _ . -")
        if password is not None and not (MIN_PASSWORD <= len(password) <= 256):
            raise UserError(f"пароль: от {MIN_PASSWORD} до 256 символов")
        if role is not None and role not in ROLES:
            raise UserError("роль: admin или user")

    def add(self, name: str, password: str, role: str) -> None:
        self._check(name, password, role)
        h = _ph.hash(password)
        with self._mu:
            if name in self._u:
                raise UserError("такой пользователь уже есть")
            self._u[name] = {"hash": h, "role": role, "created": time.time(), "google": None}
            self._save()

    def set_password(self, name: str, password: str) -> None:
        self._check(name, password, None)
        h = _ph.hash(password)
        with self._mu:
            if name not in self._u:
                raise UserError("нет такого пользователя")
            self._u[name]["hash"] = h
            self._save()

    def _admins(self) -> int:
        return sum(1 for r in self._u.values() if r["role"] == "admin")

    def set_role(self, name: str, role: str) -> None:
        self._check(name, None, role)
        with self._mu:
            if name not in self._u:
                raise UserError("нет такого пользователя")
            if self._u[name]["role"] == "admin" and role != "admin" and self._admins() == 1:
                raise UserError("нельзя убрать последнего администратора")
            self._u[name]["role"] = role
            self._save()

    def delete(self, name: str) -> None:
        with self._mu:
            if name not in self._u:
                raise UserError("нет такого пользователя")
            if self._u[name]["role"] == "admin" and self._admins() == 1:
                raise UserError("нельзя удалить последнего администратора")
            del self._u[name]
            self._save()


@dataclass
class Session:
    user: str
    ip: str
    created: float
    last_seen: float


class SessionStore:
    """Токен живёт только в cookie; на сервере (и в базе) храним его SHA-256,
    так что даже копия базы не даёт готовых токенов. Сессии переживают перезапуск.
    В памяти — рабочая копия; время последней активности пишется в базу не чаще раза в минуту."""

    MAX_PER_USER = 20
    TOUCH_EVERY = 60

    def __init__(self, idle_s: int, max_s: int, db=None):
        self.idle_s = idle_s
        self.max_s = max_s
        self.db = db
        self._s: dict[str, Session] = {}
        self._saved: dict[str, float] = {}       # last_seen, записанный в базу
        self._lock = threading.Lock()
        if db is not None:
            now = time.time()
            for key, user, ip, created, last in db.run("SELECT key, user, ip, created, last_seen FROM sessions"):
                if now - last <= idle_s and now - created <= max_s:
                    self._s[key] = Session(user, ip, created, last)
                    self._saved[key] = last
            db.run("DELETE FROM sessions WHERE ? - last_seen > ? OR ? - created > ?", (now, idle_s, now, max_s))

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _db_del(self, keys: list[str]) -> None:
        for k in keys:
            self._saved.pop(k, None)
        if self.db is not None and keys:
            self.db.many("DELETE FROM sessions WHERE key = ?", [(k,) for k in keys])

    def create(self, user: str, ip: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        k = self._key(token)
        with self._lock:
            self._purge(now)
            mine = sorted((s.created, key) for key, s in self._s.items() if s.user == user)
            old = [key for _, key in mine[: max(0, len(mine) - self.MAX_PER_USER + 1)]]
            for key in old:
                del self._s[key]
            self._s[k] = Session(user, ip, now, now)
            self._db_del(old)
            if self.db is not None:
                self.db.run("INSERT OR REPLACE INTO sessions(key, user, ip, created, last_seen) VALUES(?,?,?,?,?)",
                            (k, user, ip, now, now))
                self._saved[k] = now
        return token

    def get(self, token: str | None) -> Session | None:
        if not token or len(token) > 128:
            return None
        k = self._key(token)
        now = time.time()
        with self._lock:
            s = self._s.get(k)
            if s is None:
                return None
            if now - s.last_seen > self.idle_s or now - s.created > self.max_s:
                del self._s[k]
                self._db_del([k])
                return None
            s.last_seen = now
            if self.db is not None and now - self._saved.get(k, 0) > self.TOUCH_EVERY:
                self.db.run("UPDATE sessions SET last_seen = ? WHERE key = ?", (now, k))
                self._saved[k] = now
            return s

    def delete(self, token: str | None) -> None:
        if token:
            k = self._key(token)
            with self._lock:
                self._s.pop(k, None)
                self._db_del([k])

    def sid(self, token: str | None) -> str:
        """Короткий публичный id сессии (для админки) — не позволяет восстановить токен."""
        return self._key(token)[:16] if token else ""

    def list(self) -> list[dict]:
        now = time.time()
        with self._lock:
            self._purge(now)
            return [{"id": k[:16], "user": s.user, "ip": s.ip, "created": int(s.created),
                     "last_seen": int(s.last_seen)} for k, s in sorted(self._s.items(), key=lambda kv: -kv[1].last_seen)]

    def revoke(self, sid: str) -> bool:
        with self._lock:
            for k in [k for k in self._s if k[:16] == sid]:
                del self._s[k]
                self._db_del([k])
                return True
        return False

    def revoke_user(self, user: str) -> int:
        with self._lock:
            ks = [k for k, s in self._s.items() if s.user == user]
            for k in ks:
                del self._s[k]
            self._db_del(ks)
            return len(ks)

    def _purge(self, now: float) -> None:
        dead = [k for k, s in self._s.items()
                if now - s.last_seen > self.idle_s or now - s.created > self.max_s]
        for k in dead:
            del self._s[k]
        self._db_del(dead)


class LoginLimiter:
    """5 неудач с IP за 15 минут -> блок IP на 15 минут.
    Плюс глобальный потолок, чтобы распределённый перебор тоже упирался."""

    def __init__(self, per_ip=5, window=900, lock=900, global_max=50):
        self.per_ip, self.window, self.lock_s, self.global_max = per_ip, window, lock, global_max
        self._fails: dict[str, deque] = {}
        self._locked: dict[str, float] = {}
        self._global: deque = deque()
        self._mu = threading.Lock()

    def _trim(self, dq: deque, now: float) -> None:
        while dq and now - dq[0] > self.window:
            dq.popleft()

    def blocked(self, ip: str) -> int:
        """Сколько секунд ещё ждать (0 = можно)."""
        now = time.time()
        with self._mu:
            until = self._locked.get(ip, 0)
            if until > now:
                return int(until - now) + 1
            self._locked.pop(ip, None)
            self._trim(self._global, now)
            if len(self._global) >= self.global_max:
                return int(self.window - (now - self._global[0])) + 1
            return 0

    def fail(self, ip: str) -> bool:
        """Регистрирует неудачу. True, если IP только что заблокирован."""
        now = time.time()
        with self._mu:
            self._global.append(now)
            dq = self._fails.setdefault(ip, deque())
            self._trim(dq, now)
            dq.append(now)
            if len(self._fails) > 10000:  # защита памяти
                self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] < self.window}
            if len(dq) >= self.per_ip:
                self._locked[ip] = now + self.lock_s
                dq.clear()
                return True
            return False

    def locked(self) -> list[dict]:
        now = time.time()
        with self._mu:
            return [{"ip": ip, "left": int(t - now) + 1} for ip, t in self._locked.items() if t > now]

    def unlock(self, ip: str) -> None:
        with self._mu:
            self._locked.pop(ip, None)
            self._fails.pop(ip, None)

    def success(self, ip: str) -> None:
        with self._mu:
            self._fails.pop(ip, None)
