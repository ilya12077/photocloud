"""Пароли (argon2id), серверные сессии, ограничение перебора."""
from __future__ import annotations

import hashlib
import ipaddress
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

from . import totp
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()
# хэш-пустышка: для несуществующего пользователя тоже тратим время на verify,
# чтобы по времени ответа нельзя было понять, есть ли такой логин
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
ROLES = ("admin", "user")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
MIN_PASSWORD = 8


class UserError(ValueError):
    pass


def norm_folder(f: str) -> str:
    """Папка из настроек доступа -> «a/b». Только простые части пути: без «..», «.»,
    обратных слэшей и пустых частей — чтобы правило нельзя было обойти."""
    if not isinstance(f, str):
        raise UserError("папка: строка")
    parts = [x for x in f.strip().replace("\\", "/").split("/") if x != ""]
    if not parts or len(f) > 500 or any(x in (".", "..") or "\x00" in x or "\\" in x for x in parts):
        raise UserError(f"неверная папка: {f!r}")
    return "/".join(parts)


def norm_folders(fs) -> list[str] | None:
    """None — все папки; иначе отсортированный список без повторов."""
    if fs is None:
        return None
    if not isinstance(fs, list) or len(fs) > 200:
        raise UserError("папки: список")
    return sorted({norm_folder(f) for f in fs})


class UserStore:
    """Пользователи в DATA_DIR/users.json: {"users": {name: {"hash", "role", "created"}}}.
    Пароли — только argon2id-хэши. Запись атомарная (tmp + replace)."""

    def __init__(self, path: Path):
        self.path = path
        self._u: dict[str, dict] = {}
        self._mtime = 0
        self._mu = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        mtime = self.path.stat().st_mtime_ns
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        users: dict[str, dict] = {}
        for name, rec in (raw.get("users") or {}).items():
            if not (USER_RE.match(name) and isinstance(rec, dict) and str(rec.get("hash", "")).startswith("$argon2")
                    and rec.get("role") in ROLES):
                continue
            g = rec.get("google")
            try:
                folders = norm_folders(rec.get("folders"))
                exclude = norm_folders(rec.get("exclude")) or []
            except UserError:
                folders, exclude = [], []   # испорченная запись — безопаснее ничего, чем всё
            users[name] = {"hash": rec["hash"], "role": rec["role"], "created": float(rec.get("created", 0)),
                           "google": g.lower() if isinstance(g, str) and EMAIL_RE.match(g) else None,
                           "folders": folders, "exclude": exclude,
                           "wake": rec.get("wake", True) is not False}
            sec = rec.get("totp")
            if isinstance(sec, str) and totp.SECRET_RE.match(sec):
                users[name].update(totp=sec, totp_step=int(rec.get("totp_step") or 0))
            if rec.get("totp_required") or users[name].get("totp"):
                users[name]["totp_required"] = True
        self._u, self._mtime = users, mtime

    def _sync(self) -> None:
        """users.json поменяли снаружи (например, «python -m app 2fa-reset» из консоли
        контейнера) — перечитать, иначе следующая запись затёрла бы эту правку."""
        try:
            m = self.path.stat().st_mtime_ns
        except OSError:
            return
        if m != self._mtime:
            self._load()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"users": self._u}, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._mtime = self.path.stat().st_mtime_ns

    def empty(self) -> bool:
        return not self._u

    def role(self, name: str) -> str | None:
        rec = self._u.get(name)
        return rec["role"] if rec else None

    def list(self) -> list[dict]:
        with self._mu:
            self._sync()
        return [{"user": n, "role": r["role"], "created": int(r["created"]), "google": r.get("google"),
                 "folders": r.get("folders"), "exclude": r.get("exclude") or [], "wake": r.get("wake", True),
                 "totp": "on" if r.get("totp") else "pending" if r.get("totp_required") else "off"}
                for n, r in sorted(self._u.items())]

    # ---- двухфакторный вход (TOTP). Включает админ; пользователь настраивает приложение при
    # следующем входе. Потерян телефон — сброс (в админке или «python -m app 2fa-reset <логин>»):
    # при следующем входе настройка заново.
    def totp_on(self, name: str) -> bool:
        """Приложение уже настроено — при входе нужен код."""
        with self._mu:
            self._sync()
            rec = self._u.get(name)
            return bool(rec and rec.get("totp"))

    def totp_required(self, name: str) -> bool:
        with self._mu:
            self._sync()
            rec = self._u.get(name)
            return bool(rec and rec.get("totp_required"))

    def totp_check(self, name: str, code) -> bool:
        """Код из приложения подошёл. Один и тот же код дважды не принимается."""
        c = totp.norm(code)
        with self._mu:
            self._sync()
            rec = self._u.get(name)
            if not rec or not rec.get("totp") or not c:
                return False
            st = totp.match(rec["totp"], c, rec.get("totp_step", 0))
            if st is None:
                return False
            rec["totp_step"] = st
            self._save()
            return True

    def totp_enable(self, name: str, secret: str, step: int) -> None:
        """Пользователь настроил приложение (код подошёл)."""
        with self._mu:
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            self._u[name].update(totp=secret, totp_step=step, totp_required=True)
            self._save()

    def totp_set(self, name: str, mode: str) -> None:
        """on — требовать (настроит при следующем входе); off — выключить совсем;
        reset — забыть приложение (новый телефон), при следующем входе настройка заново."""
        with self._mu:
            self._sync()
            rec = self._u.get(name)
            if rec is None:
                raise UserError("нет такого пользователя")
            if mode == "on":
                rec["totp_required"] = True
            elif mode in ("off", "reset"):
                for k in ("totp", "totp_step", "totp_codes"):
                    rec.pop(k, None)
                if mode == "off":
                    rec.pop("totp_required", None)
            else:
                raise UserError("mode: on, off или reset")
            self._save()

    def folders(self, name: str):
        """Доступ пользователя к папкам: None — всё; иначе (разрешённые или None=все, исключённые).
        Нет такого пользователя — ничего."""
        rec = self._u.get(name)
        if rec is None:
            return ((), ())
        allow, deny = rec.get("folders"), tuple(rec.get("exclude") or ())
        if allow is None and not deny:
            return None
        return (None if allow is None else tuple(allow), deny)

    def can_wake(self, name: str) -> bool:
        rec = self._u.get(name)
        return bool(rec) and (rec["role"] == "admin" or rec.get("wake", True) is not False)

    def set_wake(self, name: str, allow: bool) -> None:
        with self._mu:
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            self._u[name]["wake"] = bool(allow)
            self._save()

    def set_folders(self, name: str, folders, exclude=None) -> None:
        """folders: None — все папки, список — только эти (с подпапками);
        exclude: подпапки, которые при этом скрыты (тоже с их подпапками)."""
        folders = norm_folders(folders)
        exclude = norm_folders(exclude or []) or []
        with self._mu:
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            self._u[name]["folders"] = folders
            self._u[name]["exclude"] = exclude
            self._save()

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
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            if email and any(r.get("google") == email for n, r in self._u.items() if n != name):
                raise UserError("этот Google-аккаунт уже привязан к другому пользователю")
            self._u[name]["google"] = email or None
            self._save()

    def verify(self, username: str, password: str) -> str | None:
        """Роль при верном пароле, иначе None. Время ответа не зависит от наличия логина."""
        with self._mu:
            self._sync()
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
                self._sync()
                cur = self._u.get(username)
                if cur is not None and cur["hash"] == h:
                    cur["hash"] = _ph.hash(password)
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
            self._sync()
            if name in self._u:
                raise UserError("такой пользователь уже есть")
            self._u[name] = {"hash": h, "role": role, "created": time.time(), "google": None, "folders": None, "exclude": [], "wake": True}
            self._save()

    def set_password(self, name: str, password: str) -> None:
        self._check(name, password, None)
        h = _ph.hash(password)
        with self._mu:
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            self._u[name]["hash"] = h
            self._save()

    def _admins(self) -> int:
        return sum(1 for r in self._u.values() if r["role"] == "admin")

    def set_role(self, name: str, role: str) -> None:
        self._check(name, None, role)
        with self._mu:
            self._sync()
            if name not in self._u:
                raise UserError("нет такого пользователя")
            if self._u[name]["role"] == "admin" and role != "admin" and self._admins() == 1:
                raise UserError("нельзя убрать последнего администратора")
            self._u[name]["role"] = role
            self._save()

    def delete(self, name: str) -> None:
        with self._mu:
            self._sync()
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
    remember: bool = True


class SessionStore:
    """Токен живёт только в cookie; на сервере (и в базе) храним его SHA-256,
    так что даже копия базы не даёт готовых токенов. Сессии переживают перезапуск.
    В памяти — рабочая копия; время последней активности пишется в базу не чаще раза в минуту.
    Без «Запомнить вход» сессия живёт до short_s бездействия (и cookie сеансовая), с ней — до idle_s.
    Бездействие — это отсутствие запросов от человека: фоновый опрос состояния сессию не продлевает."""

    MAX_PER_USER = 20
    TOUCH_EVERY = 60

    def __init__(self, idle_s: int, max_s: int, db=None, short_s: int = 900):
        self.idle_s = idle_s
        self.short_s = short_s
        self.max_s = max_s
        self.db = db
        self._s: dict[str, Session] = {}
        self._saved: dict[str, float] = {}       # last_seen, записанный в базу
        self._lock = threading.Lock()
        if db is not None:
            now = time.time()
            for key, user, ip, created, last, rem in db.run(
                    "SELECT key, user, ip, created, last_seen, remember FROM sessions"):
                s = Session(user, ip, created, last, bool(rem))
                if not self._dead(s, now):
                    self._s[key] = s
                    self._saved[key] = last
            db.many("DELETE FROM sessions WHERE key = ?",
                    [(k,) for (k,) in db.run("SELECT key FROM sessions") if k not in self._s])

    def _dead(self, s: Session, now: float) -> bool:
        return now - s.last_seen > (self.idle_s if s.remember else self.short_s) or now - s.created > self.max_s

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _db_del(self, keys: list[str]) -> None:
        for k in keys:
            self._saved.pop(k, None)
        if self.db is not None and keys:
            self.db.many("DELETE FROM sessions WHERE key = ?", [(k,) for k in keys])

    def create(self, user: str, ip: str, remember: bool = True) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        k = self._key(token)
        with self._lock:
            self._purge(now)
            mine = sorted((s.created, key) for key, s in self._s.items() if s.user == user)
            old = [key for _, key in mine[: max(0, len(mine) - self.MAX_PER_USER + 1)]]
            for key in old:
                del self._s[key]
            self._s[k] = Session(user, ip, now, now, remember)
            self._db_del(old)
            if self.db is not None:
                self.db.run("INSERT OR REPLACE INTO sessions(key, user, ip, created, last_seen, remember) "
                            "VALUES(?,?,?,?,?,?)", (k, user, ip, now, now, int(remember)))
                self._saved[k] = now
        return token

    def get(self, token: str | None, touch: bool = True) -> Session | None:
        """touch=False — фоновый запрос (опрос состояния): сессию не продлевает."""
        if not token or len(token) > 128:
            return None
        k = self._key(token)
        now = time.time()
        with self._lock:
            s = self._s.get(k)
            if s is None:
                return None
            if self._dead(s, now):
                del self._s[k]
                self._db_del([k])
                return None
            if not touch:
                return s
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
                     "last_seen": int(s.last_seen), "remember": s.remember} for k, s in sorted(self._s.items(), key=lambda kv: -kv[1].last_seen)]

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
        dead = [k for k, s in self._s.items() if self._dead(s, now)]
        for k in dead:
            del self._s[k]
        self._db_del(dead)


def ip_key(ip: str) -> str:
    """Ключ для счёта неудач: IPv4 — сам адрес, IPv6 — его сеть /64 (у одного абонента их миллиарды)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 6:
        if a.ipv4_mapped is not None:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


class LoginLimiter:
    """5 неудач с адреса (IPv6 — с сети /64) за 15 минут -> блок на 15 минут.
    Плюс глобальный потолок против распределённого перебора. Он не действует на адреса,
    с которых недавно был успешный вход или ходил клиент бэкапа, и на сам клиент бэкапа
    (там токен, а не пароль) — иначе любой с десятком адресов запер бы вход всем."""

    TRUST_S = 30 * 86400

    def __init__(self, per_ip=5, window=900, lock=900, global_max=50):
        self.per_ip, self.window, self.lock_s, self.global_max = per_ip, window, lock, global_max
        self._fails: dict[str, deque] = {}
        self._locked: dict[str, float] = {}
        self._good: dict[str, float] = {}       # адрес -> время последнего успешного входа
        self._global: deque = deque()
        self._mu = threading.Lock()

    def _trim(self, dq: deque, now: float) -> None:
        while dq and now - dq[0] > self.window:
            dq.popleft()

    def _prune(self, now: float) -> None:
        self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] < self.window}
        self._locked = {k: t for k, t in self._locked.items() if t > now}
        if len(self._good) > 5000:
            self._good = dict(sorted(self._good.items(), key=lambda kv: kv[1])[-2000:])

    def blocked(self, ip: str, *, global_cap: bool = True) -> int:
        """Сколько секунд ещё ждать (0 = можно). global_cap=False — только блок самого адреса."""
        now = time.time()
        k = ip_key(ip)
        with self._mu:
            until = self._locked.get(k, 0)
            if until > now:
                return int(until - now) + 1
            self._locked.pop(k, None)
            if not global_cap or now - self._good.get(k, 0) < self.TRUST_S:
                return 0
            self._trim(self._global, now)
            if len(self._global) >= self.global_max:
                return int(self.window - (now - self._global[0])) + 1
            return 0

    def fail(self, ip: str) -> bool:
        """Регистрирует неудачу. True, если адрес только что заблокирован."""
        now = time.time()
        k = ip_key(ip)
        with self._mu:
            self._global.append(now)
            self._trim(self._global, now)
            dq = self._fails.setdefault(k, deque())
            self._trim(dq, now)
            dq.append(now)
            if len(self._fails) > 10000 or len(self._locked) > 1000:  # защита памяти
                self._prune(now)
            if len(dq) >= self.per_ip:
                self._locked[k] = now + self.lock_s
                dq.clear()
                return True
            return False

    def locked(self) -> list[dict]:
        now = time.time()
        with self._mu:
            return [{"ip": ip, "left": int(t - now) + 1} for ip, t in self._locked.items() if t > now]

    def unlock(self, ip: str) -> None:
        k = ip_key(ip)
        with self._mu:
            self._locked.pop(k, None)
            self._fails.pop(k, None)

    def success(self, ip: str, at: float | None = None) -> None:
        """Успешный вход (или запрос клиента бэкапа с верным токеном): адрес «свой»."""
        k = ip_key(ip)
        with self._mu:
            self._fails.pop(k, None)
            self._good[k] = max(self._good.get(k, 0), at or time.time())
