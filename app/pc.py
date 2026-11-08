"""Клиент на ПК с архивом (photocloud_pc.pyw): удаление помеченных фото в корзину Windows.

Доверие к клиенту — не токен, а ключ ECDSA P-256 в TPM этого ПК (не извлекается):
- привязка: админ открывает окно на 10 минут; клиент присылает открытый ключ, сервер даёт
  одноразовое число, клиент кладёт его, подписанное ключом, в служебную папку шары
  (.photocloud/pair-….json), сервер читает файл по SMB и проверяет подпись — так видно,
  что ключ у того, кто может писать в саму папку архива; открытый ключ запоминается;
- сессия (15 минут): клиент подписывает ключом TPM свой одноразовый ключ ECDH — общий секрет
  даёт ключ сессии, каждым запросом клиент подписывает HMAC (метод, путь, хеш тела, время,
  счётчик); каждый номер счётчика принимается один раз — повтор запроса не пройдёт;
- опасное (отчёт «удалено» — снимает пометки) — ещё и свежей подписью TPM над точным списком.
MachineGuid и IP — только для сигналов в журнале, не для проверки."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PAIR_WINDOW = 600
SESSION_TTL = 900
CLOCK_SKEW = 120
REPLAY_WINDOW = 1024
PAIR_DIR = ".photocloud"


class PcError(ValueError):
    pass


def b64d(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 4096:
        raise PcError("bad base64")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError):
        raise PcError("bad base64") from None


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pub_from_raw(raw: bytes) -> ec.EllipticCurvePublicKey:
    """Открытый ключ P-256 из X||Y (64 байта)."""
    if len(raw) != 64:
        raise PcError("bad public key")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"),
                                             ec.SECP256R1()).public_key()
    except ValueError:
        raise PcError("bad public key") from None


def raw_from_pub(pub: ec.EllipticCurvePublicKey) -> bytes:
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def verify(pub_raw: bytes, sig_raw: bytes, message: bytes) -> None:
    """Подпись r||s (как отдаёт NCrypt/TPM) над SHA-256 сообщения."""
    if len(sig_raw) != 64:
        raise PcError("bad signature")
    der = encode_dss_signature(int.from_bytes(sig_raw[:32], "big"), int.from_bytes(sig_raw[32:], "big"))
    try:
        pub_from_raw(pub_raw).verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise PcError("signature") from None


def fingerprint(pub_raw: bytes) -> str:
    h = hashlib.sha256(pub_raw).hexdigest()[:24]
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))


def pair_message(nonce: str, pub: str) -> bytes:
    return f"photocloud-pair\n{nonce}\n{pub}".encode()


def session_message(cid: str, eph: str, ts: int, guid: str) -> bytes:
    return f"photocloud-session\n{cid}\n{eph}\n{ts}\n{guid}".encode()


def delete_message(sid: str, ts: int, items: list) -> bytes:
    return ("photocloud-delete\n" + sid + "\n" + str(ts) + "\n"
            + json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))).encode()


def mac_message(method: str, path: str, body: bytes, ts: int, ctr: int) -> bytes:
    return f"{method}\n{path}\n{hashlib.sha256(body).hexdigest()}\n{ts}\n{ctr}".encode()


class PcAuth:
    """Привязанный клиент (один), окно привязки, ожидающие привязки, сессии."""

    def __init__(self, db):
        self.db = db
        self.mu = threading.Lock()
        self.pair_until = 0.0
        self._pending: dict[str, dict] = {}       # nonce -> {pub, name, key_type, exp}
        self._sessions: dict[str, dict] = {}      # sid -> {key, cid, exp, ctr}

    # ---- привязка
    def open_window(self) -> float:
        self.pair_until = time.time() + PAIR_WINDOW
        return self.pair_until

    def window_open(self) -> bool:
        return time.time() < self.pair_until

    def pair_start(self, pub: str, name: str, key_type: str) -> str:
        if not self.window_open():
            raise PcError("окно привязки закрыто — открой его в админке («Клиент ПК» → «Привязать»)")
        pub_from_raw(b64d(pub))
        now = time.time()
        with self.mu:
            self._pending = {k: v for k, v in self._pending.items() if v["exp"] > now}
            if len(self._pending) > 20:
                raise PcError("слишком много попыток привязки")
            nonce = secrets.token_hex(16)
            self._pending[nonce] = {"pub": pub, "name": str(name)[:60], "key_type": key_type if key_type in
                                    ("tpm", "software") else "?", "exp": now + PAIR_WINDOW}
        return nonce

    @staticmethod
    def pair_file(nonce: str) -> str:
        return f"{PAIR_DIR}/pair-{nonce}.json"

    def pair_finish(self, nonce: str, content: bytes, ip: str) -> dict:
        """content — файл, прочитанный сервером из шары."""
        with self.mu:
            p = self._pending.pop(nonce, None)
        if p is None or p["exp"] < time.time() or not self.window_open():
            raise PcError("привязка устарела — начни заново")
        try:
            data = json.loads(content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise PcError("файл привязки испорчен") from None
        if data.get("nonce") != nonce or data.get("pub") != p["pub"]:
            raise PcError("файл привязки не от этого клиента")
        verify(b64d(p["pub"]), b64d(data.get("sig", "")), pair_message(nonce, p["pub"]))
        cid = secrets.token_hex(8)
        self.db.pc_pair(cid, p["pub"], p["name"], p["key_type"], ip)
        self.pair_until = 0.0              # окно одноразовое
        with self.mu:
            self._sessions.clear()         # прежний клиент (если был) — сразу без сессий
        return {"id": cid, "fp": fingerprint(b64d(p["pub"]))}

    # ---- сессии
    def session(self, cid: str, eph: str, ts, guid: str, sig: str, ip: str) -> tuple[dict, dict]:
        """-> (ответ клиенту, сигналы {guid_changed, ip_changed})."""
        c = self.db.pc_get()
        if not c or c["id"] != cid:
            raise PcError("клиент не привязан")
        if not isinstance(ts, int) or abs(time.time() - ts) > CLOCK_SKEW:
            raise PcError("часы на ПК расходятся с сервером больше чем на 2 минуты")
        guid = str(guid or "")[:64]
        verify(b64d(c["pub"]), b64d(sig), session_message(cid, eph, ts, guid))
        client_eph = pub_from_raw(b64d(eph))
        mine = ec.generate_private_key(ec.SECP256R1())
        shared = mine.exchange(ec.ECDH(), client_eph)
        my_raw = raw_from_pub(mine.public_key())
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64d(eph) + my_raw,
                   info=b"photocloud-pc-session").derive(shared)
        sid = secrets.token_urlsafe(18)
        now = time.time()
        with self.mu:
            self._sessions = {k: v for k, v in self._sessions.items() if v["exp"] > now}
            self._sessions[sid] = {"key": key, "cid": cid, "exp": now + SESSION_TTL, "max": 0, "seen": set()}
        alarms = {"guid_changed": bool(c.get("guid")) and c["guid"] != guid,
                  "ip_changed": bool(c.get("last_ip")) and c["last_ip"] != ip}
        self.db.pc_seen(cid, ip, guid)
        return {"sid": sid, "eph": b64e(my_raw), "exp": int(now + SESSION_TTL)}, alarms

    def check(self, sid: str, ts: str, ctr: str, mac: str, method: str, path: str, body: bytes) -> dict:
        """Проверка подписи запроса. -> сессия."""
        with self.mu:
            s = self._sessions.get(sid or "")
            if s is None or s["exp"] < time.time():
                raise PcError("session")
            try:
                t, n = int(ts), int(ctr)
            except (TypeError, ValueError):
                raise PcError("bad headers") from None
            if abs(time.time() - t) > CLOCK_SKEW:
                raise PcError("clock")
            want = hmac.new(s["key"], mac_message(method, path, body, t, n), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, str(mac or "")):
                raise PcError("mac")
            # счётчик: каждый номер — один раз; запросы идут параллельно и могут прийти не по порядку,
            # поэтому принимаем ещё не виденные номера в окне 1024 от наибольшего
            if n <= 0 or n in s["seen"] or n <= s["max"] - REPLAY_WINDOW:
                raise PcError("replay")
            s["seen"].add(n)
            if n > s["max"]:
                s["max"] = n
                if len(s["seen"]) > 2 * REPLAY_WINDOW:
                    s["seen"] = {x for x in s["seen"] if x > n - REPLAY_WINDOW}
            return {"sid": sid, "cid": s["cid"]}

    def verify_op(self, message: bytes, sig: str) -> None:
        """Опасная операция — свежая подпись ключом TPM над её точным содержимым."""
        c = self.db.pc_get()
        if not c:
            raise PcError("клиент не привязан")
        verify(b64d(c["pub"]), b64d(sig), message)

    def unpair(self) -> bool:
        with self.mu:
            self._sessions.clear()
        return self.db.pc_unpair()
