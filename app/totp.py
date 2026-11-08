"""Двухфакторный вход: TOTP (RFC 6238, как в Google Authenticator)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import re
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
SECRET_RE = re.compile(r"^[A-Z2-7]{32}$")
CODE_RE = re.compile(r"^\d{6}$")


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    v = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS
    return f"{v:0{DIGITS}d}"


def now_step(t: float | None = None) -> int:
    return int((time.time() if t is None else t) // STEP)


def match(secret: str, code: str, after: int = -1, t: float | None = None) -> int | None:
    """Шаг времени, которому соответствует код (±1 шаг на расхождение часов), или None.
    Шаги не новее after отвергаются — один и тот же код нельзя использовать дважды."""
    if not CODE_RE.match(code):
        return None
    cur = now_step(t)
    for st in (cur, cur - 1, cur + 1):
        if st > after and hmac.compare_digest(_hotp(secret, st), code):
            return st
    return None


def norm(code) -> str:
    """Код, как его набрал человек: пробелы и дефисы убираем."""
    return re.sub(r"[\s-]", "", code) if isinstance(code, str) and len(code) <= 40 else ""


def uri(secret: str, user: str, issuer: str) -> str:
    issuer = issuer or "Фотоархив"
    return (f"otpauth://totp/{quote(issuer)}:{quote(user)}?secret={secret}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def qr_data_url(text: str) -> str:
    """QR-код как data:-картинка (SVG). Нет библиотеки — пусто, тогда в интерфейсе только ключ текстом."""
    try:
        import segno
    except ImportError:
        return ""
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, dark="#000", light="#fff", xmldecl=False)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
