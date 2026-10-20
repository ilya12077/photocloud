"""Вход через Google (OpenID Connect, Authorization Code + PKCE).

Регистрации через Google нет: войти можно только в аккаунт, к которому
администратор заранее привязал email в /admin.

id_token получаем напрямую с token endpoint Google по TLS, поэтому по
OIDC Core §3.1.3.7 подпись можно не проверять — проверяем iss, aud, exp, nonce
и email_verified. state хранится на сервере и привязан к браузеру cookie
(защита от подмены входа), всё одноразовое и живёт 10 минут."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
ISSUERS = {"https://accounts.google.com", "accounts.google.com"}
TTL = 600


class GoogleError(Exception):
    pass


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class GoogleAuth:
    def __init__(self, client_id: str, client_secret: str, public_url: str):
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri = public_url + "/auth/google/callback"
        self._pending: dict[str, dict] = {}
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False)

    async def close(self) -> None:
        await self._http.aclose()

    def _purge(self) -> None:
        now = time.time()
        for k in [k for k, v in self._pending.items() if now - v["t"] > TTL]:
            del self._pending[k]

    def start(self) -> tuple[str, str]:
        """-> (url для редиректа, state для cookie)."""
        self._purge()
        if len(self._pending) > 1000:
            raise GoogleError("too many pending")
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self._pending[state] = {"nonce": nonce, "verifier": verifier, "t": time.time()}
        q = {
            "client_id": self.client_id, "redirect_uri": self.redirect_uri, "response_type": "code",
            "scope": "openid email", "state": state, "nonce": nonce, "prompt": "select_account",
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
        }
        return AUTH_URL + "?" + urlencode(q), state

    async def finish(self, state: str, cookie_state: str, code: str) -> str:
        """Проверяет ответ Google, возвращает подтверждённый email."""
        if not state or not cookie_state or not secrets.compare_digest(state, cookie_state):
            raise GoogleError("state mismatch")
        p = self._pending.pop(state, None)
        if p is None or time.time() - p["t"] > TTL:
            raise GoogleError("state expired")
        if not code or len(code) > 2048:
            raise GoogleError("no code")
        try:
            r = await self._http.post(TOKEN_URL, data={
                "code": code, "client_id": self.client_id, "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri, "grant_type": "authorization_code", "code_verifier": p["verifier"],
            })
        except httpx.HTTPError as e:
            raise GoogleError(f"token endpoint: {type(e).__name__}") from None
        if r.status_code != 200:
            raise GoogleError(f"token endpoint HTTP {r.status_code}")
        try:
            idt = r.json()["id_token"]
            payload = idt.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (KeyError, IndexError, ValueError, TypeError):
            raise GoogleError("bad id_token") from None
        now = time.time()
        if claims.get("iss") not in ISSUERS:
            raise GoogleError("iss")
        aud = claims.get("aud")
        if aud != self.client_id and not (isinstance(aud, list) and self.client_id in aud):
            raise GoogleError("aud")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - 60:
            raise GoogleError("expired")
        if not secrets.compare_digest(str(claims.get("nonce", "")), p["nonce"]):
            raise GoogleError("nonce")
        if claims.get("email_verified") is not True or not isinstance(claims.get("email"), str):
            raise GoogleError("email not verified")
        return claims["email"].lower()
