"""Вход через Яндекс ID (OAuth 2.0, Authorization Code + PKCE).

Регистрации через Яндекс нет: войти можно только в аккаунт, к которому администратор
заранее привязал email в /admin. Код меняем на токен напрямую на oauth.yandex.ru по TLS,
по токену берём email с login.yandex.ru/info — и токен сразу забываем. state хранится
на сервере и привязан к браузеру cookie (защита от подмены входа), всё одноразовое, 10 минут."""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx

AUTH_URL = "https://oauth.yandex.ru/authorize"
TOKEN_URL = "https://oauth.yandex.ru/token"
INFO_URL = "https://login.yandex.ru/info"
TTL = 600


class YandexError(Exception):
    pass


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class YandexAuth:
    def __init__(self, client_id: str, client_secret: str, public_url: str):
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri = public_url + "/auth/yandex/callback"
        self._pending: dict[str, dict] = {}
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False)

    async def close(self) -> None:
        await self._http.aclose()

    def start(self, remember: bool = False) -> tuple[str, str]:
        """-> (url для редиректа, state для cookie). remember — галочка «Запомнить вход»."""
        now = time.time()
        for k in [k for k, v in self._pending.items() if now - v["t"] > TTL]:
            del self._pending[k]
        if len(self._pending) > 1000:
            raise YandexError("too many pending")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self._pending[state] = {"verifier": verifier, "t": now, "remember": remember}
        q = {"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
             "scope": "login:email", "state": state,
             "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        return AUTH_URL + "?" + urlencode(q), state

    async def finish(self, state: str, cookie_state: str, code: str) -> tuple[list[str], bool]:
        """-> (адреса почты аккаунта, первый — основной; «Запомнить вход»)."""
        if not state or not cookie_state or not secrets.compare_digest(state, cookie_state):
            raise YandexError("state mismatch")
        p = self._pending.pop(state, None)
        if p is None or time.time() - p["t"] > TTL:
            raise YandexError("state expired")
        if not code or len(code) > 2048:
            raise YandexError("no code")
        try:
            r = await self._http.post(TOKEN_URL, data={
                "grant_type": "authorization_code", "code": code, "client_id": self.client_id,
                "client_secret": self.client_secret, "code_verifier": p["verifier"]})
        except httpx.HTTPError as e:
            raise YandexError(f"token endpoint: {type(e).__name__}") from None
        if r.status_code != 200:
            raise YandexError(f"token endpoint HTTP {r.status_code}")
        try:
            token = r.json()["access_token"]
        except (KeyError, ValueError, TypeError):
            raise YandexError("no access_token") from None
        try:
            r = await self._http.get(INFO_URL, params={"format": "json"}, headers={"Authorization": f"OAuth {token}"})
        except httpx.HTTPError as e:
            raise YandexError(f"info: {type(e).__name__}") from None
        if r.status_code != 200:
            raise YandexError(f"info HTTP {r.status_code}")
        try:
            info = r.json()
        except ValueError:
            raise YandexError("info: bad json") from None
        emails = [info.get("default_email")] + list(info.get("emails") or [])
        out = []
        for e in emails:
            if isinstance(e, str) and "@" in e and e.lower() not in out:
                out.append(e.lower())
        if not out:
            raise YandexError("no email (нужно право «Адрес электронной почты»)")
        return out, bool(p.get("remember"))
