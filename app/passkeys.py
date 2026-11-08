"""Вход по ключу (passkey, WebAuthn): ключ живёт на устройстве пользователя (отпечаток, лицо, PIN),
сервер хранит только открытый ключ. Вход по ключу — сразу, без пароля и кода из приложения."""
from __future__ import annotations

import hashlib
import secrets
import time
from urllib.parse import urlparse

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

TTL = 300


class PasskeyError(ValueError):
    pass


def rp_for(origin: str, allowed: set[str]) -> tuple[str, str]:
    """(rp_id, origin): ключ привязывается к домену сайта; чужой Origin — отказ."""
    origin = (origin or "").rstrip("/")
    if not origin or origin not in allowed:
        raise PasskeyError("origin")
    host = urlparse(origin).hostname
    if not host:
        raise PasskeyError("origin")
    return host, origin


class Passkeys:
    def __init__(self, db, rp_name: str):
        self.db = db
        self.rp_name = rp_name
        self._pending: dict[str, dict] = {}     # билет -> {challenge, rp_id, origin, user?, exp}

    def _put(self, data: dict) -> str:
        now = time.time()
        for k in [k for k, v in self._pending.items() if v["exp"] < now]:
            del self._pending[k]
        if len(self._pending) > 1000:
            raise PasskeyError("busy")
        ticket = secrets.token_urlsafe(24)
        self._pending[ticket] = {**data, "exp": now + TTL}
        return ticket

    def _take(self, ticket: str) -> dict:
        p = self._pending.pop(ticket or "", None)
        if p is None or p["exp"] < time.time():
            raise PasskeyError("expired")
        return p

    # ---- создание ключа (пользователь уже вошёл)
    def register_options(self, user: str, rp_id: str, origin: str) -> tuple[str, str]:
        """-> (опции для navigator.credentials.create в JSON, билет)."""
        have = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid)) for cid, *_ in self.db.passkeys_of(user)]
        opts = generate_registration_options(
            rp_id=rp_id, rp_name=self.rp_name or "Фотоархив", user_name=user, user_display_name=user,
            user_id=hashlib.sha256(("photocloud-user:" + user).encode()).digest()[:16],
            exclude_credentials=have,   # на этом устройстве ключ уже есть — второй не нужен
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
        ticket = self._put({"challenge": opts.challenge, "rp_id": rp_id, "origin": origin, "user": user})
        return options_to_json(opts), ticket

    def register(self, user: str, ticket: str, credential: dict, name: str) -> str:
        p = self._take(ticket)
        if p["user"] != user:
            raise PasskeyError("user")
        try:
            v = verify_registration_response(credential=credential, expected_challenge=p["challenge"],
                                             expected_rp_id=p["rp_id"], expected_origin=p["origin"],
                                             require_user_verification=True)
        except (InvalidRegistrationResponse, KeyError, TypeError, ValueError) as e:
            raise PasskeyError(f"registration: {e}") from None
        cid = bytes_to_base64url(v.credential_id)
        self.db.passkey_add(cid, user, v.credential_public_key, v.sign_count, (name or "")[:60])
        return cid

    # ---- вход по ключу
    def login_options(self, rp_id: str, origin: str) -> tuple[str, str]:
        # список ключей не передаём: устройство само предложит ключи этого сайта
        opts = generate_authentication_options(rp_id=rp_id, user_verification=UserVerificationRequirement.REQUIRED)
        ticket = self._put({"challenge": opts.challenge, "rp_id": rp_id, "origin": origin})
        return options_to_json(opts), ticket

    def login(self, ticket: str, credential: dict) -> str:
        """-> пользователь, если ключ его и подпись верна."""
        p = self._take(ticket)
        if not isinstance(credential, dict) or not isinstance(credential.get("id"), str):
            raise PasskeyError("credential")
        row = self.db.passkey_get(credential["id"])
        if row is None:
            raise PasskeyError("unknown key")
        user, pubkey, count = row
        try:
            v = verify_authentication_response(credential=credential, expected_challenge=p["challenge"],
                                               expected_rp_id=p["rp_id"], expected_origin=p["origin"],
                                               credential_public_key=pubkey, credential_current_sign_count=count,
                                               require_user_verification=True)
        except (InvalidAuthenticationResponse, KeyError, TypeError, ValueError) as e:
            raise PasskeyError(f"authentication: {e}") from None
        self.db.passkey_used(credential["id"], v.new_sign_count)
        return user


