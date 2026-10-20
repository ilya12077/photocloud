"""Клиент Home Assistant REST API: пробуждение ПК и уведомления на телефон.

Вызываются ТОЛЬКО сервисы из конфига; пользовательский ввод в вызов
никогда не попадает, кроме текста уведомления, который чистится."""
from __future__ import annotations

import logging
import re
import time

import httpx

log = logging.getLogger("photocloud.ha")

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(text: str, limit: int = 64) -> str:
    """Для подстановки недоверенных строк (логин, IP) в текст уведомления:
    без управляющих символов и шаблонных скобок, ограниченная длина."""
    t = _CTRL.sub("", str(text)).replace("{", "(").replace("}", ")")
    return t[:limit] + ("…" if len(t) > limit else "")


class HomeAssistant:
    def __init__(self, s):
        self.s = s
        self._client = httpx.AsyncClient(
            base_url=s.ha_url,
            headers={"Authorization": f"Bearer {s.ha_token}"},
            timeout=httpx.Timeout(10.0, connect=5.0),
            verify=s.ha_verify_ssl,
            follow_redirects=False,
        )
        self._last_notify: dict[str, float] = {}

    async def close(self) -> None:
        await self._client.aclose()

    async def call(self, service: str, data: dict) -> bool:
        domain, svc = service.split(".", 1)  # формат проверен в config
        try:
            r = await self._client.post(f"/api/services/{domain}/{svc}", json=data)
        except httpx.HTTPError as e:
            log.warning("HA %s: %s", service, type(e).__name__)
            return False
        if r.status_code >= 300:
            log.warning("HA %s: HTTP %s", service, r.status_code)
            return False
        return True

    async def wake(self) -> bool:
        if not (self.s.ha_token and self.s.ha_wake_service):
            return False
        return await self.call(self.s.ha_wake_service, dict(self.s.ha_wake_data))

    async def notify(self, event: str, message: str, *, dedupe_s: int = 60, key: str | None = None) -> None:
        """Уведомление, если событие включено. Одинаковые события не чаще раза в dedupe_s."""
        if not self.s.ha_notify_service or event not in self.s.notify_events:
            return
        now = time.time()
        key = f"{event}:{key if key is not None else message}"
        if now - self._last_notify.get(key, 0) < dedupe_s:
            return
        self._last_notify[key] = now
        if len(self._last_notify) > 500:
            self._last_notify = {k: v for k, v in self._last_notify.items() if now - v < 3600}
        await self.call(self.s.ha_notify_service, {
            "title": self.s.public_name,
            "message": message,
            "data": {"tag": f"photocloud-{event}", "group": "photocloud"},
        })
