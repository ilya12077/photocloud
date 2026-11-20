"""Отложенный повторный обход архива после серии событий от клиента ПК.

Сканирование нельзя запускать после каждого отчёта об удалении: одна массовая
операция выдаёт тысячи событий и десятки отчётов о пачках. Время — monotonic.
Методы вызываются из основного asyncio-потока сервера.
"""
from __future__ import annotations

import time


class ArchiveScanDebounce:
    def __init__(self, quiet_seconds: float = 20, max_wait_seconds: float = 180):
        self.quiet_seconds = quiet_seconds
        self.max_wait_seconds = max_wait_seconds
        self.first = self.last = 0.0

    def note(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        if not self.last:
            self.first = now
        self.last = now

    def waiting(self, now: float | None = None) -> bool:
        if not self.last:
            return False
        now = time.monotonic() if now is None else now
        return (now - self.last < self.quiet_seconds
                and now - self.first < self.max_wait_seconds)

    def reset(self) -> None:
        self.first = self.last = 0.0
