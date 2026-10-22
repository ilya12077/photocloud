"""Очередь на генерацию эскизов.

Обычный семафор обслуживает запросы по порядку прихода (FIFO). При прокрутке это
плохо: впереди стоят эскизы, которые уже уехали с экрана, а видимые ждут за ними
(в логах это было «очередь ~1 с» при работе ~0.1 с на эскиз). Здесь:
  * сначала быстрая версия открытого фото, потом полная, потом соседние, потом сетка;
  * внутри уровня — САМЫЙ СВЕЖИЙ запрос первым (LIFO): он про то, что на экране сейчас;
  * ждущие запросы раз в 0.25 с проверяют, не ушёл ли клиент, и уходят из очереди."""
from __future__ import annotations

import asyncio
import heapq
import itertools

PRIO_QUICK = 0       # просмотрщик: быстрая лёгкая версия открытого фото
PRIO_VIEWER = 1      # просмотрщик: полная версия открытого фото
PRIO_PREFETCH = 2    # соседние фото заранее
PRIO_GRID = 3


class Gone(Exception):
    """Клиент отменил запрос, пока тот стоял в очереди."""


class Scheduler:
    def __init__(self, slots: int):
        self.slots = slots
        self.free = slots
        self._heap: list = []
        self._seq = itertools.count()

    @property
    def waiting(self) -> int:
        return sum(1 for e in self._heap if not e[2].done())

    async def acquire(self, prio: int, request=None) -> None:
        if self.free > 0 and not self.waiting:
            self.free -= 1
            return
        fut = asyncio.get_running_loop().create_future()
        heapq.heappush(self._heap, (prio, -next(self._seq), fut))   # меньше = раньше
        try:
            while True:
                try:
                    await asyncio.wait_for(asyncio.shield(fut), 0.25)
                    return                                         # слот передан нам
                except asyncio.TimeoutError:
                    if request is not None and await request.is_disconnected():
                        raise Gone from None
        except BaseException:
            if fut.done() and not fut.cancelled():
                self.release()          # слот уже успели отдать — возвращаем
            else:
                fut.cancel()            # release() пропустит отменённых
            raise

    def release(self) -> None:
        while self._heap:
            _, _, fut = heapq.heappop(self._heap)
            if not fut.done():
                fut.set_result(None)    # слот переходит ждущему, free не меняется
                return
        self.free = min(self.slots, self.free + 1)

    def slot(self, prio: int, request=None):
        return _Slot(self, prio, request)


class _Slot:
    def __init__(self, s: Scheduler, prio: int, request):
        self.s, self.prio, self.request = s, prio, request

    async def __aenter__(self):
        await self.s.acquire(self.prio, self.request)

    async def __aexit__(self, *_exc):
        self.s.release()
        return False
