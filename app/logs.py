"""Журналы для админки.

server — последние записи логов процесса (в памяти, кольцевой буфер).
audit  — журнал безопасности (входы, блокировки, изменения пользователей и
настроек): JSONL в DATA_DIR/audit.log, ротация по размеру."""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import deque
from pathlib import Path

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(v, limit=200) -> str:
    return _CTRL.sub(" ", str(v))[:limit]


class RingHandler(logging.Handler):
    def __init__(self, size: int = 3000):
        super().__init__(logging.INFO)
        self.buf: deque = deque(maxlen=size)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                msg += f" [{type(record.exc_info[1]).__name__}]"
            self.buf.append({"t": round(record.created, 3), "lvl": record.levelname,
                             "src": record.name, "msg": _clean(msg, 1000)})
        except Exception:  # noqa: BLE001
            pass

    def tail(self, n: int, min_level: int) -> list[dict]:
        out = [r for r in list(self.buf) if logging.getLevelName(r["lvl"]) >= min_level]
        return out[-n:]


class Audit:
    MAX_BYTES = 5 * 1024 * 1024

    def __init__(self, path: Path):
        self.path = path
        self.recent: deque = deque(maxlen=3000)
        self._mu = threading.Lock()
        try:
            with open(path, encoding="utf-8") as f:
                for line in f.readlines()[-3000:]:
                    try:
                        self.recent.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass

    def __call__(self, event: str, user: str = "", ip: str = "", detail: str = "") -> None:
        rec = {"t": round(time.time(), 3), "ev": event, "user": _clean(user, 64), "ip": _clean(ip, 64),
               "detail": _clean(detail)}
        with self._mu:
            self.recent.append(rec)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.MAX_BYTES:
                    os.replace(self.path, self.path.with_suffix(".log.1"))
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except OSError:
                logging.getLogger("photocloud").warning("audit: не удалось записать журнал")

    def tail(self, n: int) -> list[dict]:
        return list(self.recent)[-n:]


ring = RingHandler()


def install() -> None:
    root = logging.getLogger()
    if ring not in root.handlers:
        root.addHandler(ring)
    lg = logging.getLogger("uvicorn")      # uvicorn.error -> uvicorn (дальше не всплывает)
    if ring not in lg.handlers:
        lg.addHandler(ring)
