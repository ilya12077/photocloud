"""Потоковая ZIP-упаковка оригиналов и одноразовые ссылки на скачивание.

ZIP_STORED: JPEG/HEIC/MP4 уже сжаты, повторное сжатие расходует CPU без выгоды.
Не используем временные файлы или общий RAM-буфер: ZipFile пишет в выходной
буфер, а генератор отдаёт каждый кусок сразу после чтения исходника.
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
import zipfile
from pathlib import PurePosixPath

log = logging.getLogger("photocloud.download")


class DownloadTickets:
    def __init__(self, ttl: int = 180):
        self.ttl = ttl
        self.lock = threading.Lock()
        self.pending: dict[str, tuple[str, str, tuple[str, ...], float]] = {}

    def issue(self, user: str, sid: str, ids: list[str], now: float | None = None) -> str:
        now = time.monotonic() if now is None else now
        with self.lock:
            self.pending = {k: v for k, v in self.pending.items() if v[3] > now}
            if len(self.pending) >= 64:
                oldest = min(self.pending, key=lambda key: self.pending[key][3])
                del self.pending[oldest]
            ticket = secrets.token_urlsafe(24)  # 32 случайных символа
            self.pending[ticket] = (user, sid, tuple(ids), now + self.ttl)
            return ticket

    def take(self, user: str, sid: str, ticket: str, now: float | None = None) -> tuple[str, ...] | None:
        now = time.monotonic() if now is None else now
        with self.lock:
            entry = self.pending.get(ticket)
            if entry is None:
                return None
            if entry[3] <= now:
                del self.pending[ticket]
                return None
            if (entry[0], entry[1]) != (user, sid):
                return None
            del self.pending[ticket]
            return entry[2]


class _ZipBuffer:
    """Несохраняемый в файлы приёмник ZipFile: без seek -> data descriptors."""
    def __init__(self):
        self.parts: list[bytes] = []

    def write(self, data: bytes) -> int:
        if data:
            self.parts.append(bytes(data))
        return len(data)

    def flush(self) -> None:
        pass

    def drain(self):
        parts, self.parts = self.parts, []
        return parts


def _zip_path(rel: str) -> str:
    path = rel.replace("\\", "/")
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or any(part in (".", "..") for part in path.split("/")):
        raise ValueError("некорректный путь внутри архива")
    return "/".join(parts)


def iter_zip_originals(photos, opener, chunk_size: int = 256 * 1024):
    """Потоковый ZIP64 с исходной иерархией папок и отчётом о неудачах чтения.

    Один исходный файл читается целиком до следующего, без параллельных
    SMB-чтений. Если сеть оборвалась, в ZIP добавляется отчёт об ошибках.
    Уже начатый файл может оказаться неполным — отчёт явно сообщает об этом.
    """
    sink = _ZipBuffer()
    errors = []
    with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for photo in photos:
            path = photo.rel
            try:
                safe_path = _zip_path(path)
                # Сначала открыть источник: не создавать пустых записей о
                # файлах, которых нет на ПК.
                with opener(path) as source:
                    info = zipfile.ZipInfo(safe_path)
                    info.compress_type = zipfile.ZIP_STORED
                    info.flag_bits |= 0x800
                    stamp = time.localtime(photo.mtime)
                    if 1980 <= stamp.tm_year <= 2107:
                        info.date_time = stamp[:6]
                    with archive.open(info, mode="w", force_zip64=True) as dest:
                        while True:
                            part = source.read(chunk_size)
                            if not part:
                                break
                            dest.write(part)
                            yield from sink.drain()
                yield from sink.drain()
            except Exception as exc:
                log.warning("ZIP: не удалось полностью прочитать %s (%s)", path, type(exc).__name__)
                errors.append(f"{path}: {type(exc).__name__}: {exc}")
                yield from sink.drain()
        if errors:
            archive.writestr("ОШИБКИ_СКАЧИВАНИЯ.txt",
                             ("Некоторые файлы не удалось прочитать полностью.\n"
                              "Не используйте неполные файлы из этого архива.\n\n"
                              + "\n".join(errors) + "\n").encode("utf-8"))
            yield from sink.drain()
    yield from sink.drain()
