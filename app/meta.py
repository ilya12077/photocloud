"""Дата съёмки без чтения файла целиком.

JPEG: EXIF DateTimeOriginal (обычно в первых нескольких КБ).
MP4/MOV/3GP: creation_time из atom mvhd (несколько коротких чтений с seek,
работает и когда moov в конце файла).

Парсеры читают ограниченное число байт и никогда не доверяют длинам из файла
без проверки — битый или злонамеренный файл даёт None, а не исключение/зависание."""
from __future__ import annotations

import datetime as dt
import re
import struct
from zoneinfo import ZoneInfo

JPEG_EXT = {".jpg", ".jpeg"}
MP4_EXT = {".mp4", ".mov", ".m4v", ".3gp"}

_EXIF_MAX = 128 * 1024           # дальше первых 128 КБ EXIF не ищем
_DATE_RE = re.compile(rb"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
_TZ_RE = re.compile(rb"^([+-])(\d{2}):(\d{2})")
_MP4_EPOCH = dt.datetime(1904, 1, 1, tzinfo=dt.timezone.utc)
_MIN_TS = dt.datetime(1995, 1, 1, tzinfo=dt.timezone.utc).timestamp()


def _plausible(ts: float) -> float | None:
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    return ts if _MIN_TS <= ts <= now + 86400 * 2 else None


class _Buf:
    """Читает файл с начала порциями по мере надобности (не больше limit)."""

    def __init__(self, f, limit: int):
        self.f, self.limit, self.b = f, limit, b""

    def need(self, end: int) -> bool:
        if end > self.limit:
            return False
        while len(self.b) < end:
            chunk = self.f.read(max(end - len(self.b), 16384))
            if not chunk:
                return False
            self.b += chunk
        return True


def _exif_date(f, tz: ZoneInfo) -> float | None:
    r = _Buf(f, _EXIF_MAX)
    if not r.need(4) or r.b[:2] != b"\xff\xd8":
        return None
    pos = 2
    for _ in range(32):                       # сегменты до EXIF
        if not r.need(pos + 4) or r.b[pos] != 0xFF:
            return None
        marker = r.b[pos + 1]
        if marker in (0xD9, 0xDA):            # конец/начало данных — EXIF не нашли
            return None
        seglen = struct.unpack(">H", r.b[pos + 2:pos + 4])[0]
        if seglen < 2:
            return None
        if marker == 0xE1 and r.need(pos + 10) and r.b[pos + 4:pos + 10] == b"Exif\0\0":
            return _tiff_date(r, pos + 10, pos + 2 + seglen, tz)
        pos += 2 + seglen
    return None


def _tiff_date(r: _Buf, base: int, end: int, tz: ZoneInfo) -> float | None:
    if not r.need(base + 8):
        return None
    bo = r.b[base:base + 2]
    if bo == b"II":
        e = "<"
    elif bo == b"MM":
        e = ">"
    else:
        return None

    def u16(off):
        return struct.unpack(e + "H", r.b[off:off + 2])[0]

    def u32(off):
        return struct.unpack(e + "I", r.b[off:off + 4])[0]

    def ifd(off) -> dict:
        """tag -> (type, count, value_offset_abs) для одной IFD."""
        a = base + off
        if off < 8 or a >= end or not r.need(a + 2):
            return {}
        n = u16(a)
        if n > 400 or not r.need(a + 2 + n * 12):
            return {}
        out = {}
        for i in range(n):
            p = a + 2 + i * 12
            tag, typ, cnt = u16(p), u16(p + 2), u32(p + 4)
            out[tag] = (typ, cnt, p + 8)
        return out

    def ascii_val(entry) -> bytes | None:
        typ, cnt, p = entry
        if typ != 2 or not (1 <= cnt <= 64):
            return None
        if cnt <= 4:
            return r.b[p:p + cnt]
        a = base + u32(p)
        if a + cnt > end or not r.need(a + cnt):
            return None
        return r.b[a:a + cnt]

    ifd0 = ifd(u32(base + 4))
    candidates = []
    if 0x8769 in ifd0:
        typ, _, p = ifd0[0x8769]
        sub = ifd(u32(p)) if typ in (4, 13) else {}
        for tag, tz_tag in ((0x9003, 0x9011), (0x9004, 0x9012)):   # Original, Digitized
            if tag in sub:
                candidates.append((ascii_val(sub[tag]), ascii_val(sub[tz_tag]) if tz_tag in sub else None))
    for raw, off in candidates:
        ts = _parse_exif_dt(raw, off, tz)
        if ts:
            return ts
    return None


def _parse_exif_dt(raw: bytes | None, off: bytes | None, tz: ZoneInfo) -> float | None:
    if not raw:
        return None
    m = _DATE_RE.match(raw)
    if not m:
        return None
    try:
        y, mo, d, h, mi, s = (int(x) for x in m.groups())
        naive = dt.datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None
    zone: dt.tzinfo = tz
    if off:
        mt = _TZ_RE.match(off)
        if mt:
            sign = 1 if mt.group(1) == b"+" else -1
            zone = dt.timezone(sign * dt.timedelta(hours=int(mt.group(2)), minutes=int(mt.group(3))))
    return _plausible(naive.replace(tzinfo=zone).timestamp())


def _mp4_date(f, size: int) -> float | None:
    def box_at(pos: int, limit: int):
        if pos + 8 > limit:
            return None
        f.seek(pos)
        h = f.read(16)
        if len(h) < 8:
            return None
        bsize, btype = struct.unpack(">I4s", h[:8])
        hdr = 8
        if bsize == 1:
            if len(h) < 16:
                return None
            bsize = struct.unpack(">Q", h[8:16])[0]
            hdr = 16
        elif bsize == 0:
            bsize = limit - pos
        if bsize < hdr or pos + bsize > limit:
            return None
        return btype, pos, bsize, hdr

    pos, moov = 0, None
    for _ in range(64):                       # верхний уровень: ftyp, mdat, moov...
        b = box_at(pos, size)
        if b is None:
            return None
        if b[0] == b"moov":
            moov = b
            break
        pos += b[2]
    if moov is None:
        return None
    _, mpos, msize, mhdr = moov
    pos, end = mpos + mhdr, mpos + msize
    for _ in range(64):
        b = box_at(pos, end)
        if b is None:
            return None
        if b[0] == b"mvhd":
            f.seek(b[1] + b[3])
            body = f.read(20)
            if len(body) < 8:
                return None
            if body[0] == 1:
                if len(body) < 12:
                    return None
                secs = struct.unpack(">Q", body[4:12])[0]
            else:
                secs = struct.unpack(">I", body[4:8])[0]
            if secs == 0:
                return None
            try:
                return _plausible((_MP4_EPOCH + dt.timedelta(seconds=secs)).timestamp())
            except OverflowError:
                return None
        pos += b[2]
    return None


# ---------------------------------------------------------------- дата из имени файла
# Телефоны, мессенджеры и скриншотеры пишут время съёмки в имя (местное время):
#   IMG_20240512_123456.jpg  PXL_20230101_120000123.jpg  20240512_123456.mp4 (Samsung)
#   IMG-20230101-WA0001.jpg (WhatsApp, только дата)  photo_2023-01-01_12-00-00.jpg (Telegram)
#   Screenshot_2023-01-01-12-00-00-123_com.app.png   1675859348723.jpg (Unix-время в мс)
_NAME_DT = re.compile(
    r"(?<!\d)((?:19|20)\d{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])"
    r"(?:(?:[-_. T]|\s+at\s+)?([01]\d|2[0-3])[-_.:h]?([0-5]\d)[-_.:m]?([0-5]\d)(?:[-_.]?\d{1,3})?)?(?!\d)")
# суффикс копии — только через разделитель или в скобках: «1675859348723_1», «1675859348723 (2)»
_NAME_UNIX = re.compile(r"^(\d{10}|\d{13})(?:[-_ ]\(?\d{1,3}\)?|\(\d{1,3}\))?$")


def name_date(name: str, tz: ZoneInfo) -> float | None:
    """Дата из имени файла (местное время) или None. Без даты времени — полдень."""
    stem = name.rsplit(".", 1)[0]
    m = _NAME_UNIX.match(stem)
    if m:
        v = int(m.group(1))
        return _plausible(v / 1000 if len(m.group(1)) == 13 else v)
    for m in _NAME_DT.finditer(stem):
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        h, mi, s = (int(m.group(i)) if m.group(i) else None for i in (4, 5, 6))
        if h is None:
            h, mi, s = 12, 0, 0
        try:
            ts = dt.datetime(y, mo, d, h, mi, s, tzinfo=tz).timestamp()
        except ValueError:          # 31 февраля и т.п.
            continue
        ts = _plausible(ts)
        if ts:
            return ts
    return None


def needs_scan(ext: str) -> bool:
    return ext in JPEG_EXT or ext in MP4_EXT


def taken_at(f, ext: str, size: int, tz: ZoneInfo) -> float | None:
    """Дата съёмки (unix ts) или None. f — открытый на чтение файл с поддержкой seek."""
    try:
        if ext in JPEG_EXT:
            return _exif_date(f, tz)
        if ext in MP4_EXT:
            return _mp4_date(f, size)
    except (struct.error, ValueError, OverflowError):
        return None
    # OSError (обрыв SMB и т.п.) пробрасываем: это «не смогли прочитать», а не «даты нет»
    return None
