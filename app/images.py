"""Эскизы и превью на лету. На диск ничего не пишется: результат живёт
в LRU-кэше в RAM, а дальше — в кэше браузера (URL содержит mtime)."""
from __future__ import annotations

import io
import threading
import time
import warnings
from collections import OrderedDict

from PIL import ExifTags, Image, ImageFile, ImageFilter, ImageOps

try:  # HEIC с айфонов
    from pillow_heif import register_heif_opener
    register_heif_opener()
except Exception:  # noqa: BLE001
    pass

Image.MAX_IMAGE_PIXELS = 200_000_000           # защита от «бомб» распаковки
ImageFile.LOAD_TRUNCATED_IMAGES = False
warnings.simplefilter("error", Image.DecompressionBombWarning)


class TooLarge(Exception):
    pass


class LRUBytes:
    def __init__(self, max_bytes: int):
        self.max = max_bytes
        self.size = 0
        self._d: OrderedDict = OrderedDict()
        self._mu = threading.Lock()

    def get(self, key):
        with self._mu:
            v = self._d.get(key)
            if v is not None:
                self._d.move_to_end(key)
            return v

    def clear(self) -> None:
        with self._mu:
            self._d.clear()
            self.size = 0

    def put(self, key, value: bytes) -> None:
        if len(value) > self.max // 4:
            return
        with self._mu:
            old = self._d.pop(key, None)
            if old is not None:
                self.size -= len(old)
            self._d[key] = value
            self.size += len(value)
            while self.size > self.max and self._d:
                _, v = self._d.popitem(last=False)
                self.size -= len(v)


def read_limited(f, limit: int) -> bytes:
    """Дочитать файл до конца, но не больше limit байт.
    Размер узнаём заранее: f.read(limit + 1) с limit в 150 МБ заставлял Python каждый раз
    выделять буфер на 150 МБ — это ~10–17 мс на КАЖДЫЙ файл, даже на 5-килобайтный."""
    pos = f.tell()
    size = f.seek(0, 2)
    f.seek(pos)
    left = size - pos
    if left > limit:
        raise TooLarge
    data = f.read(left)
    if len(data) < left:            # файл укоротился, пока читали
        return data
    extra = f.read(1)               # файл растёт прямо сейчас — проверяем, что не вышли за лимит
    if extra and len(data) + 1 > limit:
        raise TooLarge
    return data + extra


_TRANSPOSE = {2: Image.Transpose.FLIP_LEFT_RIGHT, 3: Image.Transpose.ROTATE_180, 4: Image.Transpose.FLIP_TOP_BOTTOM,
              5: Image.Transpose.TRANSPOSE, 6: Image.Transpose.ROTATE_270, 7: Image.Transpose.TRANSVERSE,
              8: Image.Transpose.ROTATE_90}
HEAD_BYTES = 256 * 1024          # EXIF и заголовок JPEG почти всегда в первых десятках КБ


def _aspect_ok(a: tuple, b: tuple) -> bool:
    ra, rb = a[0] / a[1], b[0] / b[1]
    return abs(ra - rb) / rb < 0.03          # эскиз с чёрными полосами или от другой картинки — мимо


def embedded_jpeg(head: bytes, box: int):
    """Готовый эскиз из EXIF (IFD1), который кладут телефоны и камеры. Обычно 160–512 px.
    Декод занимает 1–3 мс вместо 50+ мс на полный JPEG. None — если нет или он мельче нужного."""
    try:
        with Image.open(io.BytesIO(head)) as im:
            if im.format != "JPEG":
                return None
            size = im.size
            raw = im.info.get("exif") or b""
            ex = im.getexif()
            orient = ex.get(0x0112, 1)
            ifd1 = ex.get_ifd(ExifTags.IFD.IFD1)
        off, ln = ifd1.get(0x0201), ifd1.get(0x0202)
        if not (isinstance(off, int) and isinstance(ln, int)) or not (0 < ln <= 200_000):
            return None
        base = 6 if raw.startswith(b"Exif\0\0") else 0
        tb = raw[base + off: base + off + ln]
        if len(tb) != ln or tb[:2] != b"\xff\xd8":
            return None
        t = Image.open(io.BytesIO(tb))
        t.load()
        if max(t.size) < box * 0.9 or not _aspect_ok(t.size, size):
            return None
        t = t.convert("RGB")
        if orient in _TRANSPOSE:                 # эскиз хранится без поворота
            t = t.transpose(_TRANSPOSE[orient])
        return t
    except Exception:  # noqa: BLE001 — любой мусор в EXIF: просто идём полным путём
        return None


def embedded_heic(data: bytes, box: int):
    """Встроенный эскиз HEIC (у iPhone ~320 px): ~30 мс вместо 1.5–2 с на полный декод."""
    try:
        import pillow_heif
        h = pillow_heif.open_heif(io.BytesIO(data), convert_hdr_to_8bit=True)
        img = h[0] if hasattr(h, "__getitem__") else h
        sizes = img.info.get("thumbnails") or []
        ok = [(sz, i) for i, sz in enumerate(sizes) if sz and sz >= box * 0.9]
        if not ok:
            return None
        th = img.get_thumbnail(min(ok)[1]).to_pillow()   # libheif уже применил поворот
        if not _aspect_ok(th.size, img.size):
            return None
        return th.convert("RGB")
    except Exception:  # noqa: BLE001
        return None


def finish(im, box: int, quality: int, fmt: str, tm: dict | None, t_decoded: float) -> bytes:
    """Уменьшение + сжатие уже декодированной картинки."""
    t1 = t_decoded
    im.thumbnail((box, box), Image.Resampling.LANCZOS if box <= 512 else Image.Resampling.BICUBIC)
    if im.mode in ("RGBA", "LA", "P"):
        im = im.convert("RGBA")
        bg = Image.new("RGB", im.size, (255, 255, 255))
        bg.paste(im, mask=im.getchannel("A"))
        im = bg
    elif im.mode != "RGB":
        im = im.convert("RGB")
    t2 = time.perf_counter()
    def encode(q: int) -> bytes:
        out = io.BytesIO()
        if fmt == "webp":
            # эскизы: method 2; превью (крупные): method 0 — почти вдвое быстрее, размер тот же
            im.save(out, "WEBP", quality=q, method=2 if box <= 1000 else 0)
        else:
            im.save(out, "JPEG", quality=q, optimize=False, progressive=box > 1000)
        return out.getvalue()

    data = encode(quality)
    if box >= 960:
        # Превью на весь экран: зернистые сканы плёнки, шумные ночные снимки при том же
        # качестве весят в 5–10 раз больше обычных (до 1 МБ на 2048 px) — на медленном
        # канале это секунды. Если вышло больше ~0.5 бита на пиксель, пережимаем сильнее:
        # на шуме разница на глаз не видна, а размер падает в разы.
        budget = im.width * im.height // 16            # ≈ 0.5 бита на пиксель: 1600×1200 -> ~120 КБ
        if len(data) > budget:
            data = encode(max(30, quality - 20))
        if len(data) > budget:
            # всё ещё много — это шум/зерно: чуть сглаживаем его (на экране незаметно,
            # для деталей есть увеличение и оригинал) и сжимаем ещё раз
            im = im.filter(ImageFilter.GaussianBlur(0.7))
            data = min(data, encode(max(30, quality - 25)), key=len)
    if tm is not None:
        tm["resize"] = (t2 - t1) * 1000
        tm["encode"] = (time.perf_counter() - t2) * 1000
    return data


def render(data: bytes, box: int, quality: int, fmt: str = "webp", tm: dict | None = None) -> bytes:
    """WebP/JPEG с длинной стороной <= box, с учётом EXIF-поворота, без метаданных.
    tm — словарь, куда пишутся длительности этапов (мс) для диагностики."""
    im = decode(data, box, tm)
    return finish(im, box, quality, fmt, tm, time.perf_counter())


def decode(data: bytes, box: int, tm: dict | None = None):
    """Декод (с EXIF-поворотом) не меньше чем до box по длинной стороне."""
    t0 = time.perf_counter()
    with Image.open(io.BytesIO(data)) as im:
        if getattr(im, "n_frames", 1) > 1:
            im.seek(0)
        # draft: JPEG декодируется сразу в 1/2..1/8 масштаба — в разы быстрее и меньше памяти.
        # Просим ровно столько, чтобы ДЛИННАЯ сторона была >= box (а не обе), — так draft
        # чаще берёт 1/8 вместо 1/4.
        w, h = im.size
        req = (box, max(1, box * h // w)) if w >= h else (max(1, box * w // h), box)
        im.draft("RGB", req)
        im = ImageOps.exif_transpose(im)
        im.load()
        if tm is not None:
            tm["decode"] = tm.get("decode", 0) + (time.perf_counter() - t0) * 1000
        return im
