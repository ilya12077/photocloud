"""Эскизы и превью на лету. На диск ничего не пишется: результат живёт
в LRU-кэше в RAM, а дальше — в кэше браузера (URL содержит mtime)."""
from __future__ import annotations

import io
import threading
import warnings
from collections import OrderedDict

from PIL import Image, ImageFile, ImageOps

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
    data = f.read(limit + 1)
    if len(data) > limit:
        raise TooLarge
    return data


def render(data: bytes, box: int, quality: int, fmt: str = "webp") -> bytes:
    """WebP/JPEG с длинной стороной <= box, с учётом EXIF-поворота, без метаданных."""
    with Image.open(io.BytesIO(data)) as im:
        if getattr(im, "n_frames", 1) > 1:
            im.seek(0)
        # draft: JPEG декодируется сразу в 1/2..1/8 масштаба — в разы быстрее и меньше памяти
        im.draft("RGB", (box, box))
        im = ImageOps.exif_transpose(im)
        im.thumbnail((box, box), Image.Resampling.LANCZOS if box <= 512 else Image.Resampling.BICUBIC)
        if im.mode in ("RGBA", "LA", "P"):
            im = im.convert("RGBA")
            bg = Image.new("RGB", im.size, (255, 255, 255))
            bg.paste(im, mask=im.getchannel("A"))
            im = bg
        elif im.mode != "RGB":
            im = im.convert("RGB")
        out = io.BytesIO()
        if fmt == "webp":
            # method: 4 для мелких (лучше сжатие), 2 для крупных (быстрее кодирование)
            im.save(out, "WEBP", quality=quality, method=4 if box <= 1000 else 2)
        else:
            im.save(out, "JPEG", quality=quality, optimize=False, progressive=box > 1000)
        return out.getvalue()
