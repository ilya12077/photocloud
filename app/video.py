"""Кадр из видео для эскиза — через ffmpeg (бинарник из pip-пакета imageio-ffmpeg,
или путь из FFMPEG). Защита: демуксер задаётся явно по расширению и разрешены
только нужные протоколы — иначе файл, замаскированный под .mp4 (например,
HLS-плейлист), мог бы заставить ffmpeg прочитать чужие файлы или URL."""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys

log = logging.getLogger("photocloud.video")

DEMUXER = {".mp4": "mov", ".mov": "mov", ".m4v": "mov", ".3gp": "mov", ".webm": "matroska",
           ".mts": "mpegts", ".m2ts": "mpegts", ".avi": "avi"}


def find_ffmpeg(configured: str) -> str | None:
    """FFMPEG из настроек -> ffmpeg из системы (в Docker поставим пакетом) -> бинарник из pip."""
    if configured:
        return configured if shutil.which(configured) or _exists(configured) else None
    system = shutil.which("ffmpeg")
    if system:
        return system
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:  # noqa: BLE001
        return None


def _exists(p: str) -> bool:
    from pathlib import Path
    return Path(p).is_file()


# Варианты вывода кадра. Формат пикселей задаём ровно тот, что родной для кодировщика:
# ffmpeg 7.1 больше не подменяет его сам и падает с -22 (Invalid argument), если попросить
# «чужой» (например rgb24 для bmp или 10-битный yuv для mjpeg). Сжатие в WebP делает Pillow.
_OUTPUTS = [
    ("bgr24", "bmp", b"BM"),           # без сжатия — быстрее всего
    ("rgb24", "png", b"\x89PNG"),       # запасной вариант
]
_preferred = 0                         # вариант вывода, который сработал последним

# Способы достать кадр, от быстрого к надёжному:
#   fast  — только ключевые кадры, 1-я секунда (на 4K HEVC ~0.2 с вместо ~0.8 с)
#   exact — честный поиск 1-й секунды (декодирует промежуточные кадры)
#   first — самый первый кадр без поиска (короткие ролики, странные таймстемпы)
# У части телефонных роликов (B-кадры + edit list) «только ключевые» не даёт ни одного
# кадра — тогда идём дальше. Если fast подряд не срабатывает, начинаем сразу с exact.
_MODES = {
    "fast": ["-skip_frame", "nokey", "-ss", "1"],
    "exact": ["-ss", "1"],
    "first": [],
}
_fast_fail = 0


def _signed(code: int) -> int:
    """Windows отдаёт код возврата беззнаковым: 4294967274 == -22."""
    return code - (1 << 32) if code > 0x7FFFFFFF else code


def frame(ffmpeg: str, src: str, protocols: str, ext: str, box: int, quality: int) -> bytes:
    """Кадр (BMP/PNG) с длинной стороной <= box. src — 'file:<путь>' или http-URL."""
    global _preferred, _fast_fail
    fmt = DEMUXER.get(ext)
    if not fmt:
        raise ValueError("unsupported video")
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    modes = ["exact", "first"] if _fast_fail >= 5 else ["fast", "exact", "first"]
    order = [_preferred] + [i for i in range(len(_OUTPUTS)) if i != _preferred]
    last = None
    for oi in order:
        pix, codec, magic = _OUTPUTS[oi]
        for mode in modes:
            cmd = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
                   "-protocol_whitelist", protocols, "-threads", "1",
                   "-f", fmt, *_MODES[mode], "-i", src,
                   "-map", "0:v:0", "-an", "-sn", "-dn", "-frames:v", "1",
                   "-vf", f"scale={box}:{box}:force_original_aspect_ratio=decrease:flags=bilinear,format={pix}",
                   "-f", "image2pipe", "-c:v", codec, "pipe:1"]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                               creationflags=flags)
            if r.returncode == 0 and r.stdout[:len(magic)] == magic:
                if oi != _preferred:
                    log.info("кадры видео: переключился на вывод %s/%s", codec, pix)
                    _preferred = oi
                if mode == "fast":
                    _fast_fail = max(0, _fast_fail - 1)
                elif "fast" in modes:
                    _fast_fail += 1
                    if _fast_fail == 5:
                        log.info("кадры видео: быстрый способ не подходит этим файлам, использую точный")
                return r.stdout
            last = r
            if r.returncode != 0:
                break                       # ошибка формата вывода — пробуем следующий вариант вывода
            # код 0, но кадра нет — пробуем следующий способ
    code = _signed(last.returncode)
    err = last.stderr[-400:].decode("utf-8", "replace").replace("\r", "").strip().replace("\n", " | ")
    log.warning("ffmpeg не смог взять кадр из %s (код %s): %s", ext, code, err or "—")
    raise ValueError("no frame")
