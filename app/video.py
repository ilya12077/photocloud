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


def frame(ffmpeg: str, src: str, protocols: str, ext: str, box: int, quality: int) -> bytes:
    """Кадр (BMP) с длинной стороной <= box. src — 'file:<путь>' или http-URL."""
    fmt = DEMUXER.get(ext)
    if not fmt:
        raise ValueError("unsupported video")
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    for seek in ("1", "0"):                             # короче секунды — берём первый кадр
        cmd = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
               "-protocol_whitelist", protocols, "-f", fmt,
               "-ss", seek, "-i", src, "-map", "0:v:0", "-frames:v", "1",
               # кадр отдаём несжатым BMP в RGB: mjpeg-кодировщик ffmpeg 7.x отказывается от
               # 10-битного HDR/HEVC с телефонов и «неполного» диапазона цветов (ошибка -22),
               # а сжатие в WebP всё равно делает Pillow
               "-vf", f"scale={box}:{box}:force_original_aspect_ratio=decrease,format=rgb24",
               "-f", "image2", "-c:v", "bmp", "pipe:1"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                           creationflags=flags)
        if r.returncode == 0 and r.stdout[:2] == b"BM":
            return r.stdout
    if r.returncode < 0 or r.returncode > 128:
        log.warning("ffmpeg аварийно завершился (код %s) на %s — попробуй другую сборку ffmpeg (FFMPEG=...)",
                    r.returncode, ext)
    else:
        log.info("ffmpeg не смог взять кадр: %s", r.stderr[-300:].decode("utf-8", "replace").strip())
    raise ValueError("no frame")
