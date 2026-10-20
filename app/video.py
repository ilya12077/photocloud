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

DEMUXER = {".mp4": "mov", ".mov": "mov", ".m4v": "mov", ".3gp": "mov", ".webm": "matroska"}


def find_ffmpeg(configured: str) -> str | None:
    if configured:
        return configured if shutil.which(configured) or _exists(configured) else None
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:  # noqa: BLE001
        return shutil.which("ffmpeg")


def _exists(p: str) -> bool:
    from pathlib import Path
    return Path(p).is_file()


def frame(ffmpeg: str, src: str, protocols: str, ext: str, box: int, quality: int) -> bytes:
    """JPEG-кадр с длинной стороной <= box. src — 'file:<путь>' или http-URL."""
    fmt = DEMUXER.get(ext)
    if not fmt:
        raise ValueError("unsupported video")
    q = max(2, min(31, round(31 - quality * 0.29)))   # 72 -> ~10
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    for seek in ("1", "0"):                             # короче секунды — берём первый кадр
        cmd = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
               "-protocol_whitelist", protocols, "-f", fmt,
               "-ss", seek, "-i", src, "-map", "0:v:0", "-frames:v", "1",
               "-vf", f"scale={box}:{box}:force_original_aspect_ratio=decrease",
               "-q:v", str(q), "-f", "image2", "-c:v", "mjpeg", "pipe:1"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                           creationflags=flags)
        if r.returncode == 0 and r.stdout[:2] == b"\xff\xd8":
            return r.stdout
    log.info("ffmpeg не смог взять кадр: %s", r.stderr[-300:].decode("utf-8", "replace").strip())
    raise ValueError("no frame")
