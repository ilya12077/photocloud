"""Перекодирование видео для просмотра — на лету, без записи на диск.

Отдаём HLS: плейлист из 4-секундных кусков, каждый кусок ffmpeg делает по запросу
(-ss начало -t 4) в H.264 + AAC. Перемотка работает везде (браузер просто просит
нужный кусок), iPhone играет HLS сам, остальным браузерам помогает hls.js.
Готовые куски лежат в RAM-кэше, следующий кусок готовится заранее."""
from __future__ import annotations

import asyncio
import logging
import math
import re
import subprocess
import sys

log = logging.getLogger("photocloud.transcode")

SEG = 4.0                          # длина куска, с
# качество: «экономия» — под медленный канал, «обычное» — без заметной потери
PROFILES = {
    "eco": {"h": 720, "crf": "26", "maxrate": "1800k", "bufsize": "3600k", "ab": "96k"},
    "hq": {"h": 1080, "crf": "21", "maxrate": "8M", "bufsize": "16M", "ab": "160k"},
}
_DUR_RE = re.compile(rb"Duration:\s*(\d+):(\d{2}):(\d{2}(?:\.\d+)?)")
_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def has_x264(ffmpeg: str) -> bool:
    try:
        r = subprocess.run([ffmpeg, "-hide_banner", "-encoders"], capture_output=True, timeout=20,
                           creationflags=_FLAGS)
        return b"libx264" in r.stdout
    except Exception:  # noqa: BLE001
        return False


def probe_duration(ffmpeg: str, src: str, protocols: str, demuxer: str) -> float | None:
    """Длительность из вывода `ffmpeg -i` (ffprobe в pip-сборке нет)."""
    r = subprocess.run([ffmpeg, "-nostdin", "-hide_banner", "-protocol_whitelist", protocols,
                        "-f", demuxer, "-i", src], capture_output=True, timeout=30, creationflags=_FLAGS)
    m = _DUR_RE.search(r.stderr)
    if not m:
        return None
    d = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))
    return d if 0 < d < 24 * 3600 else None


def playlist(duration: float, seg_url) -> str:
    n = max(1, math.ceil(duration / SEG - 1e-6))
    lines = ["#EXTM3U", "#EXT-X-VERSION:3", f"#EXT-X-TARGETDURATION:{math.ceil(SEG)}",
             "#EXT-X-MEDIA-SEQUENCE:0", "#EXT-X-PLAYLIST-TYPE:VOD"]
    for i in range(n):
        lines.append(f"#EXTINF:{min(SEG, duration - i * SEG):.3f},")
        lines.append(seg_url(i))
    lines.append("#EXT-X-ENDLIST")
    return "\n".join(lines) + "\n"


def segment(ffmpeg: str, src: str, protocols: str, demuxer: str, index: int, duration: float,
            profile: str) -> bytes:
    p = PROFILES[profile]
    start = index * SEG
    length = min(SEG, duration - start)
    if length <= 0:
        raise ValueError("segment out of range")
    cmd = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
           "-protocol_whitelist", protocols, "-f", demuxer,
           "-ss", f"{start:.3f}", "-i", src, "-t", f"{length:.3f}",
           "-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn",
           # не больше p["h"] по короткой стороне (вертикальные ролики тоже), чётные размеры, 8 бит
           "-vf", f"scale='if(gt(iw,ih),-2,min({p['h']},iw))':'if(gt(iw,ih),min({p['h']},ih),-2)',format=yuv420p",
           "-c:v", "libx264", "-preset", "veryfast", "-crf", p["crf"],
           "-maxrate", p["maxrate"], "-bufsize", p["bufsize"],
           "-profile:v", "high", "-level", "4.1", "-g", "48",
           "-force_key_frames", "expr:eq(n,0)",              # каждый кусок начинается с ключевого кадра
           "-c:a", "aac", "-ac", "2", "-b:a", p["ab"], "-ar", "48000",
           # метки времени — как в полном ролике, чтобы куски шли встык
           "-output_ts_offset", f"{start:.3f}", "-muxdelay", "0", "-muxpreload", "0",
           "-f", "mpegts", "pipe:1"]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, creationflags=_FLAGS)
    if r.returncode != 0 or len(r.stdout) < 188:
        err = r.stderr[-300:].decode("utf-8", "replace").replace("\r", "").strip().replace("\n", " | ")
        log.warning("перекодирование куска %d не удалось: %s", index, err or r.returncode)
        raise ValueError("transcode failed")
    return r.stdout


class Transcoder:
    """Куски в RAM (LRU), не больше `slots` ffmpeg одновременно, предзагрузка следующего куска."""

    def __init__(self, cache, slots: int = 1):
        self.cache = cache
        self.sem = asyncio.Semaphore(slots)
        self.durations: dict[str, float | None] = {}
        self.inflight: dict[tuple, asyncio.Task] = {}

    async def get(self, key: tuple, produce) -> bytes:
        data = self.cache.get(key)
        if data is not None:
            return data
        task = self.inflight.get(key)
        if task is None:
            async def run():
                async with self.sem:
                    hit = self.cache.get(key)
                    if hit is not None:
                        return hit
                    out = await asyncio.to_thread(produce)
                    self.cache.put(key, out)
                    return out
            task = asyncio.create_task(run())
            self.inflight[key] = task
            task.add_done_callback(lambda _t, k=key: self.inflight.pop(k, None))
        return await asyncio.shield(task)

    def prefetch(self, key: tuple, produce) -> None:
        if self.cache.get(key) is None and key not in self.inflight:
            t = asyncio.ensure_future(self.get(key, produce))
            t.add_done_callback(lambda f: f.cancelled() or f.exception())
