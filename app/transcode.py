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
# сжатое видео для просмотра; без сжатия — исходный файл (галочка «Оригинал»)
PROFILES = {
    # 720p ~1 Мбит/с: идёт без пауз даже на 2 Мбит/с мобильного интернета
    "eco": {"h": 720, "crf": "28", "maxrate": "1000k", "bufsize": "2000k", "ab": "64k"},
}
_FPS_RE = re.compile(rb"Video:.*?(\d+(?:\.\d+)?) fps")
fps_of: dict[str, float] = {}     # src -> частота кадров (из того же вызова ffmpeg -i)
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
    f = _FPS_RE.search(r.stderr)
    if f:
        if len(fps_of) > 5000:
            fps_of.clear()
        fps_of[src] = float(f.group(1))
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
           # 60 к/с -> 30 (для просмотра хватает, а кодирование вдвое легче; кадры отбрасываются
           # до уменьшения, так что и масштабировать вдвое меньше). Не больше p["h"] по короткой
           # стороне (вертикальные тоже), чётные размеры, 8 бит.
           "-vf", ("fps=30," if fps_of.get(src, 0) > 32 else "") + f"scale='if(gt(iw,ih),-2,min({p['h']},iw))':'if(gt(iw,ih),min({p['h']},ih),-2)':flags=bilinear,format=yuv420p",
           "-c:v", "libx264", "-preset", "superfast", "-crf", p["crf"],
           "-maxrate", p["maxrate"], "-bufsize", p["bufsize"],
           "-profile:v", "high", "-level", "4.1", "-g", "48",
           "-force_key_frames", "expr:eq(n,0)",              # каждый кусок начинается с ключевого кадра
           "-c:a", "aac", "-ac", "2", "-b:a", p["ab"], "-ar", "48000",
           # метки времени — как в полном ролике, чтобы куски шли встык
           "-output_ts_offset", f"{start:.3f}", "-muxdelay", "0", "-muxpreload", "0",
           "-f", "mpegts", "pipe:1"]
    from .video import run_ff
    r = run_ff(cmd, src, protocols, demuxer, 120)
    if r.returncode != 0 or len(r.stdout) < 188:
        from .video import _clean_err
        log.warning("перекодирование куска %d не удалось: %s", index, _clean_err(r.stderr))
        from .video import _source_unavailable
        if _source_unavailable(r.stderr):
            raise ConnectionError("video source unavailable")
        raise ValueError("transcode failed")
    return r.stdout


LIVE_PROFILES = {
    # короткая сторона, crf, потолок битрейта, звук; eco — превью-ролик, hq — после него
    "hq":  {"h": 1080, "crf": 23, "max": "5000k", "buf": "10000k", "a": "128k"},
    "eco": {"h": 480, "crf": 29, "max": "600k",  "buf": "1200k", "a": "48k"},
}


def live_clip(ffmpeg: str, src: str, protocols: str, demuxer: str, profile: str = "hq") -> bytes:
    """Ролик живого фото -> MP4 (H.264 + AAC, ≤ 10 с, ≤ 30 к/с).
    Фрагментированный MP4: его можно писать в трубу, а браузеры играют его как обычный."""
    p = LIVE_PROFILES[profile]
    h = p["h"]
    cmd = [ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
           "-protocol_whitelist", protocols, "-f", demuxer, "-i", src, "-t", "10",
           "-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn",
           "-vf", f"scale='if(gt(iw,ih),-2,min({h},iw))':'if(gt(iw,ih),min({h},ih),-2)':flags=bilinear,format=yuv420p",
           "-fpsmax", "30",
           "-c:v", "libx264", "-preset", "superfast", "-crf", str(p["crf"]),
           "-maxrate", p["max"], "-bufsize", p["buf"], "-profile:v", "high", "-level", "4.1",
           "-c:a", "aac", "-b:a", p["a"], "-ac", "2",
           "-movflags", "frag_keyframe+empty_moov+default_base_moof", "-f", "mp4", "pipe:1"]
    from .video import run_ff
    r = run_ff(cmd, src, protocols, demuxer, 120)
    if r.returncode != 0 or len(r.stdout) < 1000:
        from .video import _clean_err
        log.warning("ролик живого фото не перекодирован: %s", _clean_err(r.stderr))
        from .video import _source_unavailable
        if _source_unavailable(r.stderr):
            raise ConnectionError("video source unavailable")
        raise ValueError("live clip failed")
    return r.stdout


class Transcoder:
    """Куски в RAM (LRU), не больше `slots` ffmpeg одновременно, предзагрузка следующего куска."""

    def __init__(self, cache, slots: int = 1):
        self.cache = cache
        self.sem = asyncio.Semaphore(slots)
        self.durations: dict[str, float | None] = {}
        self.inflight: dict[tuple, asyncio.Task] = {}

    async def get(self, key: tuple, produce) -> bytes:
        """key[0] — id файла: по нему stop() останавливает всю работу над этим файлом."""
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
                    from .video import tagged
                    out = await asyncio.to_thread(tagged, key[0], produce)
                    self.cache.put(key, out)
                    return out
            task = asyncio.create_task(run())
            self.inflight[key] = task
            task.add_done_callback(lambda _t, k=key: self.inflight.pop(k, None))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            me = asyncio.current_task()
            if task.cancelled() and not (me and me.cancelling()):
                from .video import Stopped
                raise Stopped() from None       # работу остановили через stop(), а не нас
            raise

    def stop(self, pid: str) -> int:
        """Вышли из видео / живого фото: снимаем из очереди и убиваем ffmpeg этого файла,
        чтобы процессор и чтение с ПК сразу достались эскизам."""
        n = 0
        for key, task in list(self.inflight.items()):
            if key[0] == pid:
                task.cancel()
                n += 1
        from .video import stop
        return n + stop(pid)

    def prefetch(self, key: tuple, produce) -> None:
        if self.cache.get(key) is None and key not in self.inflight:
            t = asyncio.ensure_future(self.get(key, produce))
            t.add_done_callback(lambda f: f.cancelled() or f.exception())
