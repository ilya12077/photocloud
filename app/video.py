"""Кадр из видео для эскиза — через ffmpeg (бинарник из pip-пакета imageio-ffmpeg,
или путь из FFMPEG). Защита: демуксер задаётся явно по расширению и разрешены
только нужные протоколы — иначе файл, замаскированный под .mp4 (например,
HLS-плейлист), мог бы заставить ffmpeg прочитать чужие файлы или URL."""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import threading

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


def _clean_err(b: bytes, limit: int = 700) -> str:
    """Начало ошибки ffmpeg — самое важное (там причина), хвост — следствия."""
    t = b.decode("utf-8", "replace").replace("\r", "").strip()
    lines = [ln for ln in t.splitlines() if ln.strip()]
    t = " | ".join(lines)
    return (t[:limit] + " …") if len(t) > limit else (t or "—")


def describe(ffmpeg: str, src: str, protocols: str, demuxer: str) -> str:
    """Какие потоки внутри файла (кодек, размер, пиксели) — для диагностики в логе."""
    try:
        r = subprocess.run([ffmpeg, "-nostdin", "-hide_banner", "-protocol_whitelist", protocols,
                            "-f", demuxer, "-i", src], capture_output=True, timeout=30,
                           creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
        out = r.stderr.decode("utf-8", "replace")
        keep = [ln.strip() for ln in out.splitlines() if "Stream #" in ln or "Duration:" in ln
                or "displaymatrix" in ln.lower() or "rotation" in ln.lower()]
        return " | ".join(keep)[:700] or "—"
    except Exception as e:  # noqa: BLE001
        return f"не удалось описать ({type(e).__name__})"


# --- «битые» цветовые метки. Некоторые телефоны пишут в H.264/HEVC цветовую матрицу
# со значением «reserved». ffmpeg 7.1 такие кадры отвергает («Invalid color space»).
# Лечим без перекодирования исходника: битстрим-фильтр на входе переписывает метку
# на обычную smpte170m (как и записано у них в transfer). Делается только для таких файлов.
_colorfix: dict[str, list[str]] = {}
_BAD_COLOR = (b"Invalid color space", b"Invalid color primaries", b"Invalid color trc")


def colorfix_args(ffmpeg: str, src: str, protocols: str, demuxer: str) -> list[str]:
    if src in _colorfix:
        return _colorfix[src]
    info = describe(ffmpeg, src, protocols, demuxer)
    bsf = "hevc_metadata" if "Video: hevc" in info else "h264_metadata" if "Video: h264" in info else ""
    args = ["-bsf:v", f"{bsf}=matrix_coefficients=6:colour_primaries=6:transfer_characteristics=6"] if bsf else []
    if len(_colorfix) > 2000:
        _colorfix.clear()
    _colorfix[src] = args
    return args


# ---- остановка ffmpeg, когда результат больше не нужен (вышли из видео)
# Поток, запускающий ffmpeg, может пометить себя тегом (обычно id файла); stop(tag)
# убивает все процессы с этим тегом, и запрос заканчивается исключением Stopped.
class Stopped(Exception):
    """ffmpeg остановлен: результат больше никому не нужен."""


_tls = threading.local()
_procs: dict[str, set] = {}
_stopped: dict[str, float] = {}
_procs_mu = threading.Lock()


def tagged(tag: str, fn):
    """Выполнить fn, пометив все запущенные им ffmpeg тегом."""
    _tls.tag = tag
    try:
        return fn()
    finally:
        _tls.tag = None


def stop(tag: str) -> int:
    with _procs_mu:
        procs = list(_procs.get(tag, ()))
        if procs:
            _stopped[tag] = len(procs)
    for pr in procs:
        try:
            pr.kill()
        except OSError:
            pass
    return len(procs)


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    tag = getattr(_tls, "tag", None)
    pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    if tag:
        with _procs_mu:
            _procs.setdefault(tag, set()).add(pr)
    try:
        out, err = pr.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        pr.kill()
        pr.communicate()
        raise
    finally:
        if tag:
            with _procs_mu:
                ps = _procs.get(tag)
                if ps is not None:
                    ps.discard(pr)
                    if not ps:
                        del _procs[tag]
    if tag and pr.returncode != 0:
        with _procs_mu:
            if _stopped.pop(tag, None) is not None:
                raise Stopped()
    return subprocess.CompletedProcess(cmd, pr.returncode, out, err)


def run_ff(cmd: list[str], src: str, protocols: str, demuxer: str, timeout: int):
    """Запуск ffmpeg; при «Invalid color space» — один повтор с исправлением метки цвета."""
    ffmpeg = cmd[0]
    pre = _colorfix.get(src)
    if pre:
        i = cmd.index("-i")
        cmd = cmd[:i] + pre + cmd[i:]
    r = _run(cmd, timeout)
    if pre is None and r.returncode != 0 and any(m in r.stderr for m in _BAD_COLOR):
        fix = colorfix_args(ffmpeg, src, protocols, demuxer)
        if fix:
            i = cmd.index("-i")
            r = _run(cmd[:i] + fix + cmd[i:], timeout)
    return r


def _signed(code: int) -> int:
    """Windows отдаёт код возврата беззнаковым: 4294967274 == -22."""
    return code - (1 << 32) if code > 0x7FFFFFFF else code


def _source_unavailable(err: bytes) -> bool:
    e = err or b""
    return any(x in e for x in (b"Server returned 5", b"Connection refused", b"Connection reset",
                                b"Connection timed out"))


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
            r = run_ff(cmd, src, protocols, fmt, 25)
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
            if r.returncode != 0 and _source_unavailable(r.stderr):
                # исходник не отдался (ПК выключен/не отвечает) — файл тут ни при чём:
                # не перебираем способы и не помечаем видео как «не декодируется»
                raise ConnectionError("video source unavailable")
            if r.returncode != 0:
                break                       # ошибка формата вывода — пробуем следующий вариант вывода
            # код 0, но кадра нет — пробуем следующий способ
    code = _signed(last.returncode)
    log.warning("ffmpeg не смог взять кадр из %s (код %s): %s || файл: %s", ext, code,
                _clean_err(last.stderr), describe(ffmpeg, src, protocols, fmt))
    raise ValueError("no frame")
