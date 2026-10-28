"""Photocloud: веб-галерея фотографий с домашнего ПК.

Запуск: uvicorn app.main:app --host 0.0.0.0 --port 8099 --no-proxy-headers --no-server-header
"""
from __future__ import annotations

import asyncio
import hashlib
import contextlib
import ipaddress
import json
import logging
import mimetypes
import re
import secrets
import random
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.staticfiles import StaticFiles
from PIL import Image, UnidentifiedImageError

from . import config
from . import geo
from . import logs
from .db import DB
from .backup import TokenStore
from .auth import USER_RE, LoginLimiter, Session, SessionStore, UserError, UserStore
from .ha import HomeAssistant, clean
from .images import LRUBytes, TooLarge, decode, embedded_heic, embedded_jpeg, finish, read_head, read_limited, render
from . import transcode, video
from .google_auth import GoogleAuth, GoogleError
from .library import Library, folder_ok
from .sched import PRIO_GRID, PRIO_PREFETCH, PRIO_QUICK, PRIO_VIEWER, Gone, Scheduler
from .storage import is_missing, make_storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("photocloud")

S = config.load()
logs.install()
# служебные библиотеки пишут каждый шаг SMB/HTTP — в журнале нужны только их предупреждения
for _name in ("smbprotocol", "smbclient", "httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)
audit = logs.Audit(S.data_dir / "audit.log")
STARTED = time.time()
STATIC = Path(__file__).parent / "static"
COOKIE = "__Host-pc_sess" if S.cookie_secure else "pc_sess"
OAUTH_COOKIE = "__Host-pc_oauth" if S.cookie_secure else "pc_oauth"
ID_RE = r"^[A-Za-z0-9_-]{8}$"

storage = make_storage(S)
db = DB(S.data_dir / "photocloud.db")
library = Library(S.tz, S.meta_threads, db)
FFMPEG = video.find_ffmpeg(S.ffmpeg)
TRANSCODE = bool(S.transcode and FFMPEG and transcode.has_x264(FFMPEG))
transcoder = transcode.Transcoder(LRUBytes(S.transcode_cache_mb * 1024 * 1024), S.transcode_slots)
google = GoogleAuth(S.google_client_id, S.google_client_secret, S.public_url) if S.google_client_id else None
# одноразовый секрет для внутреннего канала ffmpeg -> приложение (только loopback)
INTERNAL_TOKEN = secrets.token_urlsafe(32)
ha = HomeAssistant(S)
try:
    users = UserStore(S.data_dir / "users.json")
except (OSError, ValueError) as e:
    raise SystemExit(f"Не читается {S.data_dir / 'users.json'}: {e}") from None
# пока нет ни одного пользователя — первичная настройка по одноразовому токену из консоли
SETUP_TOKEN = secrets.token_urlsafe(24) if users.empty() else ""
sessions = SessionStore(S.session_idle_hours * 3600, S.session_max_hours * 3600, db)
tokens = TokenStore(db)                       # клиенты бэкапа
library.hash_wanted = tokens.any              # хеши файлов считаем, только если бэкап есть
limiter = LoginLimiter()
thumb_cache = LRUBytes(S.thumb_cache_mb * 1024 * 1024)
preview_cache = LRUBytes(S.preview_cache_mb * 1024 * 1024)
sched = Scheduler(S.workers)
# кадры из видео — отдельная очередь: они в 10 раз дольше фото и не должны держать ленту
sched_video = Scheduler(2)
login_sem = asyncio.Semaphore(2)              # argon2 ест ~64 МБ RAM на проверку
inflight: dict[tuple, asyncio.Future] = {}
# файлы, которые не удалось декодировать: не мучаем ffmpeg/Pillow повторно 10 минут
failed: dict[tuple, float] = {}
FAILED_TTL = 600
known_ips: dict[str, set] = {}
_bg_tasks: set = set()

CONTENT_TYPES = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp",
    ".gif": "image/gif", ".bmp": "image/bmp", ".tif": "image/tiff", ".tiff": "image/tiff",
    ".heic": "image/heic", ".heif": "image/heif",
    # .mov отдаём как mp4: Chrome/Edge тогда тоже пытаются его играть (кодек тот же H.264/HEVC)
    ".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/mp4", ".3gp": "video/3gpp", ".webm": "video/webm",
    ".mts": "video/mp2t", ".m2ts": "video/mp2t", ".avi": "video/x-msvideo",
}
RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


def bg(coro) -> None:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)


# ---------------------------------------------------------------- сеть/прокси

def _in(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def client_ip(scope_client, headers) -> str:
    peer = scope_client[0] if scope_client else ""
    if not _in(peer, S.trusted_proxies):
        return peer
    xri = headers.get("x-real-ip", "").strip()
    if xri:
        try:
            return str(ipaddress.ip_address(xri))
        except ValueError:
            pass
    # самый правый адрес XFF, не являющийся нашим прокси
    for part in reversed([p.strip() for p in headers.get("x-forwarded-for", "").split(",") if p.strip()]):
        try:
            ipaddress.ip_address(part)
        except ValueError:
            break
        if not _in(part, S.trusted_proxies):
            return part
    return peer


SEC_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    (b"content-security-policy",
     b"default-src 'none'; script-src 'self'; style-src 'self'; "
     b"img-src 'self' blob: data: https://tile.openstreetmap.org; "
     b"media-src 'self' blob:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
]
if S.cookie_secure:
    SEC_HEADERS.append((b"strict-transport-security", b"max-age=31536000"))


class Guard:
    """ASGI-обёртка: доступ только через доверенный прокси + заголовки безопасности."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        peer = scope["client"][0] if scope.get("client") else ""
        if scope["path"].startswith("/internal/"):
            # внутренний канал для ffmpeg: только с loopback и без заголовков прокси
            hdrs = {k.lower() for k, _ in scope.get("headers", [])}
            if peer not in ("127.0.0.1", "::1") or b"x-forwarded-for" in hdrs or b"x-real-ip" in hdrs:
                await send({"type": "http.response.start", "status": 404, "headers": SEC_HEADERS})
                await send({"type": "http.response.body", "body": b""})
                return
            return await self.app(scope, receive, send)
        if S.require_proxy:
            peer = scope["client"][0] if scope.get("client") else ""
            if not _in(peer, S.trusted_proxies):
                await send({"type": "http.response.start", "status": 403,
                            "headers": [(b"content-type", b"text/plain")] + SEC_HEADERS})
                await send({"type": "http.response.body", "body": b"forbidden"})
                return

        async def _send(msg):
            if msg["type"] == "http.response.start":
                names = {k.lower() for k, _ in msg.get("headers", [])}
                msg["headers"] = list(msg.get("headers", [])) + [h for h in SEC_HEADERS if h[0] not in names]
            await send(msg)

        await self.app(scope, receive, _send)


@contextlib.asynccontextmanager
async def lifespan(_app):
    global loop
    loop = asyncio.get_running_loop()
    log.info("Photocloud %s", config.app_version())
    bg(_pc_watch())
    if FFMPEG:
        log.info("ffmpeg: %s · перекодирование видео: %s", FFMPEG, "да" if TRANSCODE else "нет")
    else:
        log.warning("ffmpeg не найден — у видео не будет эскизов (pip install imageio-ffmpeg)")
    if SETUP_TOKEN:
        # ссылка — на внешний адрес сайта, если он известен (через NPM), иначе на localhost
        base = S.public_url or (sorted(S.allowed_origins)[0] if S.allowed_origins else "") \
            or f"http://{'localhost' if S.bind in ('0.0.0.0', '127.0.0.1') else S.bind}:{S.port}"
        log.warning("Пользователей нет. Создай администратора по ссылке (одноразовая, только в этой консоли):\n"
                    "    %s/admin#setup=%s", base, SETUP_TOKEN)
    if S.storage == "local":
        log.warning("ТЕСТОВЫЙ РЕЖИМ: фото читаются из локальной папки %s", S.local_root)
    if not S.cookie_secure:
        log.warning("COOKIE_SECURE=false — допустимо только для теста по http://localhost")
    yield
    await ha.close()
    await geocoder.close()
    if google:
        await google.close()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def ip_of(request: Request) -> str:
    return client_ip(request.scope.get("client"), request.headers)


# ---------------------------------------------------------------- auth deps

async def require_user(request: Request) -> Session:
    token = request.cookies.get(COOKIE)
    s = sessions.get(token)
    if s is None:
        raise HTTPException(401, "auth")
    role = users.role(s.user)
    if role is None:                 # пользователя удалили — сессия больше не действует
        sessions.delete(token)
        raise HTTPException(401, "auth")
    s.role = role  # type: ignore[attr-defined]
    s.sid = sessions.sid(token)  # type: ignore[attr-defined]
    return s


def user_folders(s: Session):
    """Папки, доступные пользователю: None — все (админ всегда видит всё)."""
    if getattr(s, "role", None) == "admin":
        return None
    return users.folders(s.user)


def visible(s: Session, p) -> bool:
    """Файл p в папках, доступных пользователю. Все запросы по id проходят через это:
    чужой id отвечает 404 — так же, как несуществующий."""
    return p is not None and folder_ok(p.rel, user_folders(s))


async def require_admin(s: Session = Depends(require_user)) -> Session:
    if s.role != "admin":  # type: ignore[attr-defined]
        raise HTTPException(403, "admin")
    return s


async def require_csrf(request: Request) -> None:
    """Для изменяющих запросов: кастомный заголовок (кросс-сайт форма его не поставит,
    а CORS мы не разрешаем) + проверка Origin."""
    if request.headers.get("x-requested-with") != "photocloud":
        raise HTTPException(403, "csrf")
    origin = request.headers.get("origin")
    if origin:
        if S.allowed_origins:
            if origin.rstrip("/") not in S.allowed_origins:
                raise HTTPException(403, "origin")
        else:
            host = request.headers.get("host", "")
            if re.sub(r"^https?://", "", origin).rstrip("/") != host:
                raise HTTPException(403, "origin")


async def read_json(request: Request, limit: int = 4096) -> dict:
    cl = request.headers.get("content-length")
    if cl and (not cl.isdigit() or int(cl) > limit):
        raise HTTPException(413)
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise HTTPException(413)
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(400) from None
    if not isinstance(data, dict):
        raise HTTPException(400)
    return data


def no_store(resp: Response) -> Response:
    resp.headers["cache-control"] = "no-store"
    return resp


# ---------------------------------------------------------------- страницы

def _versioned_html(name: str) -> bytes:
    """HTML с версиями у ссылок на статику (?v=хэш файла). Тогда браузер хранит
    js/css «навсегда» и не тратит запросы на проверку — а после обновления файла
    меняется хэш, и новая версия скачивается сама."""
    html = (STATIC / name).read_text(encoding="utf-8")

    def ver(m):
        f = STATIC / m.group(2)
        try:
            h = hashlib.blake2b(f.read_bytes(), digest_size=5).hexdigest()
        except OSError:
            return m.group(0)
        return f'{m.group(1)}/static/{m.group(2)}?v={h}"'
    return re.sub(r'((?:src|href)=")/static/([A-Za-z0-9_./-]+\.(?:js|css))"', ver, html).encode()


PAGES = {"/": _versioned_html("index.html"), "/admin": _versioned_html("admin.html")}


@app.get("/", include_in_schema=False)
async def index_page():
    return Response(PAGES["/"], media_type="text/html; charset=utf-8", headers={"cache-control": "no-cache"})


@app.get("/admin", include_in_schema=False)
async def admin_page():
    return Response(PAGES["/admin"], media_type="text/html; charset=utf-8", headers={"cache-control": "no-cache"})


class _Static(StaticFiles):
    async def get_response(self, path, scope):
        r = await super().get_response(path, scope)
        q = scope.get("query_string", b"")
        # с версией в адресе — кэш на год; без неё (hls.js грузится по прямому адресу) — с проверкой
        r.headers["cache-control"] = "public, max-age=31536000, immutable" if q.startswith(b"v=") else "no-cache"
        return r


app.mount("/static", _Static(directory=STATIC), name="static")


# ---------------------------------------------------------------- вход/выход

@app.post("/api/login", dependencies=[Depends(require_csrf)])
async def login(request: Request):
    ip = ip_of(request)
    wait = limiter.blocked(ip)
    if wait:
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429,
                                     headers={"retry-after": str(wait)}))
    data = await read_json(request)
    u, p = data.get("u"), data.get("p")
    if not isinstance(u, str) or not isinstance(p, str) or not (0 < len(u) <= 64) or not (0 < len(p) <= 256):
        raise HTTPException(400)
    async with login_sem:
        role = await run_in_threadpool(users.verify, u, p)
    if not role:
        locked = limiter.fail(ip)
        audit("login_failed", u, ip)
        if locked:
            audit("lockout", "", ip, "5 неудачных входов, блок 15 мин")
        bg(ha.notify("login_failed", f"Неудачный вход: «{clean(u, 32)}» с {clean(ip)}", dedupe_s=300, key=ip))
        if locked:
            bg(ha.notify("lockout", f"IP {clean(ip)} заблокирован на 15 мин после 5 неудачных входов"))
        await asyncio.sleep(0.3)
        return no_store(JSONResponse({"error": "bad"}, 401))
    limiter.success(ip)
    audit("login", u, ip)
    return no_store(start_session(request, JSONResponse({"user": u, "role": role}), u, ip, "паролю"))


def start_session(request: Request, resp: Response, u: str, ip: str, how: str) -> Response:
    sessions.delete(request.cookies.get(COOKIE))   # против фиксации сессии
    token = sessions.create(u, ip)
    seen = known_ips.setdefault(u, set())
    if ip not in seen:
        seen.add(ip)
        bg(ha.notify("login_new_ip", f"Вход {u} с нового адреса {clean(ip)} (по {how})", dedupe_s=0))
    bg(ha.notify("login", f"Вход {u} с {clean(ip)} (по {how})", dedupe_s=0))
    resp.set_cookie(COOKIE, token, max_age=S.session_max_hours * 3600, path="/",
                    secure=S.cookie_secure, httponly=True, samesite="strict")
    return resp


@app.get("/api/auth/providers")
async def auth_providers():
    return no_store(JSONResponse({"google": google is not None}))


@app.get("/auth/google")
async def google_start(request: Request):
    if google is None:
        raise HTTPException(404)
    if limiter.blocked(ip_of(request)):
        return RedirectResponse("/#err=locked", 303)
    try:
        url, state = google.start()
    except GoogleError:
        raise HTTPException(503) from None
    resp = RedirectResponse(url, 303)
    # Lax: cookie должна вернуться при переходе со страницы Google обратно к нам
    resp.set_cookie(OAUTH_COOKIE, state, max_age=600, path="/", secure=S.cookie_secure,
                    httponly=True, samesite="lax")
    return no_store(resp)


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    if google is None:
        raise HTTPException(404)
    ip = ip_of(request)
    q = request.query_params

    def fail(code: str) -> Response:
        r = RedirectResponse(f"/#err={code}", 303)
        r.delete_cookie(OAUTH_COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="lax")
        return no_store(r)

    if limiter.blocked(ip):
        return fail("locked")
    if q.get("error"):
        return fail("google-cancel")
    try:
        email = await google.finish(q.get("state", ""), request.cookies.get(OAUTH_COOKIE, ""), q.get("code", ""))
    except GoogleError as e:
        log.info("Google-вход отклонён: %s", e)
        audit("login_google_failed", "", ip, str(e))
        return fail("google")
    hit = users.by_google(email)
    if hit is None:
        limiter.fail(ip)
        audit("login_google_denied", "", ip, email)
        bg(ha.notify("login_failed", f"Вход через Google с непривязанного аккаунта {clean(email)} с {clean(ip)}",
                     dedupe_s=300, key=ip))
        return fail("google-denied")
    u, _role = hit
    limiter.success(ip)
    audit("login_google", u, ip, email)
    resp = start_session(request, RedirectResponse("/", 303), u, ip, "Google")
    resp.delete_cookie(OAUTH_COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="lax")
    return no_store(resp)


@app.post("/api/logout", dependencies=[Depends(require_csrf)])
async def logout(request: Request):
    s = sessions.get(request.cookies.get(COOKIE))
    if s:
        audit("logout", s.user, ip_of(request))
    sessions.delete(request.cookies.get(COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="strict")
    return no_store(resp)


@app.get("/api/me")
async def me(s: Session = Depends(require_user)):
    return no_store(JSONResponse({"user": s.user, "role": s.role, "name": S.public_name,  # type: ignore[attr-defined]
                                  "sizes": {"s": S.thumb_small_size, "t": S.thumb_size, "m": S.thumb_large_size},
                                  "video": bool(FFMPEG), "transcode": TRANSCODE,
                                  "can_wake": users.can_wake(s.user)}))


# ---------------------------------------------------------------- ПК и индекс

class PC:
    up = False
    checked = 0.0
    wake_at = 0.0
    wake_notified = False
    revived = False      # ПК снова в сети — перечитать папки и дочитать даты
    checked_once = False
    _lock = asyncio.Lock()

    @classmethod
    async def is_up(cls) -> bool:
        async with cls._lock:
            if time.time() - cls.checked > 3:
                was = cls.up
                cls.up = await _probe()
                cls.checked = time.time()
                if cls.up and not was and cls.checked_once:
                    cls.revived = True
                cls.checked_once = True
                if was and not cls.up and hasattr(storage, "reset"):
                    # в отдельном потоке и без ожидания: статус и кнопка включения не должны зависеть от сброса
                    threading.Thread(target=storage.reset, name="smb-reset", daemon=True).start()
            return cls.up

    @classmethod
    def suspect(cls) -> None:
        """Запрос к ПК упал по таймауту/обрыву — следующая проверка пойдёт сразу, а не через 3 с."""
        cls.checked = 0.0


# ---------------------------------------------------------------- потоки для работы с ПК
# Всё, что читает файлы с ПК, идёт в отдельный пул. Если ПК пропал посреди запросов и
# потоки повисли, это не задевает вход, страницы и админку (у них свой пул), а сам
# HTTP-запрос не ждёт дольше тайм-аута. Если же пул повис целиком и не оживает,
# процесс завершается — Docker (restart: unless-stopped) поднимает его заново.
SMB_THREADS = 24
STALL_EXIT = 150          # с: все потоки заняты и ни один не завершился
_smb_pool = ThreadPoolExecutor(SMB_THREADS, thread_name_prefix="pc")


class SmbPool:
    busy = 0
    last_done = time.monotonic()
    mu = threading.Lock()


def _tracked(fn, *a):
    with SmbPool.mu:
        SmbPool.busy += 1
    try:
        return fn(*a)
    finally:
        with SmbPool.mu:
            SmbPool.busy -= 1
            SmbPool.last_done = time.monotonic()


async def on_pc(fn, *a, timeout: float = 60):
    """Выполнить fn в пуле «ПК» не дольше timeout. Тайм-аут = ПК не отвечает."""
    fut = loop.run_in_executor(_smb_pool, _tracked, fn, *a)
    try:
        return await asyncio.wait_for(fut, timeout)
    except asyncio.TimeoutError:
        PC.suspect()
        log.warning("запрос к компьютеру не завершился за %d с", timeout)
        if hasattr(storage, "reset"):
            threading.Thread(target=storage.reset, name="smb-reset", daemon=True).start()
        raise ConnectionError("PC timeout") from None


def _stall_guard() -> None:
    import faulthandler
    import sys
    while True:
        time.sleep(10)
        with SmbPool.mu:
            busy, idle_for = SmbPool.busy, time.monotonic() - SmbPool.last_done
        if busy >= SMB_THREADS and idle_for > STALL_EXIT:
            log.error("все %d потоков чтения с компьютера висят %d с — перезапускаю сервер. "
                      "Стеки потоков ниже (пришли их разработчику):", busy, idle_for)
            for h in logging.getLogger().handlers:
                with contextlib.suppress(Exception):
                    h.flush()
            faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
            sys.stderr.flush()
            os._exit(70)


threading.Thread(target=_stall_guard, name="stall-guard", daemon=True).start()


async def _probe() -> bool:
    """Отвечает ли ПК. Для SMB — прямо в цикле событий, без пула потоков: если потоки
    заняты зависшими запросами к выключенному ПК, проверка всё равно проходит,
    и статус с кнопкой включения продолжают работать."""
    host = getattr(storage, "host", None)
    if not host:
        return await run_in_threadpool(storage.reachable)
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, storage.port), 1.5)
    except (OSError, asyncio.TimeoutError):
        return False
    w.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(w.wait_closed(), 1)
    return True


loop: asyncio.AbstractEventLoop


def _index_error(err: str) -> None:
    loop.call_soon_threadsafe(bg, ha.notify("index_error", f"Ошибка индексации фото: {clean(err)}", dedupe_s=3600))



def pc_state(up: bool) -> str:
    """up / waking (ждём после команды включения) / down — одинаково для сайта и админки."""
    if up:
        return "up"
    if PC.wake_at and time.time() - PC.wake_at < S.wake_timeout:
        return "waking"
    return "down"


async def _pc_watch() -> None:
    """Фоновый наблюдатель — работает, даже если сайт никто не открыл:
    обновляет список файлов (сразу после запуска, потом раз в INDEX_TTL и когда ПК
    снова в сети), завершает ожидание включения и шлёт «не проснулся»."""
    await asyncio.sleep(1)
    while True:
        try:
            up = await PC.is_up()
            if up:
                PC.wake_at = 0
                if PC.revived or library.stale(S.index_ttl):
                    if library.start_build(storage, _index_error):
                        PC.revived = False
            elif PC.wake_at and pc_state(False) == "down" and not PC.wake_notified:
                PC.wake_notified = True
                bg(ha.notify("wake_timeout", "Компьютер не проснулся после WoL"))
        except Exception:  # noqa: BLE001
            log.exception("фоновая проверка компьютера")
        try:
            _backup_stale_check()
            if PC.up:
                await run_in_threadpool(_verify_tick)
        except Exception:  # noqa: BLE001
            log.exception("проверка клиентов бэкапа")
        await asyncio.sleep(5 if PC.wake_at else 15)     # пока ждём включения — чаще


@app.get("/api/status")
async def status(s: Session = Depends(require_user)):
    pc = pc_state(await PC.is_up())
    view = await run_in_threadpool(library.view, user_folders(s))
    if pc == "up":
        PC.wake_at = 0
    return no_store(JSONResponse({
        "pc": pc,
        "wake_left": max(0, int(S.wake_timeout - (time.time() - PC.wake_at))) if pc == "waking" else 0,
        "wake_failed": pc == "down" and bool(PC.wake_at),
        "index": {"state": library.state, "count": view.count, "progress": library.progress,
                  "built_at": int(library.built_at), "v": view.version,
                  "info": [library.info_done, library.info_total, library.info_state],
                  "meta": [library.meta_done, library.meta_total]},
    }))


@app.post("/api/wake", dependencies=[Depends(require_csrf)])
async def wake(s: Session = Depends(require_user)):
    return await _wake(s.user, f"{s.user} будит компьютер")


async def _wake(user: str, message: str, detail: str = "") -> Response:
    if not users.can_wake(user):
        raise HTTPException(403, "wake not allowed")
    if await PC.is_up():
        return no_store(JSONResponse({"pc": "up"}))
    if PC.wake_at and time.time() - PC.wake_at < 30:
        return no_store(JSONResponse({"pc": "waking"}))
    if S.storage == "local":
        raise HTTPException(409, "local mode")
    ok = await ha.wake()
    if not ok:
        return no_store(JSONResponse({"error": "ha"}, 502))
    PC.wake_at, PC.wake_notified = time.time(), False
    audit("wake", user, "", detail)
    bg(ha.notify("wake", message))
    return no_store(JSONResponse({"pc": "waking"}))


@app.post("/api/reindex", dependencies=[Depends(require_csrf)])
async def reindex(_: Session = Depends(require_admin)):
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    library.start_build(storage, _index_error)
    return no_store(JSONResponse({"ok": True}))


@app.get("/api/library")
async def get_library(request: Request, s: Session = Depends(require_user)):
    v = await run_in_threadpool(library.view, user_folders(s))     # только свои папки
    etag = f'"{v.version}"'
    headers = {"etag": etag, "cache-control": "private, no-cache", "vary": "cookie, accept-encoding"}
    if v.version and request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    if "gzip" in request.headers.get("accept-encoding", ""):
        headers["content-encoding"] = "gzip"
        return Response(v.gz, media_type="application/json", headers=headers)
    return Response(v.payload, media_type="application/json", headers=headers)


# ---------------------------------------------------------------- картинки

class ClientGone(Exception):
    pass


def _video_src(p) -> tuple[str, str]:
    if hasattr(storage, "local_path"):
        return "file:" + str(storage.local_path(p.rel)), "file"
    host = "127.0.0.1" if S.bind in ("0.0.0.0", "127.0.0.1") else S.bind
    return f"http://{host}:{S.port}/internal/raw/{p.id}?k={INTERNAL_TOKEN}", "http,tcp"


def _produce(p, box: int, quality: int, tm: dict | None = None) -> bytes:
    tm = {} if tm is None else tm
    if p.video:
        if not FFMPEG:
            raise ValueError("no ffmpeg")
        src, protocols = _video_src(p)
        t = time.perf_counter()
        frame = video.frame(FFMPEG, src, protocols, p.ext, box, 90)
        tm["decode"] = (time.perf_counter() - t) * 1000        # ffmpeg: чтение + декод кадра
        return render(frame, box, quality, S.image_format, tm)
    limit = S.max_decode_mb * 1024 * 1024
    small = box <= S.thumb_size                 # для эскизов пробуем встроенный готовый эскиз
    t = time.perf_counter()
    try:
        with storage.open(p.rel) as f:
            if small and p.ext in (".jpg", ".jpeg"):
                # сначала только начало файла: по сети это в разы быстрее, чем тянуть все 4–10 МБ
                head = read_head(f)
                tm["read"] = (time.perf_counter() - t) * 1000
                t1 = time.perf_counter()
                emb = embedded_jpeg(head, box)
                if emb is not None:
                    tm["decode"] = (time.perf_counter() - t1) * 1000
                    tm["src"] = 1                # 1 = встроенный эскиз
                    return finish(emb, box, quality, S.image_format, tm, time.perf_counter())
                t = time.perf_counter()
                data = head + read_limited(f, max(0, limit - len(head)))
                if len(data) > limit:
                    raise TooLarge
            else:
                data = read_limited(f, limit)
    except TooLarge:
        raise
    except Exception as e:  # noqa: BLE001
        raise ConnectionError(type(e).__name__) from e
    tm["read"] = tm.get("read", 0) + (time.perf_counter() - t) * 1000
    if small and p.ext in (".heic", ".heif"):
        t1 = time.perf_counter()
        emb = embedded_heic(data, box)
        if emb is not None:
            tm["decode"] = (time.perf_counter() - t1) * 1000
            tm["src"] = 1
            return finish(emb, box, quality, S.image_format, tm, time.perf_counter())
    return render(data, box, quality, S.image_format, tm)


def _produce_pair(p, box_q: int, qual_q: int, tm: dict):
    """Быстрая версия для просмотрщика + байты файла для полной версии.
    Файл с ПК читается ОДИН раз. Быстрая версия декодируется сразу в малом масштабе
    (JPEG draft — в разы быстрее), полная потом декодируется из тех же байтов в фоне."""
    limit = S.max_decode_mb * 1024 * 1024
    t = time.perf_counter()
    try:
        with storage.open(p.rel) as f:
            data = read_limited(f, limit)
    except TooLarge:
        raise
    except Exception as e:  # noqa: BLE001
        raise ConnectionError(type(e).__name__) from e
    tm["read"] = (time.perf_counter() - t) * 1000
    quick = render(data, box_q, qual_q, S.image_format, tm)
    return quick, data


# Полные превью (2048) «впрок» делаются по одному и только для последнего открытого фото: если
# быстро листать (или сразу увеличивать — тогда нужен оригинал), старые заготовки
# пропускаются, а не копятся очередью на процессоре. Кому полное всё же понадобится —
# запросит, и оно сделается обычным порядком.
_companion_mu = asyncio.Semaphore(1)
_companion_seq = 0


async def _finish_companion(ckey, cfut, raw, box: int, quality: int) -> None:
    global _companion_seq
    _companion_seq += 1
    my = _companion_seq
    try:
        async with _companion_mu:
            if my != _companion_seq:
                raise ClientGone()                   # есть заготовка новее — эта уже не нужна
            data = await on_pc(render, raw, box, quality, S.image_format, None, timeout=60)
        preview_cache.put(ckey, data)
        cfut.set_result(data)
    except Exception:  # noqa: BLE001 — ждущие сделают сами
        if not cfut.done():
            cfut.set_exception(ClientGone())
    finally:
        if inflight.get(ckey) is cfut:
            del inflight[ckey]


def _fmt_class(p) -> str:
    if p.video:
        return "видео"
    return {".jpg": "jpeg", ".jpeg": "jpeg", ".heic": "heic", ".heif": "heic", ".png": "png"}.get(p.ext, "другое")


class Perf:
    """Статистика генерации эскизов для админки (последние 2000 запросов)."""
    recs: deque = deque(maxlen=2000)
    hits = 0
    misses = 0

    @classmethod
    def summary(cls) -> dict:
        def med(vals):
            vals = sorted(vals)
            return round(vals[len(vals) // 2], 1) if vals else None

        def p90(vals):
            vals = sorted(vals)
            return round(vals[min(len(vals) - 1, int(len(vals) * 0.9))], 1) if vals else None

        groups: dict = {}
        for r in cls.recs:
            groups.setdefault((r["kind"], r["fmt"]), []).append(r)
        rows = []
        for (kind, fmt), rs in sorted(groups.items()):
            row = {"kind": kind, "fmt": fmt, "n": len(rs), "kb": med([r["kb"] for r in rs])}
            for st_ in ("queue", "read", "decode", "resize", "encode", "total"):
                row[st_] = med([r.get(st_, 0) for r in rs])
            row["total_p90"] = p90([r["total"] for r in rs])
            row["embedded"] = round(sum(1 for r in rs if r.get("src")) / len(rs) * 100)
            rows.append(row)
        total = cls.hits + cls.misses
        return {"rows": rows, "hit_ratio": round(cls.hits / total * 100) if total else None,
                "requests": total, "workers": S.workers, "inflight": len(inflight), "waiting": sched.waiting + sched_video.waiting}


async def rendered(request: Request, kind: str, pid: str, s: Session) -> Response:
    p = library.get(pid)
    if not visible(s, p):
        raise HTTPException(404)
    box = {"s": S.thumb_small_size, "t": S.thumb_size, "m": S.thumb_large_size, "q": S.preview_quick_size,
           "p": S.preview_size}[kind]
    cache, q = (thumb_cache, S.thumb_quality) if kind in "stm" else (preview_cache, S.preview_quality)
    if kind == "q":
        q = S.preview_quick_quality
    # приоритет: быстрая версия открытого фото > полная > соседние (заголовок X-PF) > сетка
    # X-PF: 1 — соседи открытого фото, grid — видимые плитки сетки
    pf = request.headers.get("x-pf")
    prefetch = pf in ("1", "grid")
    prio = PRIO_GRID if kind in "stm" else PRIO_QUICK if kind == "q" else PRIO_VIEWER
    if prefetch and prio != PRIO_GRID:
        prio = PRIO_PREFETCH
    # к быстрой версии сразу готовим полную 2048 (n=p): тот же файл, второй раз с ПК не читаем
    nk = request.query_params.get("n")
    # для плиток сетки — только быстрое превью: полное «на всякий случай» для каждой плитки
    # заняло бы процессор и задержало эскизы
    ckey = (nk, pid, p.mtime, p.size) if kind == "q" and nk == "p" and not p.video and pf != "grid" else None
    key = (kind, pid, p.mtime, p.size)
    if time.time() - failed.get(key, 0) < FAILED_TTL:
        raise HTTPException(415)
    data = None
    timing = ""
    try:
        for _ in range(3):
            data = cache.get(key)
            if data is not None:
                Perf.hits += 1
                timing = "cache;desc=hit"
                break
            fut = inflight.get(key)
            if fut is not None:
                try:
                    data = await asyncio.shield(fut)
                    timing = "shared;desc=joined"
                    break
                except ClientGone:
                    continue   # тот, кто генерировал, ушёл — попробуем сами
            if not await PC.is_up():
                # ПК выключен: отвечаем сразу, а не ждём таймаутов SMB на каждой плитке
                raise HTTPException(503, "pc")
            fut = loop.create_future()
            fut.add_done_callback(lambda f: f.cancelled() or f.exception())
            inflight[key] = fut
            try:
                tq = time.perf_counter()
                try:
                    # просмотрщик — вне очереди; в сетке — сначала самые свежие запросы
                    lane = sched_video if p.video else sched
                    await lane.acquire(prio, request)
                except Gone:
                    raise ClientGone from None
                if not await PC.is_up():
                    # ПК выключился, пока запрос стоял в очереди
                    lane.release()
                    raise HTTPException(503, "pc")
                try:
                    tm = {"queue": (time.perf_counter() - tq) * 1000}
                    t0 = time.perf_counter()
                    pair = ckey is not None and preview_cache.get(ckey) is None and ckey not in inflight
                    if pair:
                        cfut = loop.create_future()
                        cfut.add_done_callback(lambda f: f.cancelled() or f.exception())
                        inflight[ckey] = cfut
                        try:
                            nbox = S.preview_size
                            data, raw = await on_pc(_produce_pair, p, box, q, tm, timeout=60)
                        except BaseException:
                            cfut.set_exception(ClientGone())
                            if inflight.get(ckey) is cfut:
                                del inflight[ckey]
                            raise
                        bg(_finish_companion(ckey, cfut, raw, nbox, S.preview_quality))
                    else:
                        data = await on_pc(_produce, p, box, q, tm, timeout=240 if p.video else 60)
                    tm["total"] = (time.perf_counter() - t0) * 1000
                finally:
                    lane.release()
                Perf.misses += 1
                Perf.recs.append({"kind": kind, "fmt": _fmt_class(p), "kb": len(data) / 1024, **tm})
                # видно в браузере: DevTools -> Network -> запрос -> Timing
                timing = ", ".join(f"{k};dur={v:.1f}" for k, v in tm.items() if k != "src") + \
                    (", src;desc=embedded" if tm.get("src") else "")
                cache.put(key, data)
                fut.set_result(data)
                break
            except BaseException as e:
                if not fut.done():
                    fut.set_exception(e if isinstance(e, Exception) else ClientGone())
                raise
            finally:
                if inflight.get(key) is fut:
                    del inflight[key]
    except ClientGone:
        return Response(status_code=499)
    except TooLarge:
        raise HTTPException(413) from None
    except (ConnectionError, TimeoutError) as e:
        if e.__cause__ is not None and is_missing(e.__cause__):
            raise _gone(p) from None             # эскиз удалённого файла: 404, а не «ПК выключен»
        PC.suspect()
        raise HTTPException(503, "pc") from None
    except (UnidentifiedImageError, Image.DecompressionBombWarning, Image.DecompressionBombError,
            OSError, ValueError, SyntaxError, MemoryError, video.subprocess.TimeoutExpired) as e:
        # одну и ту же неудачу видят все, кто ждал этот эскиз, — в лог пишем один раз
        if time.time() - failed.get(key, 0) > 2:
            log.info("не удалось декодировать %s (%s): %s %s", pid, p.name, type(e).__name__, str(e)[:160])
        if len(failed) > 5000:
            failed.clear()
        failed[key] = time.time()
        raise HTTPException(415) from None
    if data is None:
        raise HTTPException(503)
    v = request.query_params.get("v")
    cc = "private, max-age=31536000, immutable" if v == str(int(p.mtime)) else "private, max-age=60"
    return Response(data, media_type="image/webp" if S.image_format == "webp" else "image/jpeg",
                    headers={"cache-control": cc, "server-timing": timing})


def _gone(p) -> HTTPException:
    """Файл из списка пропал с ПК — список устарел: пересканировать папки (не чаще раза в минуту)."""
    global _gone_rescan
    log.info("%s уже нет на компьютере — обновляю список файлов", p.rel)
    if time.time() - _gone_rescan > 60:
        _gone_rescan = time.time()
        library.start_build(storage, _index_error)
    return HTTPException(404, "gone")


_gone_rescan = 0.0


def _size(f) -> int:
    n = f.seek(0, 2)
    f.seek(0)
    return n


async def serve_file(request: Request, p, extra: dict) -> Response:
    """Отдача оригинала с поддержкой Range (нужно для перемотки видео и iOS Safari)."""
    if not await PC.is_up():
        raise HTTPException(503, "pc")
    try:
        f = await on_pc(storage.open, p.rel, timeout=30)
        size = await on_pc(_size, f, timeout=30)
    except Exception as e:  # noqa: BLE001
        if is_missing(e):
            raise _gone(p) from None             # удалили на ПК: 404, а не «компьютер выключен»
        PC.suspect()
        raise HTTPException(503, "pc") from None
    start, end, status = 0, size - 1, 200
    headers = {"accept-ranges": "bytes", **extra}
    m = RANGE_RE.match((request.headers.get("range") or "").strip())
    if m and (m.group(1) or m.group(2)):
        if m.group(1):
            start = int(m.group(1))
            end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
        else:
            start, end = max(0, size - int(m.group(2))), size - 1
        if start > end or start >= size:
            await on_pc(f.close, timeout=10)
            return Response(status_code=416, headers={"content-range": f"bytes */{size}"})
        status = 206
        headers["content-range"] = f"bytes {start}-{end}/{size}"
    headers["content-length"] = str(end - start + 1)

    async def gen():
        try:
            f.seek(start)
            left = end - start + 1
            while left > 0:
                chunk = await on_pc(f.read, min(256 * 1024, left), timeout=45)
                if not chunk:
                    break
                left -= len(chunk)
                yield chunk
        finally:
            with contextlib.suppress(Exception):
                await on_pc(f.close, timeout=10)

    return StreamingResponse(gen(), status_code=status,
                             media_type=CONTENT_TYPES.get(p.ext, "application/octet-stream"), headers=headers)


# ---------------------------------------------------------------- «Подробнее»: камера, размеры, место

geocoder = geo.Geocoder(db)
_info_cache: dict = {}


HEIC_EXT = (".heic", ".heif")


def _info_from_file(p) -> dict:
    """Подробности без чтения файла целиком: EXIF и размеры почти всегда в начале
    (JPEG — до начала данных картинки, обычно до 256 КБ; HEIC — 512 КБ). Только если у HEIC в начале не нашлось ни
    камеры, ни координат, дочитываем файл — у части программ EXIF лежит в конце."""
    with storage.open(p.rel) as f:
        head = f.read(512 * 1024) if p.ext in HEIC_EXT else read_head(f)
        info = geo.exif_info(head)
        if p.ext in HEIC_EXT and "camera" not in info and "lat" not in info and p.size > len(head):
            try:
                info = geo.exif_info(head + read_limited(f, S.max_decode_mb * 1024 * 1024 - len(head)))
            except TooLarge:
                pass
    return info


library.info_reader = _info_from_file      # фоновый сбор подробностей после сканирования


@app.post("/api/admin/info/stop", dependencies=[Depends(require_csrf)])
async def admin_info_stop(request: Request, s: Session = Depends(require_admin)):
    """Остановить текущий фоновый сбор подробностей; следующее сканирование продолжит."""
    library.stop_info()
    audit("info_stop", s.user, ip_of(request), "остановлен сбор метаданных")
    return no_store(JSONResponse({"ok": True}))


async def _photo_info(pid: str, s: Session) -> dict:
    p = library.get(pid)
    if not visible(s, p):
        raise HTTPException(404)
    key = p.cache_key()                     # путь+размер+mtime: файл изменился — прочитаем заново
    info = _info_cache.get(key)
    if info is None:
        saved = await run_in_threadpool(db.info_get, key)       # прочитанное раньше — из базы
        if saved is not None:
            info = json.loads(saved)
        elif p.video:
            info = {}
        else:
            if not await PC.is_up():
                raise HTTPException(503, "pc")
            try:
                info = await on_pc(_info_from_file, p, timeout=30)
            except Exception:  # noqa: BLE001
                raise HTTPException(503, "pc") from None
            await run_in_threadpool(db.info_put, key, json.dumps(info))
        if len(_info_cache) > 5000:
            _info_cache.clear()
        _info_cache[key] = info
    return info


@app.get("/api/info/{pid}")
async def photo_info(pid: str = PathParam(pattern=ID_RE), s: Session = Depends(require_user)):
    """Подробности сразу: адрес — только если уже известен (без похода в интернет),
    чтобы карта показалась мгновенно; неизвестный адрес — отдельным запросом ниже."""
    out = dict(await _photo_info(pid, s))
    if "lat" in out:
        addr = await geocoder.cached(out["lat"], out["lon"])
        if addr is not None:
            out["address"] = addr or None
            out["address_known"] = True
    return no_store(JSONResponse(out))


@app.get("/api/info/{pid}/address")
async def photo_address(pid: str = PathParam(pattern=ID_RE), s: Session = Depends(require_user)):
    """Адрес по координатам снимка: OpenStreetMap (до 1–2 с при первом запросе места)."""
    info = await _photo_info(pid, s)
    if "lat" not in info:
        return no_store(JSONResponse({"address": None}))
    return no_store(JSONResponse({"address": await geocoder.address(info["lat"], info["lon"])}))


@app.get("/img/o/{pid}")
async def original(request: Request, pid: str = PathParam(pattern=ID_RE), s: Session = Depends(require_user)):
    p = library.get(pid)
    if not visible(s, p):
        raise HTTPException(404)
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", p.name)[:100] or "file"
    disp = "attachment" if request.query_params.get("dl") == "1" else "inline"
    return await serve_file(request, p, {
        "content-disposition": f"{disp}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(p.name)}",
        "cache-control": "private, max-age=3600",
        "content-security-policy": "default-src 'none'; sandbox",
    })


# ---------------------------------------------------------------- бэкап на другой компьютер
# Клиент ходит с токеном (Authorization: Bearer …), cookie не нужны, поэтому и CSRF не нужен:
# браузер сам такой заголовок не подставит.

def _hash_file(p, stop) -> str | None:
    h = hashlib.sha256()
    with storage.open(p.rel) as f:
        while True:
            if stop.is_set():
                return None
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


library.hash_reader = _hash_file

VERIFY_EVERY = 30 * 86400        # полная сверка хешей с файлами — раз в 30 дней
_verify_checked = 0.0


def _hash_mismatch(p, old: str, new: str) -> None:
    db.kv_set("hash_gen", int(db.kv_get("hash_gen") or 0) + 1)   # список для клиентов поменялся
    audit("hash_mismatch", "", "", f"{p.rel}: {old[:12]}… → {new[:12]}…")
    loop.call_soon_threadsafe(bg, ha.notify(
        "hash_mismatch", f"Проверка хешей: «{clean(p.rel, 120)}» изменился без смены размера и даты "
                         f"(порча диска на компьютере или программа, сохраняющая дату). Счётчик — в админке.",
        dedupe_s=3600, key="hash_mismatch"))


library.on_mismatch = _hash_mismatch


def _verify_info() -> dict:
    last, since = db.kv_get("verify_last"), db.kv_get("verify_since")
    return {"state": library.verify_state, "done": library.verify_done, "total": library.verify_total,
            "bytes_done": library.verify_bytes_done, "bytes_total": library.verify_bytes_total,
            "bad": library.verify_bad if library.verify_state else int(db.kv_get("verify_last_bad") or 0),
            "last": int(float(last)) if last else 0,
            "since": int(float(since)) if since else 0, "paused": db.kv_get("verify_paused") == "1",
            "next": int(float(last)) + VERIFY_EVERY if last else 0}


def _verify_tick() -> None:
    """Раз в минуту, пока ПК включён: начать проверку, если прошёл месяц, продолжить прерванную,
    отметить завершённую. Отметки — в базе (kv): verify_last, verify_since, verify_paused."""
    global _verify_checked
    now = time.time()
    if now - _verify_checked < 60 or not tokens.any() or library.state != "ready" or library.hash_busy():
        return
    _verify_checked = now
    last, since = db.kv_get("verify_last"), db.kv_get("verify_since")
    if last is None:
        db.kv_set("verify_last", now)       # хеши только что посчитаны — первая сверка через месяц
        return
    if since and library.verify_state == "done":
        db.kv_set("verify_last", now)
        db.kv_set("verify_since", None)
        db.kv_set("verify_last_bad", library.verify_bad)
        audit("hash_verify_done", "", "", f"проверено {library.verify_done}, не совпало {library.verify_bad}")
        return
    if since is None and now - float(last) >= VERIFY_EVERY:
        since = str(now)
        db.kv_set("verify_since", since)
    if since and db.kv_get("verify_paused") != "1":
        library.start_verify(storage, float(since))


def _hash_progress() -> dict:
    return {"state": library.hash_state, "done": library.hash_done, "total": library.hash_total,
            "bytes_done": library.hash_bytes_done, "bytes_total": library.hash_bytes_total}


_last_stale_check = 0.0


def _backup_stale_check() -> None:
    """Раз в 10 минут: клиент бэкапа давно не выходил на связь — уведомление (один раз)."""
    global _last_stale_check
    now = time.time()
    if now - _last_stale_check < 600 or not S.backup_stale_days:
        return
    _last_stale_check = now
    limit = S.backup_stale_days * 86400
    changed = False
    for t in tokens.all():
        if not t.stale_sent and now - (t.last_seen or t.created) > limit:
            t.stale_sent, t.dirty, changed = 1, True, True
            bg(ha.notify("backup_stale", f"Бэкап «{clean(t.name, 40)}» не выходил на связь больше "
                                         f"{S.backup_stale_days} дн.", dedupe_s=0))
    if changed:
        tokens.flush()


async def require_backup(request: Request):
    ip = ip_of(request)
    wait = limiter.blocked(ip)
    if wait:
        raise HTTPException(429, "locked", headers={"retry-after": str(wait)})
    auth = request.headers.get("authorization", "")
    t = tokens.get(auth[7:].strip() if auth[:7].lower() == "bearer " else "")
    if t is None or users.role(t.user) is None:
        if limiter.fail(ip):
            audit("lockout", "", ip, "5 неверных токенов бэкапа, блок 15 мин")
            bg(ha.notify("lockout", f"IP {clean(ip)} заблокирован на 15 мин: неверные токены бэкапа"))
        audit("backup_denied", "", ip)
        await asyncio.sleep(0.3)
        raise HTTPException(401, "token")
    tokens.seen(t, ip)
    return t


def _token_access(t):
    return None if users.role(t.user) == "admin" else users.folders(t.user)


_rel_map: tuple[str, dict] = ("", {})


def _by_rel(rel: str):
    global _rel_map
    ver, m = _rel_map
    if ver != library.version:
        m = {p.rel: p for p in library.by_id.values()}
        _rel_map = (library.version, m)
    return m.get(rel)


@app.get("/api/backup/status")
async def backup_status(t=Depends(require_backup)):
    up = await PC.is_up()
    pc = pc_state(up)
    return no_store(JSONResponse({
        "server": config.app_version(),
        "name": t.name,
        "pc": pc,
        "wake_left": max(0, int(S.wake_timeout - (time.time() - PC.wake_at))) if pc == "waking" else 0,
        "can_wake": users.can_wake(t.user),
        "index": {"state": library.state, "built_at": int(library.built_at), "version": library.version,
                  "complete": library.state == "ready" and not library.skipped and not library.error,
                  "skipped": library.skipped, "building": library.busy()},
        "hashes": _hash_progress(),
    }))


@app.post("/api/backup/wake")
async def backup_wake(t=Depends(require_backup)):
    return await _wake(t.user, f"Бэкап «{clean(t.name, 40)}» будит компьютер", f"бэкап «{t.name}»")


@app.get("/api/backup/manifest")
async def backup_manifest(request: Request, t=Depends(require_backup)):
    """Все видимые токену файлы: [путь, размер, mtime, дата снимка, sha256 | null]."""
    access = _token_access(t)
    # клиенты спрашивают раз в 10 с: «ничего не поменялось» отвечаем без чтения всех хешей
    n_hashes = await run_in_threadpool(db.hashes_count)
    gen = await run_in_threadpool(db.kv_get, "hash_gen")       # растёт, когда проверка нашла изменённый файл
    ver = library.version
    tag = hashlib.blake2b(f"{ver}|{n_hashes}|{gen}|{access!r}|{library.skipped}".encode(), digest_size=10).hexdigest()
    etag = f'"{tag}"'
    if ver and request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"etag": etag, "cache-control": "no-store"})
    hashes = await run_in_threadpool(db.hashes_load)

    def build() -> bytes:
        files = [[p.rel, p.size, int(p.mtime), int(p.date), hashes.get(p.cache_key())]
                 for p in library.by_id.values() if folder_ok(p.rel, access)]
        return json.dumps({"v": tag, "index_version": ver,
                           "complete": bool(ver) and library.state == "ready" and not library.skipped
                           and not library.error, "files": files},
                          ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")

    body = await run_in_threadpool(build)
    headers = {"etag": etag, "cache-control": "no-store"}
    if "gzip" in request.headers.get("accept-encoding", ""):
        import gzip
        body = await run_in_threadpool(gzip.compress, body, 6)
        headers["content-encoding"] = "gzip"
    return Response(body, media_type="application/json", headers=headers)


# Сжатие блоками: файл идёт кадрами [тип 1 байт][длина 4 байта][данные], каждый кадр — до 1 МБ
# исходных байт. Блок отправляется сжатым (zlib), только если так меньше хотя бы на 3%.
# JPEG/MP4/HEIC уже сжаты — после пары неудачных блоков сервер перестаёт их жать и лишь
# изредка пробует снова (внутри файла бывают и несжатые куски), чтобы не тратить процессор.
FRAME_RAW, FRAME_ZLIB = 0, 1
FRAME_BLOCK = 1024 * 1024


def _frame(raw: bytes, try_zip: bool) -> tuple[bytes, bool]:
    import zlib
    if try_zip:
        z = zlib.compress(raw, 3)
        if len(z) < len(raw) * 0.97:
            return bytes([FRAME_ZLIB]) + len(z).to_bytes(4, "big") + z, True
    return bytes([FRAME_RAW]) + len(raw).to_bytes(4, "big") + raw, False




async def _framed(p, start: int) -> Response:
    if not await PC.is_up():
        raise HTTPException(503, "pc")
    try:
        f = await on_pc(storage.open, p.rel, timeout=30)
        size = await on_pc(_size, f, timeout=30)
    except Exception as e:  # noqa: BLE001
        if is_missing(e):
            raise _gone(p) from None
        PC.suspect()
        raise HTTPException(503, "pc") from None
    if start > size:
        await on_pc(f.close, timeout=10)
        return Response(status_code=416, headers={"content-range": f"bytes */{size}"})

    async def gen():
        misses, skip = 0, 0
        try:
            f.seek(start)
            left = size - start
            while left > 0:
                raw = await on_pc(f.read, min(FRAME_BLOCK, left), timeout=60)
                if not raw:
                    break
                left -= len(raw)
                frame, ok = await run_in_threadpool(_frame, raw, skip == 0)
                if skip:
                    skip -= 1
                elif ok:
                    misses = 0
                else:
                    misses += 1
                    skip = min(32, 2 ** misses)       # не жмётся — следующие блоки без попыток
                yield frame
        except Exception as e:  # noqa: BLE001 — ПК пропал посреди файла: клиент докачает
            PC.suspect()
            log.info("бэкап: отдача %s прервана (%s)", p.name, type(e).__name__)
        finally:
            with contextlib.suppress(Exception):
                await on_pc(f.close, timeout=10)

    return StreamingResponse(gen(), media_type="application/octet-stream", headers={
        "cache-control": "no-store", "x-pc-frames": "1", "x-file-size": str(size),
        "x-file-mtime": str(int(p.mtime)), "x-start": str(start)})


@app.get("/api/backup/file")
async def backup_file(request: Request, path: str = "", z: int = 0, start: int = 0, t=Depends(require_backup)):
    p = _by_rel(path) if 0 < len(path) <= 2000 else None
    if p is None or not folder_ok(p.rel, _token_access(t)):
        raise HTTPException(404)
    if z == 1:                                        # клиент 1.1+: сжатие блоками
        return await _framed(p, max(0, start))
    return await serve_file(request, p, {"cache-control": "no-store",
                                         "content-disposition": "attachment",
                                         "x-file-size": str(p.size), "x-file-mtime": str(int(p.mtime))})


_REPORT_NUM = ("files", "bytes", "copied", "copied_bytes", "left_files", "left_bytes", "moved",
               "versions", "deleted", "errors", "pending_delete", "speed", "cur_done", "cur_size",
               "wire_bytes", "raw_bytes", "limit_mbps", "verify_last", "verify_done", "verify_total", "verify_bad")


@app.post("/api/backup/report")
async def backup_report(request: Request, t=Depends(require_backup)):
    d = await read_json(request)
    rep = {k: int(d[k]) for k in _REPORT_NUM
           if isinstance(d.get(k), int) and not isinstance(d.get(k), bool) and 0 <= d[k] < 2**53}
    for k in ("state", "client", "error", "current"):
        if isinstance(d.get(k), str):
            rep[k] = clean(d[k], 200)
    rep["at"] = int(time.time())
    await run_in_threadpool(tokens.set_report, t, rep)
    return no_store(JSONResponse({"ok": True}))


# ---- админка: токены бэкапа

_unhashed_cache: tuple = (None, 0)


def _unhashed() -> int:
    """Сколько файлов индекса ещё без хеша (пересчёт — только когда поменялся индекс или число хешей)."""
    global _unhashed_cache
    key = (library.version, db.hashes_count())
    if _unhashed_cache[0] != key:
        have = set(db.hashes_load())
        _unhashed_cache = (key, sum(1 for p in library.by_id.values() if p.cache_key() not in have))
    return _unhashed_cache[1]


@app.get("/api/admin/backup")
async def admin_backup(_: Session = Depends(require_admin)):
    return no_store(JSONResponse({"tokens": tokens.list(), "hashes": _hash_progress(),
                                  "verify": await run_in_threadpool(_verify_info),
                                  "hashed": await run_in_threadpool(db.hashes_count),
                                  "unhashed": await run_in_threadpool(_unhashed), "files": len(library.by_id),
                                  "users": [u["user"] for u in users.list()]}))


@app.post("/api/admin/backup/tokens", dependencies=[Depends(require_csrf)])
async def admin_backup_token_add(request: Request, s: Session = Depends(require_admin)):
    d = await read_json(request)
    name, user = d.get("name"), d.get("user")
    if not isinstance(name, str) or not isinstance(user, str) or users.role(user) is None:
        return _bad("нужны название и существующий пользователь")
    try:
        token, t = await run_in_threadpool(tokens.create, name, user)
    except ValueError as e:
        return _bad(str(e))
    audit("backup_token_add", s.user, ip_of(request), f"«{t.name}» для {user}")
    if await PC.is_up():
        library.start_hashes(storage)        # первый клиент — хеши начнём считать сразу
    return no_store(JSONResponse({"token": token, "id": t.id}))


@app.post("/api/admin/backup/tokens/{tid}/revoke", dependencies=[Depends(require_csrf)])
async def admin_backup_token_revoke(request: Request, tid: str, s: Session = Depends(require_admin)):
    if not re.fullmatch(r"[0-9a-f]{12}", tid):
        raise HTTPException(400)
    t = await run_in_threadpool(tokens.revoke, tid)
    if t is None:
        raise HTTPException(404)
    if not tokens.any():
        library.stop_hashes()
    audit("backup_token_revoke", s.user, ip_of(request), f"«{t.name}» ({t.user})")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/backup/hashes/stop", dependencies=[Depends(require_csrf)])
async def admin_backup_hashes_stop(request: Request, s: Session = Depends(require_admin)):
    library.stop_hashes()
    audit("hash_stop", s.user, ip_of(request), "остановлен подсчёт хешей")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/backup/verify/start", dependencies=[Depends(require_csrf)])
async def admin_backup_verify_start(request: Request, s: Session = Depends(require_admin)):
    """Проверить хеши всех файлов: продолжить начатую проверку или начать новую."""
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    if library.hash_busy():
        return _bad("сейчас уже считаются хеши — подожди окончания или останови")
    since = await run_in_threadpool(db.kv_get, "verify_since")
    if not since:
        since = str(time.time())
        await run_in_threadpool(db.kv_set, "verify_since", since)
    await run_in_threadpool(db.kv_set, "verify_paused", None)
    ok = library.start_verify(storage, float(since))
    audit("hash_verify", s.user, ip_of(request), "запущена проверка хешей")
    return no_store(JSONResponse({"ok": ok}))


@app.post("/api/admin/backup/verify/stop", dependencies=[Depends(require_csrf)])
async def admin_backup_verify_stop(request: Request, s: Session = Depends(require_admin)):
    await run_in_threadpool(db.kv_set, "verify_paused", "1")    # сама не продолжится, только по кнопке
    library.stop_hashes()
    audit("hash_stop", s.user, ip_of(request), "остановлена проверка хешей")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/backup/hashes/start", dependencies=[Depends(require_csrf)])
async def admin_backup_hashes_start(_: Session = Depends(require_admin)):
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    return no_store(JSONResponse({"ok": library.start_hashes(storage)}))


@app.get("/img/{kind}/{pid}")
async def image(request: Request, kind: str = PathParam(pattern=r"^[stmqp]$"),
                pid: str = PathParam(pattern=ID_RE), s: Session = Depends(require_user)):
    """s/t/m — эскизы 240/400/900, q — быстрое превью 720 (сильно сжатое), p — превью 2048 (размеры настраиваются)."""
    return await rendered(request, kind, pid, s)


# ---------------------------------------------------------------- видео: HLS на лету

def _vid(pid: str, s: Session):
    p = library.get(pid)
    if not visible(s, p) or not p.video:
        raise HTTPException(404)
    if not TRANSCODE:
        raise HTTPException(404, "transcode off")
    return p


async def _duration(p) -> float:
    k = f"{p.id}:{int(p.mtime)}:{p.size}"
    if k not in transcoder.durations:
        src, prot = _video_src(p)
        try:
            transcoder.durations[k] = await asyncio.to_thread(
                transcode.probe_duration, FFMPEG, src, prot, video.DEMUXER[p.ext])
        except Exception:  # noqa: BLE001
            transcoder.durations[k] = None
        if len(transcoder.durations) > 5000:
            transcoder.durations.clear()
    d = transcoder.durations.get(k)
    if not d:
        raise HTTPException(415, "no duration")
    return d


@app.get("/vid/{pid}/{profile}/index.m3u8")
async def vid_playlist(pid: str = PathParam(pattern=ID_RE), profile: str = PathParam(pattern=r"^eco$"),
                       s: Session = Depends(require_user)):
    p = _vid(pid, s)
    if not await PC.is_up():
        raise HTTPException(503, "pc")
    d = await _duration(p)
    body = transcode.playlist(d, lambda i: f"{i}.ts?v={int(p.mtime)}")
    return Response(body, media_type="application/vnd.apple.mpegurl", headers={"cache-control": "no-cache"})


@app.get("/vid/{pid}/{profile}/{n}.ts")
async def vid_segment(request: Request, pid: str = PathParam(pattern=ID_RE),
                      profile: str = PathParam(pattern=r"^eco$"), n: int = PathParam(ge=0, le=100000),
                      s: Session = Depends(require_user)):
    p = _vid(pid, s)
    d = await _duration(p)
    if n * transcode.SEG >= d:
        raise HTTPException(404)
    src, prot = _video_src(p)
    dem = video.DEMUXER[p.ext]

    def maker(i):
        return lambda: transcode.segment(FFMPEG, src, prot, dem, i, d, profile)
    key = lambda i: (pid, int(p.mtime), p.size, profile, i)  # noqa: E731
    try:
        data = await transcoder.get(key(n), maker(n))
    except ValueError:
        raise HTTPException(415) from None
    except Exception:  # noqa: BLE001
        raise HTTPException(503, "pc") from None
    if (n + 1) * transcode.SEG < d:
        transcoder.prefetch(key(n + 1), maker(n + 1))     # следующий кусок — заранее
    return Response(data, media_type="video/mp2t", headers={"cache-control": "private, max-age=3600"})


@app.post("/vid/{pid}/stop", dependencies=[Depends(require_csrf)])
async def vid_stop(pid: str = PathParam(pattern=ID_RE), s: Session = Depends(require_user)):
    """Вышли из видео или живого фото: перекодирование этого файла больше не нужно."""
    if not visible(s, library.get(pid)):
        raise HTTPException(404)
    return no_store(JSONResponse({"stopped": transcoder.stop(pid)}))


@app.get("/vid/{pid}/live.mp4")
async def vid_live(request: Request, pid: str = PathParam(pattern=ID_RE), q: str = "hq",
                   s: Session = Depends(require_user)):
    """Ролик живого фото: целиком, H.264 + звук — играет в любом браузере.
    Пара секунд видео перекодируется за доли секунды и живёт в RAM-кэше."""
    p = library.get(pid)
    if not visible(s, p) or not p.video or not p.live:
        raise HTTPException(404)
    if not TRANSCODE:
        return await serve_file(request, p, {"cache-control": "private, max-age=3600"})
    q = q if q in transcode.LIVE_PROFILES else "hq"
    if not await PC.is_up():
        raise HTTPException(503, "pc")
    src, prot = _video_src(p)
    try:
        data = await transcoder.get((pid, int(p.mtime), p.size, "live-" + q),
                                    lambda: transcode.live_clip(FFMPEG, src, prot, video.DEMUXER[p.ext], q))
    except ValueError:
        raise HTTPException(415) from None
    except Exception:  # noqa: BLE001
        raise HTTPException(503, "pc") from None
    return bytes_response(request, data, "video/mp4")


def bytes_response(request: Request, data: bytes, ctype: str) -> Response:
    """Ответ из памяти с поддержкой Range (Safari без неё не играет <video>)."""
    size = len(data)
    headers = {"accept-ranges": "bytes", "cache-control": "private, max-age=3600"}
    m = RANGE_RE.match((request.headers.get("range") or "").strip())
    if m and (m.group(1) or m.group(2)):
        if m.group(1):
            start = int(m.group(1))
            end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
        else:
            start, end = max(0, size - int(m.group(2))), size - 1
        if start > end or start >= size:
            return Response(status_code=416, headers={"content-range": f"bytes */{size}"})
        headers["content-range"] = f"bytes {start}-{end}/{size}"
        return Response(data[start:end + 1], status_code=206, media_type=ctype, headers=headers)
    return Response(data, media_type=ctype, headers=headers)


@app.get("/internal/raw/{pid}")
async def internal_raw(request: Request, pid: str = PathParam(pattern=ID_RE)):
    if not secrets.compare_digest(request.query_params.get("k", ""), INTERNAL_TOKEN):
        raise HTTPException(404)
    p = library.get(pid)
    if p is None:
        raise HTTPException(404)
    return await serve_file(request, p, {"cache-control": "no-store"})


# ================================================================ админка
# Все изменяющие запросы — POST с CSRF-заголовком; доступ только роли admin.

def _bad(msg: str, code: int = 400) -> JSONResponse:
    return no_store(JSONResponse({"error": msg}, code))


@app.post("/api/admin/setup", dependencies=[Depends(require_csrf)])
async def admin_setup(request: Request):
    """Создание первого администратора по одноразовому токену из консоли."""
    global SETUP_TOKEN
    ip = ip_of(request)
    wait = limiter.blocked(ip)
    if wait:
        return _bad("locked", 429)
    data = await read_json(request)
    tok, u, pw = data.get("token"), data.get("u"), data.get("p")
    if not SETUP_TOKEN or not users.empty():
        return _bad("уже настроено", 409)
    if not isinstance(tok, str) or not secrets.compare_digest(tok, SETUP_TOKEN):
        limiter.fail(ip)
        audit("setup_failed", "", ip)
        return _bad("неверный токен", 403)
    if not isinstance(u, str) or not isinstance(pw, str):
        return _bad("нужны логин и пароль")
    try:
        await run_in_threadpool(users.add, u, pw, "admin")
    except UserError as e:
        return _bad(str(e))
    SETUP_TOKEN = ""
    audit("setup", u, ip, "создан первый администратор")
    return no_store(JSONResponse({"ok": True}))


@app.get("/api/admin/setup-needed")
async def admin_setup_needed():
    return no_store(JSONResponse({"needed": bool(SETUP_TOKEN and users.empty())}))


@app.get("/api/admin/overview")
async def admin_overview(_: Session = Depends(require_admin)):
    up = await PC.is_up()
    # считаем только то, что видно в ленте: ролики живых фото — часть снимка, а не отдельный файл
    photos = [p for p in library.by_id.values() if not (p.video and p.live)]
    videos = sum(1 for p in photos if p.video)
    return no_store(JSONResponse({
        "version": config.app_version(),
        "uptime": int(time.time() - STARTED),
        "pc": pc_state(up),
        "index": {"state": library.state, "error": library.error, "files": len(photos), "videos": videos,
                  "with_date": sum(1 for p in photos if p.taken), "with_name_date": sum(1 for p in photos if not p.taken and p.named),
                  "with_folder_year": sum(1 for p in photos if p.folder_only()),
                  "built_at": int(library.built_at),
                  "meta": [library.meta_done, library.meta_total]},
        "hashes": _hash_progress() if tokens.any() else None,
        "cache": {"thumb": [thumb_cache.size, thumb_cache.max], "preview": [preview_cache.size, preview_cache.max]},
        "sessions": len(sessions.list()),
        "config": {   # только для чтения; секреты не отдаём, лишь факт их наличия
            "storage": S.storage,
            "source": S.local_root if S.storage == "local" else f"\\\\{S.smb_host}\\{S.smb_share}"
                      + (f"\\{S.smb_subdir}" if S.smb_subdir else ""),
            "smb_encrypt": S.smb_encrypt, "bind": f"{S.bind}:{S.port}", "cookie_secure": S.cookie_secure,
            "trusted_proxies": [str(n) for n in S.trusted_proxies], "require_proxy": S.require_proxy,
            "allowed_origins": sorted(S.allowed_origins), "ha_url": S.ha_url, "ha_token": bool(S.ha_token),
            "public_url": S.public_url, "google": bool(google),
            "google_redirect": google.redirect_uri if google else "",
            "ffmpeg": FFMPEG or "", "data_dir": str(S.data_dir), "workers": S.workers,
            "timezone": str(S.tz), "format": S.image_format,
            "sizes": f"{S.thumb_small_size}/{S.thumb_size}/{S.thumb_large_size}, превью {S.preview_quick_size}/{S.preview_size}",
        },
    }))


# ---- пользователи

def _user_arg(name: str) -> str:
    if not USER_RE.match(name):
        raise HTTPException(400, "bad user")
    return name


@app.get("/api/admin/users")
async def admin_users(_: Session = Depends(require_admin)):
    return no_store(JSONResponse({"users": users.list()}))


@app.post("/api/admin/users", dependencies=[Depends(require_csrf)])
async def admin_user_add(request: Request, s: Session = Depends(require_admin)):
    d = await read_json(request)
    u, pw, role = d.get("u"), d.get("p"), d.get("role", "user")
    if not all(isinstance(x, str) for x in (u, pw, role)):
        return _bad("нужны логин, пароль и роль")
    try:
        await run_in_threadpool(users.add, u, pw, role)
    except UserError as e:
        return _bad(str(e))
    audit("user_add", s.user, ip_of(request), f"{u} ({role})")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/password", dependencies=[Depends(require_csrf)])
async def admin_user_password(request: Request, name: str, s: Session = Depends(require_admin)):
    name = _user_arg(name)
    d = await read_json(request)
    if not isinstance(d.get("p"), str):
        return _bad("нужен пароль")
    try:
        await run_in_threadpool(users.set_password, name, d["p"])
    except UserError as e:
        return _bad(str(e))
    n = sessions.revoke_user(name)          # смена пароля выкидывает все сессии пользователя
    audit("user_password", s.user, ip_of(request), f"{name}, закрыто сессий: {n}")
    return no_store(JSONResponse({"ok": True, "revoked": n}))


@app.post("/api/admin/users/{name}/google", dependencies=[Depends(require_csrf)])
async def admin_user_google(request: Request, name: str, s: Session = Depends(require_admin)):
    name = _user_arg(name)
    d = await read_json(request)
    email = d.get("email")
    if email is not None and not isinstance(email, str):
        return _bad("email строкой")
    try:
        users.set_google(name, email or None)
    except UserError as e:
        return _bad(str(e))
    audit("user_google", s.user, ip_of(request), f"{name} -> {email or 'отвязан'}")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/wake", dependencies=[Depends(require_csrf)])
async def admin_user_wake(request: Request, name: str, s: Session = Depends(require_admin)):
    """Может ли пользователь включать компьютер (админ — всегда)."""
    name = _user_arg(name)
    d = await read_json(request)
    allow = d.get("allow")
    if not isinstance(allow, bool):
        return _bad("allow: true/false")
    try:
        users.set_wake(name, allow)
    except UserError as e:
        return _bad(str(e))
    audit("user_wake", s.user, ip_of(request), f"{name} -> {'может' if allow else 'не может'} включать ПК")
    return no_store(JSONResponse({"ok": True}))


@app.get("/api/admin/folders")
async def admin_folders(_: Session = Depends(require_admin)):
    """Папки для настройки доступа: верхний уровень и следующий (длинное дерево не нужно)."""
    fl = [f for f in library._folders if f and f.count("/") <= 1]
    return no_store(JSONResponse({"folders": fl}))


@app.post("/api/admin/users/{name}/folders", dependencies=[Depends(require_csrf)])
async def admin_user_folders(request: Request, name: str, s: Session = Depends(require_admin)):
    """Какие папки видит пользователь: folders — null (все) или список (с подпапками);
    exclude — подпапки, скрытые внутри разрешённых."""
    name = _user_arg(name)
    d = await read_json(request)
    folders, exclude = d.get("folders"), d.get("exclude") or []
    try:
        users.set_folders(name, folders, exclude)
    except UserError as e:
        return _bad(str(e))
    what = "все" if folders is None else ", ".join(folders) or "никакие"
    audit("user_folders", s.user, ip_of(request), f"{name} -> {what}" + (f", кроме {', '.join(exclude)}" if exclude else ""))
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/role", dependencies=[Depends(require_csrf)])
async def admin_user_role(request: Request, name: str, s: Session = Depends(require_admin)):
    name = _user_arg(name)
    d = await read_json(request)
    try:
        users.set_role(name, d.get("role"))
    except UserError as e:
        return _bad(str(e))
    audit("user_role", s.user, ip_of(request), f"{name} -> {d.get('role')}")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/delete", dependencies=[Depends(require_csrf)])
async def admin_user_delete(request: Request, name: str, s: Session = Depends(require_admin)):
    name = _user_arg(name)
    if name == s.user:
        return _bad("нельзя удалить самого себя")
    try:
        users.delete(name)
    except UserError as e:
        return _bad(str(e))
    n = sessions.revoke_user(name)
    nt = tokens.revoke_user(name)
    audit("user_delete", s.user, ip_of(request), f"{name}, закрыто сессий: {n}" + (f", токенов бэкапа: {nt}" if nt else ""))
    return no_store(JSONResponse({"ok": True}))


# ---- сессии и блокировки

@app.get("/api/admin/sessions")
async def admin_sessions(s: Session = Depends(require_admin)):
    return no_store(JSONResponse({"sessions": sessions.list(), "current": s.sid}))  # type: ignore[attr-defined]


@app.post("/api/admin/sessions/{sid}/revoke", dependencies=[Depends(require_csrf)])
async def admin_session_revoke(request: Request, sid: str, s: Session = Depends(require_admin)):
    if not re.fullmatch(r"[0-9a-f]{16}", sid):
        raise HTTPException(400)
    ok = sessions.revoke(sid)
    audit("session_revoke", s.user, ip_of(request), sid)
    return no_store(JSONResponse({"ok": ok}))


@app.get("/api/admin/lockouts")
async def admin_lockouts(_: Session = Depends(require_admin)):
    return no_store(JSONResponse({"locked": limiter.locked()}))


@app.post("/api/admin/lockouts/{ip}/clear", dependencies=[Depends(require_csrf)])
async def admin_lockout_clear(request: Request, ip: str, s: Session = Depends(require_admin)):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(400) from None
    limiter.unlock(ip)
    audit("unlock_ip", s.user, ip_of(request), ip)
    return no_store(JSONResponse({"ok": True}))


# ---- настройки

@app.get("/api/admin/settings")
async def admin_settings(_: Session = Depends(require_admin)):
    return no_store(JSONResponse({"settings": config.export_editable(S),
                                  "events": sorted(config.ALL_NOTIFY_EVENTS)}))


@app.post("/api/admin/settings", dependencies=[Depends(require_csrf)])
async def admin_settings_save(request: Request, s: Session = Depends(require_admin)):
    d = await read_json(request, limit=8192)
    new = {}
    try:
        for k, v in d.items():
            new[k] = config.validate_override(S, k, v)
    except config.ConfigError as e:
        return _bad(str(e))
    changed = [k for k, v in new.items() if getattr(S, k) != v]
    for k, v in new.items():
        setattr(S, k, v)
    sessions.idle_s = S.session_idle_hours * 3600
    try:
        await run_in_threadpool(config.save_overrides, S)
    except OSError as e:
        return _bad(f"не удалось сохранить: {type(e).__name__}", 500)
    if changed:
        audit("settings", s.user, ip_of(request), ", ".join(changed))
    return no_store(JSONResponse({"ok": True, "changed": changed}))


# ---- обслуживание

@app.post("/api/admin/notify-test", dependencies=[Depends(require_csrf)])
async def admin_notify_test(s: Session = Depends(require_admin)):
    if not S.ha_notify_service or not S.ha_token:
        return _bad("не задан сервис уведомлений или токен HA")
    svc = await ha.notify_service()
    if not svc:
        return _bad(f"не удалось получить сервис уведомлений из {S.ha_notify_service} (см. журнал)", 502)
    ok = await ha.call(svc, {"title": S.public_name, "message": f"Тестовое уведомление от {s.user} → {svc}"})
    return no_store(JSONResponse({"ok": ok}) if ok else _bad("HA не принял вызов (см. логи)", 502))


@app.post("/api/admin/cache/clear", dependencies=[Depends(require_csrf)])
async def admin_cache_clear(request: Request, s: Session = Depends(require_admin)):
    thumb_cache.clear()
    preview_cache.clear()
    audit("cache_clear", s.user, ip_of(request))
    return no_store(JSONResponse({"ok": True}))


@app.get("/api/admin/perf")
async def admin_perf(_: Session = Depends(require_admin)):
    return no_store(JSONResponse(Perf.summary()))


@app.post("/api/admin/bench", dependencies=[Depends(require_csrf)])
async def admin_bench(_: Session = Depends(require_admin)):
    """Генерирует эскизы для случайных файлов каждого типа (мимо кэша) и меряет этапы.
    Отдельно — сколько файлов в секунду выдаёт сервер, если грузить все потоки сразу."""
    if not await PC.is_up():
        return _bad("компьютер выключен", 409)
    by_fmt: dict = {}
    for p in library.by_id.values():
        by_fmt.setdefault(_fmt_class(p), []).append(p)
    sample = []
    for fmt, ps in by_fmt.items():
        sample += [(fmt, p) for p in random.sample(ps, min(6, len(ps)))]
    results = []
    for fmt, p in sample:                       # по одному — чистые времена этапов
        tm: dict = {}
        t = time.perf_counter()
        try:
            async with sched.slot(PRIO_GRID):
                data = await on_pc(_produce, p, S.thumb_small_size, S.thumb_quality, tm)
            tm["total"] = (time.perf_counter() - t) * 1000
            results.append({"fmt": fmt, "name": p.name, "mb": round(p.size / 1048576, 1),
                            "kb": round(len(data) / 1024, 1), **{k: round(v, 1) for k, v in tm.items()}})
        except Exception as e:  # noqa: BLE001
            msg = str(e).strip()
            results.append({"fmt": fmt, "name": p.name,
                            "error": type(e).__name__ + (f": {msg[:120]}" if msg else "")})
    # параллельно: N файлов на всех потоках
    jpegs = [p for p in by_fmt.get("jpeg", []) or list(library.by_id.values()) if not p.video][:400]
    par = random.sample(jpegs, min(S.workers * 6, len(jpegs)))

    async def one(p):
        async with sched.slot(PRIO_GRID):
            await on_pc(_produce, p, S.thumb_small_size, S.thumb_quality, {})
    t = time.perf_counter()
    await asyncio.gather(*(one(p) for p in par), return_exceptions=True)
    dt = time.perf_counter() - t
    return no_store(JSONResponse({"items": results, "workers": S.workers,
                                  "parallel": {"files": len(par), "sec": round(dt, 2),
                                               "per_sec": round(len(par) / dt, 1) if dt else None}}))


@app.get("/api/admin/logs")
async def admin_logs(request: Request, _: Session = Depends(require_admin)):
    kind = request.query_params.get("kind", "audit")
    if kind == "server":
        lvl = {"debug": 10, "info": 20, "warning": 30, "error": 40}.get(request.query_params.get("level", "info"), 20)
        return no_store(JSONResponse({"items": logs.ring.tail(1000, lvl)}))
    return no_store(JSONResponse({"items": audit.tail(1000)}))


mimetypes.add_type("application/manifest+json", ".webmanifest")
class StaticGzip:
    """gzip только для страниц и статики (html/js/css ~ в 3–4 раза меньше).
    Картинки и видео уже сжаты — их не трогаем, чтобы не тратить процессор."""

    def __init__(self, app):
        from starlette.middleware.gzip import GZipMiddleware
        self.app, self.gz = app, GZipMiddleware(app, minimum_size=1024, compresslevel=6)

    async def __call__(self, scope, receive, send):
        p = scope.get("path", "") if scope["type"] == "http" else ""
        if p in ("/", "/admin") or (p.startswith("/static/")):
            return await self.gz(scope, receive, send)
        return await self.app(scope, receive, send)


app = Guard(StaticGzip(app))  # type: ignore[assignment]
