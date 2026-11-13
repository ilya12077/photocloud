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
from . import totp
from .db import DB, ThumbStore
from .backup import TokenStore
from .auth import USER_RE, LoginLimiter, Session, SessionStore, UserError, UserStore
from .ha import HomeAssistant, clean
from .images import LRUBytes, TooLarge, decode, embedded_heic, embedded_jpeg, finish, read_head, read_limited, render
from . import transcode, video
from .google_auth import GoogleAuth, GoogleError
from .yandex_auth import YandexAuth, YandexError
from .passkeys import Passkeys, PasskeyError, rp_for
from .pc import PcAuth, PcError, delete_message
from .library import Library, folder_ok
from .sched import PRIO_GRID, PRIO_PREFETCH, PRIO_QUICK, PRIO_VIEWER, Gone, Scheduler
from .storage import RESTORED, RestoreWriter, is_missing, is_read_error, make_storage

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
PK_COOKIE = "pc_pk"
ID_RE = r"^[A-Za-z0-9_-]{8}$"

storage = make_storage(S)
db = DB(S.data_dir / "photocloud.db")
pthumbs = ThumbStore(S.data_dir / "thumbs.db")      # эскизы фото 240/400 — отдельный файл
library = Library(S.tz, S.meta_threads, db)
FFMPEG = video.find_ffmpeg(S.ffmpeg)
TRANSCODE = bool(S.transcode and FFMPEG and transcode.has_x264(FFMPEG))
transcoder = transcode.Transcoder(LRUBytes(S.transcode_cache_mb * 1024 * 1024), S.transcode_slots)
google = GoogleAuth(S.google_client_id, S.google_client_secret, S.public_url) if S.google_client_id else None
yandex = YandexAuth(S.yandex_client_id, S.yandex_client_secret, S.public_url) if S.yandex_client_id else None
# одноразовый секрет для внутреннего канала ffmpeg -> приложение (только loopback)
INTERNAL_TOKEN = secrets.token_urlsafe(32)
ha = HomeAssistant(S)
try:
    users = UserStore(S.data_dir / "users.json")
except (OSError, ValueError) as e:
    raise SystemExit(f"Не читается {S.data_dir / 'users.json'}: {e}") from None
# пока нет ни одного пользователя — первичная настройка по одноразовому токену из консоли
SETUP_TOKEN = secrets.token_urlsafe(24) if users.empty() else ""
sessions = SessionStore(S.session_idle_hours * 3600, S.session_max_hours * 3600, db,
                        short_s=S.session_short_minutes * 60)
tokens = TokenStore(db)                       # клиенты бэкапа
library.hash_wanted = tokens.any              # хеши файлов считаем, только если бэкап есть
limiter = LoginLimiter()
# «свои» адреса (на них не действует общий потолок неудач) — из живых сессий и клиентов бэкапа
for _s in list(sessions._s.values()):
    limiter.success(_s.ip, _s.last_seen)
for _t in tokens.all():
    if _t.last_ip:
        limiter.success(_t.last_ip, _t.last_seen)
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
    ".mpg": "video/mpeg", ".mpeg": "video/mpeg", ".vob": "video/mpeg",
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

        admin_api = scope["path"].startswith("/api/admin/")

        async def _send(msg):
            if msg["type"] == "http.response.start":
                names = {k.lower() for k, _ in msg.get("headers", [])}
                msg["headers"] = list(msg.get("headers", [])) + [h for h in SEC_HEADERS if h[0] not in names]
                if admin_api:   # «N секунд назад» админка считает по часам сервера, а не браузера
                    msg["headers"].append((b"x-server-time", str(int(time.time() * 1000)).encode()))
            await send(msg)

        await self.app(scope, receive, _send)


@contextlib.asynccontextmanager
async def lifespan(_app):
    global loop
    loop = asyncio.get_running_loop()
    log.info("Photocloud %s", config.app_version())
    await run_in_threadpool(library.load_snapshot)     # ПК может быть выключен — показать последний список
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
    if yandex:
        await yandex.close()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def ip_of(request: Request) -> str:
    return client_ip(request.scope.get("client"), request.headers)


# ---------------------------------------------------------------- auth deps

async def require_user(request: Request) -> Session:
    token = request.cookies.get(COOKIE)
    # фоновый опрос (X-Poll) не считается действием человека — сессию не продлевает
    s = sessions.get(token, touch=request.headers.get("x-poll") != "1")
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
    чужой id отвечает 404 — так же, как несуществующий. (Скрытое у каждого своё: свои скрытые
    пользователь видит на /hidden, на других оно не влияет.)"""
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


@app.get("/starred", include_in_schema=False)
async def starred_page():
    """Избранное — та же галерея (список — /api/library?starred=1)."""
    return Response(PAGES["/"], media_type="text/html; charset=utf-8", headers={"cache-control": "no-cache"})


@app.get("/hidden", include_in_schema=False)
async def hidden_page():
    """Скрытые фото — та же галерея (кто может смотреть — решает /api/library?hidden=1)."""
    return Response(PAGES["/"], media_type="text/html; charset=utf-8", headers={"cache-control": "no-cache"})


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
    remember = data.get("r") is True      # «Запомнить вход»: по умолчанию — нет
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
    if users.totp_required(u):
        # пароль верный, но нужен код из приложения (или его настройка) — сессию дадим после него
        return no_store(_need_2fa(JSONResponse({"need": "totp"}), u, ip, "паролю", remember))
    limiter.success(ip)
    audit("login", u, ip)
    return no_store(start_session(request, JSONResponse({"user": u, "role": role}), u, ip, "паролю", remember))


# ---- двухфакторный вход: включает админ («Пользователи» → 2FA). Спрашивается при входе по паролю
# (вход через Google его не требует: там защищает сам аккаунт Google) —
# код из приложения; если приложение ещё не настроено — сначала QR-код и первый код.
# Потерян телефон — админ сбрасывает в «Пользователях» или из консоли: python -m app 2fa-reset <логин>
TFA_COOKIE = "pc_2fa"
TFA_TTL = 600
_tfa: dict[str, dict] = {}          # билет -> {user, ip, how, exp, tries, setup: новый секрет или ""}


def _need_2fa(resp: Response, u: str, ip: str, how: str, remember: bool) -> Response:
    now = time.time()
    for k in [k for k, v in _tfa.items() if v["exp"] < now]:
        del _tfa[k]
    if len(_tfa) > 1000:
        _tfa.clear()
    ticket = secrets.token_urlsafe(24)
    _tfa[ticket] = {"user": u, "ip": ip, "how": how, "exp": now + TFA_TTL, "tries": 0, "remember": remember,
                    "setup": "" if users.totp_on(u) else totp.new_secret()}
    resp.set_cookie(TFA_COOKIE, ticket, max_age=TFA_TTL, path="/", secure=S.cookie_secure,
                    httponly=True, samesite="strict")
    return resp


def _tfa_ticket(request: Request):
    ticket = request.cookies.get(TFA_COOKIE, "")
    t = _tfa.get(ticket)
    if not t or t["exp"] < time.time() or t["ip"] != ip_of(request):
        _tfa.pop(ticket, None)
        return ticket, None
    return ticket, t


@app.get("/api/login/2fa")
async def login_2fa_state(request: Request):
    """Что показать на втором шаге: поле для кода или настройку приложения (QR и ключ)."""
    _, t = _tfa_ticket(request)
    if t is None:
        return no_store(JSONResponse({"error": "expired"}, 401))
    if not t["setup"]:
        return no_store(JSONResponse({"need": "totp"}))
    u = totp.uri(t["setup"], t["user"], S.public_name)
    return no_store(JSONResponse({"need": "setup", "secret": t["setup"], "qr": totp.qr_data_url(u)}))


@app.post("/api/login/2fa", dependencies=[Depends(require_csrf)])
async def login_2fa(request: Request):
    ip = ip_of(request)
    wait = limiter.blocked(ip)
    if wait:
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429, headers={"retry-after": str(wait)}))
    ticket, t = _tfa_ticket(request)
    if t is None:
        return no_store(JSONResponse({"error": "expired"}, 401))
    data = await read_json(request)
    u = t["user"]
    if t["setup"]:
        # первая настройка: код должен совпасть с новым ключом — значит, приложение настроено верно
        st = totp.match(t["setup"], totp.norm(data.get("code")))
        ok = st is not None
        if ok:
            await run_in_threadpool(users.totp_enable, u, t["setup"], st)
            audit("2fa_on", u, ip, "приложение настроено")
    else:
        ok = await run_in_threadpool(users.totp_check, u, data.get("code"))
    if not ok:
        t["tries"] += 1
        if t["tries"] >= 5:
            _tfa.pop(ticket, None)
        locked = limiter.fail(ip)
        audit("login_2fa_failed", u, ip)
        bg(ha.notify("login_failed", f"Неверный код второго шага для «{clean(u, 32)}» с {clean(ip)}",
                     dedupe_s=300, key=ip))
        if locked:
            audit("lockout", "", ip, "5 неудачных входов, блок 15 мин")
            bg(ha.notify("lockout", f"IP {clean(ip)} заблокирован на 15 мин после 5 неудачных входов"))
        await asyncio.sleep(0.3)
        return no_store(JSONResponse({"error": "code", "left": max(0, 5 - t["tries"])}, 401))
    _tfa.pop(ticket, None)
    limiter.success(ip)
    role = users.role(u)
    if role is None:
        return no_store(JSONResponse({"error": "expired"}, 401))
    audit("login", u, ip, "с кодом из приложения")
    resp = start_session(request, JSONResponse({"user": u, "role": role}), u, ip, t["how"], t["remember"])
    resp.delete_cookie(TFA_COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="strict")
    return no_store(resp)


def start_session(request: Request, resp: Response, u: str, ip: str, how: str, remember: bool) -> Response:
    sessions.delete(request.cookies.get(COOKIE))   # против фиксации сессии
    token = sessions.create(u, ip, remember)
    seen = known_ips.setdefault(u, set())
    if ip not in seen:
        seen.add(ip)
        bg(ha.notify("login_new_ip", f"Вход {u} с нового адреса {clean(ip)} (по {how})", dedupe_s=0))
    bg(ha.notify("login", f"Вход {u} с {clean(ip)} (по {how})", dedupe_s=0))
    # без «Запомнить вход» — сеансовая cookie: закрыл браузер — вышел
    resp.set_cookie(COOKIE, token, max_age=S.session_max_hours * 3600 if remember else None, path="/",
                    secure=S.cookie_secure, httponly=True, samesite="strict")
    return resp


# ---- вход по ключу (passkey). Создать ключ предлагает админ («Пользователи» → Passkey) —
# пользователь видит предложение после следующего входа. Вход по ключу — без пароля и кода.
passkeys = Passkeys(db, S.public_name)


def _rp(request: Request) -> tuple[str, str]:
    allowed = set(S.allowed_origins) | ({S.public_url} if S.public_url else set())
    if not allowed:      # тест без настроек: сам адрес, по которому открыт сайт
        allowed = {f"{request.url.scheme}://{request.headers.get('host', '')}"}
    try:
        return rp_for(request.headers.get("origin", ""), allowed)
    except PasskeyError:
        raise HTTPException(403, "origin") from None


@app.post("/api/passkey/login/options", dependencies=[Depends(require_csrf)])
async def passkey_login_options(request: Request):
    ip = ip_of(request)
    if wait := limiter.blocked(ip):
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429))
    rp_id, origin = _rp(request)
    try:
        opts, ticket = passkeys.login_options(rp_id, origin)
    except PasskeyError:
        return _bad("занято, попробуй через минуту", 503)
    resp = Response(opts, media_type="application/json")
    resp.set_cookie(PK_COOKIE, ticket, max_age=300, path="/", secure=S.cookie_secure, httponly=True, samesite="strict")
    return no_store(resp)


@app.post("/api/passkey/login", dependencies=[Depends(require_csrf)])
async def passkey_login(request: Request):
    ip = ip_of(request)
    if wait := limiter.blocked(ip):
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429))
    data = await read_json(request, limit=16384)
    try:
        u = await run_in_threadpool(passkeys.login, request.cookies.get(PK_COOKIE, ""), data.get("credential"))
    except PasskeyError as e:
        log.info("вход по ключу отклонён: %s", e)
        locked = limiter.fail(ip)
        audit("login_passkey_failed", "", ip, str(e)[:120])
        if locked:
            audit("lockout", "", ip, "5 неудачных входов, блок 15 мин")
        await asyncio.sleep(0.3)
        return no_store(JSONResponse({"error": "key"}, 401))
    role = users.role(u)
    if role is None:
        return no_store(JSONResponse({"error": "key"}, 401))
    limiter.success(ip)
    audit("login_passkey", u, ip)
    resp = start_session(request, JSONResponse({"user": u, "role": role}), u, ip, "ключу", data.get("r") is True)
    resp.delete_cookie(PK_COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="strict")
    return no_store(resp)


@app.post("/api/passkey/register/options", dependencies=[Depends(require_csrf)])
async def passkey_register_options(request: Request, s: Session = Depends(require_user)):
    rp_id, origin = _rp(request)
    try:
        opts, ticket = await run_in_threadpool(passkeys.register_options, s.user, rp_id, origin)
    except PasskeyError:
        return _bad("занято, попробуй через минуту", 503)
    return no_store(JSONResponse({"options": json.loads(opts), "ticket": ticket}))


@app.post("/api/passkey/register", dependencies=[Depends(require_csrf)])
async def passkey_register(request: Request, s: Session = Depends(require_user)):
    data = await read_json(request, limit=32768)
    name = data.get("name") if isinstance(data.get("name"), str) else ""
    try:
        await run_in_threadpool(passkeys.register, s.user, data.get("ticket", ""), data.get("credential"), name)
    except PasskeyError as e:
        log.info("ключ не создан: %s", e)
        return _bad("не удалось сохранить ключ — попробуй ещё раз")
    await run_in_threadpool(users.set_passkey_offer, s.user, False)
    audit("passkey_add", s.user, ip_of(request), name[:60])
    return no_store(JSONResponse({"ok": True}))


@app.get("/api/auth/providers")
async def auth_providers():
    return no_store(JSONResponse({"google": google is not None, "yandex": yandex is not None}))


@app.get("/auth/google")
async def google_start(request: Request):
    if google is None:
        raise HTTPException(404)
    if limiter.blocked(ip_of(request)):
        return RedirectResponse("/#err=locked", 303)
    try:
        url, state = google.start(request.query_params.get("r") == "1")
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
        email, remember = await google.finish(q.get("state", ""), request.cookies.get(OAUTH_COOKIE, ""),
                                              q.get("code", ""))
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
    # второй шаг (код из приложения) не спрашиваем: вход через Google — сам по себе вход без пароля,
    # защищённый аккаунтом Google; 2FA — для входа по паролю (запасной путь)
    limiter.success(ip)
    audit("login_google", u, ip, email)
    resp = start_session(request, RedirectResponse("/", 303), u, ip, "Google", remember)
    resp.delete_cookie(OAUTH_COOKIE, path="/", secure=S.cookie_secure, httponly=True, samesite="lax")
    return no_store(resp)


@app.get("/auth/yandex")
async def yandex_start(request: Request):
    if yandex is None:
        raise HTTPException(404)
    if limiter.blocked(ip_of(request)):
        return RedirectResponse("/#err=locked", 303)
    try:
        url, state = yandex.start(request.query_params.get("r") == "1")
    except YandexError:
        raise HTTPException(503) from None
    resp = RedirectResponse(url, 303)
    # Lax: cookie должна вернуться при переходе со страницы Яндекса обратно к нам
    resp.set_cookie(OAUTH_COOKIE, state, max_age=600, path="/", secure=S.cookie_secure,
                    httponly=True, samesite="lax")
    return no_store(resp)


@app.get("/auth/yandex/callback")
async def yandex_callback(request: Request):
    if yandex is None:
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
        return fail("yandex-cancel")
    try:
        emails, remember = await yandex.finish(q.get("state", ""), request.cookies.get(OAUTH_COOKIE, ""),
                                               q.get("code", ""))
    except YandexError as e:
        log.info("вход через Яндекс отклонён: %s", e)
        audit("login_yandex_failed", "", ip, str(e))
        return fail("yandex")
    hit = users.by_ext("yandex", emails)
    if hit is None:
        limiter.fail(ip)
        audit("login_yandex_denied", "", ip, ", ".join(emails)[:200])
        bg(ha.notify("login_failed", f"Вход через Яндекс с непривязанного аккаунта {clean(emails[0])} с {clean(ip)}",
                     dedupe_s=300, key=ip))
        return fail("yandex-denied")
    u, _role = hit
    # как и с Google: код из приложения не спрашиваем, аккаунт защищает сам Яндекс
    limiter.success(ip)
    audit("login_yandex", u, ip, emails[0])
    resp = start_session(request, RedirectResponse("/", 303), u, ip, "Яндекс ID", remember)
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
                                  "can_wake": users.can_wake(s.user), "can_delete": s.role == "admin",  # type: ignore[attr-defined]
                                  "passkey_offer": users.passkey_offer(s.user)}))


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
async def status(hidden: int = 0, starred: int = 0, s: Session = Depends(require_user)):
    pc = pc_state(await PC.is_up())
    # на страницах скрытых и избранного — версия и число их файлов
    view = await run_in_threadpool(_view_for, s, hidden, starred)
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
        # админу — фоновый подсчёт и проверка хешей (бэкап): они тоже читают файлы с ПК
        "bg": _bg_hashes() if s.role == "admin" else None,  # type: ignore[attr-defined]
    }))


def _bg_hashes() -> dict | None:
    if library.verify_state == "running":
        return {"kind": "verify", "done": library.verify_done, "total": library.verify_total,
                **_speed_eta(library.verify_bytes_total - library.verify_bytes_done)}
    if library.hash_state == "running":
        return {"kind": "hash", "done": library.hash_done, "total": library.hash_total,
                **_speed_eta(library.hash_bytes_total - library.hash_bytes_done)}
    return None


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


# ---------------------------------------------------------------- личное: скрытые, группы, избранное
# У каждого пользователя свои: скрыл — пропало только у него (на /hidden он их видит), группы
# видит только он, избранное — тоже. Файлы на ПК не трогаются (и бэкап не меняется).
# Отмечать можно только то, что пользователь видит (свои папки). Хранится путь: файл
# переименовали или перенесли на ПК — пометка с него слетает.

HIDE_MAX = 10000          # файлов за раз


class _Mine:
    """Наборы пользователей в памяти; запись — под замком, новый набор подменяется целиком."""

    def __init__(self):
        self.mu = threading.Lock()
        self.hidden: dict[str, dict[str, float]] = db.hidden_load()       # пользователь -> {путь: когда}
        self.groups: dict[str, dict[str, tuple[str, bool]]] = db.groups_load()   # -> {путь: (группа, обложка?)}
        self.starred: dict[str, set[str]] = db.starred_load()            # -> пути
        self.gen: dict[str, int] = {}                                     # версия наборов (ключ кэша списка)

    def changed(self, user: str) -> None:
        self.gen[user] = self.gen.get(user, 0) + 1

    def forget(self, user: str) -> None:
        for d in (self.hidden, self.groups, self.starred):
            d.pop(user, None)
        self.changed(user)


mine = _Mine()
_marks: dict[str, tuple[str, float]] = db.marks_load()      # на удаление (админ): путь -> (кто, когда)


def _hidden_all() -> dict[str, list[tuple[str, float]]]:
    """Скрытые у всех пользователей: путь -> [(кто, когда)] (для админа)."""
    out: dict[str, list[tuple[str, float]]] = {}
    for user, d in list(mine.hidden.items()):
        for path, at in list(d.items()):
            out.setdefault(path, []).append((user, at))
    return out


def _view_for(s: Session, hidden: int, starred: int):
    """Список пользователя: свои папки без его скрытых; hidden=1 — только его скрытые
    (админу — скрытые всех пользователей); starred=1 — только его избранное. Его группы — в списке."""
    u = s.user
    hid = frozenset(mine.hidden.get(u, ()))
    grp = mine.groups.get(u) or None
    key = (u, mine.gen.get(u, 0), "h" if hidden else "s" if starred else "m")
    if hidden:
        if s.role == "admin":  # type: ignore[attr-defined]
            # админ видит скрытое всеми; помеченное на удаление уже не показываем
            marks = frozenset(_marks)
            allh = frozenset(_hidden_all())
            key = (u, tuple(sorted(mine.gen.items())), "H", marks)
            return library.view(user_folders(s), only=allh - marks, groups=grp, key=key)
        return library.view(user_folders(s), only=hid, groups=grp, key=key)
    if starred:
        return library.view(user_folders(s), hide=hid, only=frozenset(mine.starred.get(u, ())), groups=grp, key=key)
    return library.view(user_folders(s), hide=hid, groups=grp, key=key)


@app.get("/api/library")
async def get_library(request: Request, hidden: int = 0, starred: int = 0, s: Session = Depends(require_user)):
    v = await run_in_threadpool(_view_for, s, hidden, starred)
    etag = f'"{v.version}"'
    headers = {"etag": etag, "cache-control": "private, no-cache", "vary": "cookie, accept-encoding"}
    if v.version and request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    if "gzip" in request.headers.get("accept-encoding", ""):
        headers["content-encoding"] = "gzip"
        return Response(v.gz, media_type="application/json", headers=headers)
    return Response(v.payload, media_type="application/json", headers=headers)


async def _targets(request: Request, s: Session, with_live: bool = True, extra: tuple = ()) -> tuple[list, dict]:
    """Файлы по id из тела запроса: только видимые пользователю; живое фото — вместе с роликом."""
    d = await read_json(request, limit=HIDE_MAX * 12 + 100)
    ids = d.get("ids")
    if not isinstance(ids, list) or not ids or len(ids) > HIDE_MAX or not all(isinstance(i, str) for i in ids):
        return [], d
    out = []
    for pid in dict.fromkeys(ids):
        p = library.get(pid)
        if not visible(s, p):
            continue                                  # чужое и несуществующее молча пропускаем
        out.append(p)
        q = library.get(p.live) if with_live and p.live else None
        if q is not None:
            out.append(q)
    return out, d


def _sample(ps) -> str:
    names = [p.rel for p in ps if not (p.video and p.live)]
    return ", ".join(names[:5]) + (f" и ещё {len(names) - 5}" if len(names) > 5 else "")


def _n(ps) -> int:
    return sum(1 for p in ps if not (p.video and p.live))


@app.post("/api/hide", dependencies=[Depends(require_csrf)])
async def hide_photos(request: Request, s: Session = Depends(require_user)):
    ps, _ = await _targets(request, s)
    if not ps:
        return _bad("нечего скрывать")

    def go() -> None:
        with mine.mu:
            db.hidden_put(s.user, [p.rel for p in ps])
            cur = dict(mine.hidden.get(s.user, {}))
            cur.update({p.rel: time.time() for p in ps})
            mine.hidden[s.user] = cur
            mine.changed(s.user)

    await run_in_threadpool(go)
    audit("hide", s.user, ip_of(request), f"{_n(ps)}: {_sample(ps)}")
    return no_store(JSONResponse({"ok": True, "count": _n(ps)}))


@app.post("/api/unhide", dependencies=[Depends(require_csrf)])
async def unhide_photos(request: Request, s: Session = Depends(require_user)):
    ps, _ = await _targets(request, s)
    if not ps:
        return _bad("нечего показывать")
    admin = s.role == "admin"  # type: ignore[attr-defined]

    def go() -> None:
        global _marks
        paths = [p.rel for p in ps]
        drop = set(paths)
        # админ возвращает в галерею у всех, кто это скрыл; пользователь — только у себя
        who = [w for w, d in list(mine.hidden.items()) if drop & d.keys()] if admin else [s.user]
        with mine.mu:
            for w in who:
                db.hidden_delete(w, paths)
                mine.hidden[w] = {k: v for k, v in mine.hidden.get(w, {}).items() if k not in drop}
                mine.changed(w)
        if admin:
            db.marks_delete(paths)                    # админ вернул в галерею — удалять уже не нужно
            _marks = db.marks_load()

    await run_in_threadpool(go)
    audit("unhide", s.user, ip_of(request), f"{_n(ps)}: {_sample(ps)}")
    return no_store(JSONResponse({"ok": True, "count": _n(ps)}))


# ---------------------------------------------------------------- пометка «удалить окончательно»
# Только админ и только то, что скрыто (у кого угодно — админ видит скрытые всех). С ПК пока ничего не удаляется: будущий клиент
# на ПК заберёт список, сам проверит (путь, размер, дата, хеш) и удалит. Вернуть фото
# в галерею или «Не удалять» — снять пометку.

@app.get("/api/marks")
async def marks_ids(s: Session = Depends(require_user)):
    """id помеченных на удаление (для значков на /hidden у админа)."""
    if s.role != "admin":  # type: ignore[attr-defined]
        return no_store(JSONResponse({"ids": []}))

    def ids() -> list[str]:
        out = []
        for rel in list(_marks):
            p = _by_rel(rel)
            if p is not None and not (p.video and p.live):
                out.append(p.id)
        return out
    return no_store(JSONResponse({"ids": await run_in_threadpool(ids)}))


@app.post("/api/marks", dependencies=[Depends(require_csrf)])
async def marks_set(request: Request, s: Session = Depends(require_admin)):
    ps, d = await _targets(request, s)
    on = d.get("on")
    if not isinstance(on, bool):
        return _bad("on: true/false")
    hid = _hidden_all()
    ps = [p for p in ps if p.rel in hid or (p.live and (q := library.get(p.live)) is not None and q.rel in hid)]
    if not ps:
        return _bad("пометить можно только скрытые фото")

    def go() -> None:
        global _marks
        if on:
            db.marks_put([(p.rel, p.cache_key(), db.hash_get(p.cache_key())) for p in ps], s.user)
        else:
            db.marks_delete([p.rel for p in ps])
        _marks = db.marks_load()

    await run_in_threadpool(go)
    audit("delete_mark" if on else "delete_unmark", s.user, ip_of(request), f"{_n(ps)}: {_sample(ps)}")
    return no_store(JSONResponse({"ok": True, "count": _n(ps)}))


# ---------------------------------------------------------------- клиент на ПК (удаление в корзину)
# Подробно о доверии — в pc.py: ключ в TPM, привязка через шару, сессии с HMAC, опасное — с подписью TPM.
pcauth = PcAuth(db)


class _PcViewer:
    """Для превью: клиент ПК видит помеченные файлы, как админ."""
    user, role, ip, created, last_seen = "клиент ПК", "admin", "", 0.0, 0.0


def _pc_fail(request: Request, what: str, e: Exception, code: int = 401) -> JSONResponse:
    ip = ip_of(request)
    if limiter.fail(ip):
        audit("lockout", "", ip, "клиент ПК: неверные подписи, блок 15 мин")
    audit("pc_denied", "", ip, f"{what}: {e}")
    return no_store(JSONResponse({"error": str(e)}, code))


async def require_pc(request: Request) -> dict:
    ip = ip_of(request)
    if wait := limiter.blocked(ip, global_cap=False):
        raise HTTPException(429, "locked", headers={"retry-after": str(wait)})
    cl = request.headers.get("content-length")
    if cl and (not cl.isdigit() or int(cl) > 512 * 1024):
        raise HTTPException(413)
    body = await request.body()
    q = request.scope.get("query_string", b"").decode("latin-1")
    h = request.headers
    try:
        sess = pcauth.check(h.get("x-pc-sid", ""), h.get("x-pc-ts", ""), h.get("x-pc-ctr", ""), h.get("x-pc-mac", ""),
                            request.method, request.url.path + ("?" + q if q else ""), body)
    except PcError as e:
        if str(e) != "session":                   # истёкшая сессия — обычное дело, не попытка подбора
            if limiter.fail(ip):
                audit("lockout", "", ip, "клиент ПК: неверные подписи, блок 15 мин")
            audit("pc_denied", "", ip, str(e))
        raise HTTPException(401, "pc " + str(e)) from None
    request.state.body = body
    return sess


def _pc_json(request: Request) -> dict:
    try:
        d = json.loads(request.state.body or b"{}")
    except ValueError:
        raise HTTPException(400) from None
    if not isinstance(d, dict):
        raise HTTPException(400)
    return d


@app.post("/api/pc/pair/start")
async def pc_pair_start(request: Request):
    ip = ip_of(request)
    if wait := limiter.blocked(ip, global_cap=False):
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429))
    d = await read_json(request)
    try:
        nonce = pcauth.pair_start(d.get("pub", ""), d.get("name", ""), d.get("key_type", ""))
    except PcError as e:
        return _pc_fail(request, "привязка", e, 403)
    return no_store(JSONResponse({"nonce": nonce, "file": pcauth.pair_file(nonce), "share": S.smb_share,
                                  "subdir": S.smb_subdir}))


@app.post("/api/pc/pair/finish")
async def pc_pair_finish(request: Request):
    ip = ip_of(request)
    if wait := limiter.blocked(ip, global_cap=False):
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429))
    d = await read_json(request)
    nonce = d.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise HTTPException(400)

    def read() -> bytes:
        with storage.open(pcauth.pair_file(nonce)) as f:
            return f.read(16384)
    try:
        content = await run_in_threadpool(read)
    except (OSError, ValueError) as e:
        log.info("файл привязки не прочитан: %s", e)
        return no_store(JSONResponse({"error": "сервер не нашёл файл привязки в шаре — проверь папку архива"}, 409))
    try:
        r = await run_in_threadpool(pcauth.pair_finish, nonce, content, ip)
    except PcError as e:
        return _pc_fail(request, "привязка", e, 403)
    audit("pc_pair", "", ip, f"ключ {r['fp']}")
    bg(ha.notify("lockout", f"Привязан клиент на ПК (ключ {r['fp']}) с {clean(ip)}", dedupe_s=0))
    return no_store(JSONResponse(r))


@app.post("/api/pc/session")
async def pc_session(request: Request):
    ip = ip_of(request)
    if wait := limiter.blocked(ip, global_cap=False):
        return no_store(JSONResponse({"error": "locked", "retry": wait}, 429))
    d = await read_json(request)
    try:
        r, alarms = await run_in_threadpool(pcauth.session, d.get("id", ""), d.get("eph", ""), d.get("ts"),
                                            d.get("guid", ""), d.get("sig", ""), ip)
    except PcError as e:
        return _pc_fail(request, "сессия", e)
    limiter.success(ip)
    if alarms["guid_changed"]:
        audit("pc_guid_changed", "", ip, "клиент ПК: другой MachineGuid — переустановка Windows или другой ПК?")
        bg(ha.notify("lockout", f"Клиент на ПК: изменился MachineGuid (с {clean(ip)})", dedupe_s=0))
    if alarms["ip_changed"]:
        audit("pc_ip_changed", "", ip, "клиент ПК вышел на связь с нового адреса")
    return no_store(JSONResponse(r))


def _pc_marks() -> list[dict]:
    out = []
    for path, key, sha, by, at in db.marks_rows():
        parts = key.split("\0")
        try:
            size, mtime = int(parts[1]), int(parts[2])
        except (IndexError, ValueError):
            size, mtime = -1, -1
        p = _by_rel(path)
        out.append({"path": path, "size": size, "mtime": mtime, "sha": sha, "by": by, "at": int(at),
                    "id": p.id if p is not None else None, "video": bool(p and p.video),
                    "live": bool(p and p.video and p.live)})
    return out


@app.get("/api/pc/marks")
async def pc_marks(_: dict = Depends(require_pc)):
    return no_store(JSONResponse({"items": await run_in_threadpool(_pc_marks), "share": S.smb_share,
                                  "subdir": S.smb_subdir}))


@app.get("/api/pc/preview/{pid}")
async def pc_preview(request: Request, pid: str = PathParam(pattern=ID_RE), _: dict = Depends(require_pc)):
    p = library.get(pid)
    if p is None or p.rel not in _marks:        # только помеченные — больше клиенту ничего не нужно
        raise HTTPException(404)
    kind = request.query_params.get("k", "m")
    if kind not in ("s", "m", "p"):
        raise HTTPException(400)
    return await rendered(request, kind, pid, _PcViewer())  # type: ignore[arg-type]


@app.post("/api/pc/unmark")
async def pc_unmark(request: Request, _: dict = Depends(require_pc)):
    paths = _pc_json(request).get("paths")
    if not isinstance(paths, list) or not all(isinstance(x, str) for x in paths) or len(paths) > 10000:
        raise HTTPException(400)
    paths = [x for x in paths if x in _marks]
    await run_in_threadpool(_pc_drop, paths, False)
    audit("delete_unmark", "клиент ПК", ip_of(request), f"{len(paths)}: {', '.join(paths[:3])}")
    return no_store(JSONResponse({"ok": True, "count": len(paths)}))


def _pc_drop(paths: list[str], unhide: bool) -> None:
    """Снять пометку «на удаление»; unhide — ещё и «скрыто» у всех, кто скрыл."""
    global _marks
    db.marks_delete(paths)
    _marks = db.marks_load()
    if not unhide:
        return
    drop = set(paths)
    with mine.mu:
        for w, hd in list(mine.hidden.items()):
            if drop & hd.keys():
                db.hidden_delete(w, paths)
                mine.hidden[w] = {k: v for k, v in hd.items() if k not in drop}
                mine.changed(w)


@app.post("/api/pc/restore")
async def pc_restore(request: Request, _: dict = Depends(require_pc)):
    """«Вернуть в галерею»: снять пометку и «скрыто» у всех — фото снова в ленте."""
    paths = _pc_json(request).get("paths")
    if not isinstance(paths, list) or not all(isinstance(x, str) for x in paths) or len(paths) > 10000:
        raise HTTPException(400)
    paths = [x for x in paths if x in _marks]
    await run_in_threadpool(_pc_drop, paths, True)
    audit("unhide", "клиент ПК", ip_of(request), f"с пометкой на удаление, {len(paths)}: {', '.join(paths[:3])}")
    return no_store(JSONResponse({"ok": True, "count": len(paths)}))


@app.post("/api/pc/deleted")
async def pc_deleted(request: Request, sess: dict = Depends(require_pc)):
    """Отчёт клиента: эти файлы ушли в корзину на ПК. Снимает пометки и «скрыто» —
    только с подписью ключом TPM над точным списком."""
    d = _pc_json(request)
    items, ts, sig = d.get("items"), d.get("ts"), d.get("sig", "")
    if not isinstance(items, list) or not items or len(items) > 10000 or not isinstance(ts, int) \
            or not all(isinstance(i, dict) and isinstance(i.get("path"), str) for i in items):
        raise HTTPException(400)
    if abs(time.time() - ts) > 300:
        return no_store(JSONResponse({"error": "устаревшая подпись"}, 400))
    try:
        pcauth.verify_op(delete_message(sess["sid"], ts, items), sig)
    except PcError as e:
        return _pc_fail(request, "удаление", e, 403)
    paths = [i["path"] for i in items if i["path"] in _marks]
    await run_in_threadpool(_pc_drop, paths, True)
    audit("pc_deleted", "клиент ПК", ip_of(request), f"в корзину на ПК: {len(paths)}: {', '.join(paths[:3])}")
    if paths:
        library.start_build(storage, _index_error)   # файлов больше нет — пересобрать список
    return no_store(JSONResponse({"ok": True, "count": len(paths)}))


# ---------------------------------------------------------------- группы (стопки)
# У каждого свои: в ленте — одна обложка (первое выбранное), по нажатию группа раскрывается.

@app.post("/api/group", dependencies=[Depends(require_csrf)])
async def group_photos(request: Request, s: Session = Depends(require_user)):
    """ids — по порядку в ленте: первый станет обложкой."""
    ps, _ = await _targets(request, s, with_live=False)
    ps = [p for p in ps if not (p.video and p.live)]
    if len(ps) < 2:
        return _bad("в группе нужно хотя бы два фото")
    gid = secrets.token_hex(4)

    def go() -> None:
        with mine.mu:
            db.groups_set(s.user, gid, [p.rel for p in ps], ps[0].rel)
            mine.groups[s.user] = db.groups_load().get(s.user, {})
            mine.changed(s.user)

    await run_in_threadpool(go)
    audit("group", s.user, ip_of(request), f"{len(ps)}: {_sample(ps)}")
    return no_store(JSONResponse({"ok": True, "count": len(ps), "gid": gid}))


@app.post("/api/ungroup", dependencies=[Depends(require_csrf)])
async def ungroup_photos(request: Request, s: Session = Depends(require_user)):
    """Разобрать свои группы, в которые входят эти файлы (целиком)."""
    ps, _ = await _targets(request, s, with_live=False)
    g = mine.groups.get(s.user, {})
    gids = sorted({g[p.rel][0] for p in ps if p.rel in g})
    if not gids:
        return _bad("эти фото не в группе")

    def go() -> None:
        with mine.mu:
            db.groups_drop(s.user, gids)
            mine.groups[s.user] = db.groups_load().get(s.user, {})
            mine.changed(s.user)

    await run_in_threadpool(go)
    audit("ungroup", s.user, ip_of(request), f"групп: {len(gids)}")
    return no_store(JSONResponse({"ok": True, "groups": len(gids)}))


# ---------------------------------------------------------------- избранное

@app.get("/api/starred")
async def starred_ids(s: Session = Depends(require_user)):
    """id избранных файлов пользователя (чтобы рисовать звёздочки в ленте и в просмотре)."""
    def ids() -> list[str]:
        out = []
        for rel in list(mine.starred.get(s.user, ())):
            p = _by_rel(rel)
            if p is not None and visible(s, p):
                out.append(p.id)
        return out
    return no_store(JSONResponse({"ids": await run_in_threadpool(ids)}))


@app.post("/api/star", dependencies=[Depends(require_csrf)])
async def star_photos(request: Request, s: Session = Depends(require_user)):
    ps, d = await _targets(request, s, with_live=False)
    on = d.get("on")
    if not isinstance(on, bool):
        return _bad("on: true/false")
    paths = [p.rel for p in ps]
    if not paths:
        return _bad("нечего отмечать")

    def go() -> None:
        with mine.mu:
            (db.starred_put if on else db.starred_delete)(s.user, paths)
            cur = set(mine.starred.get(s.user, ()))
            if on:
                cur.update(paths)
            else:
                cur.difference_update(paths)
            mine.starred[s.user] = cur
            mine.changed(s.user)

    await run_in_threadpool(go)
    return no_store(JSONResponse({"ok": True, "count": len(paths)}))


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


async def _offline_thumbnail(p, kind: str) -> Response | None:
    """Без ПК используем сохранённый меньший эскиз, если крупного нет.

    Не кэшируем ответ как полноценный t/m: после включения ПК нормальное
    разрешение снова доступно по тому же URL.
    """
    if kind not in ("t", "m"):
        return None
    kinds = ("t", "s") if kind == "m" else ("s",)
    for smaller in kinds:
        key = (smaller, p.id, p.mtime, p.size)
        data = thumb_cache.get(key)
        if data is None:
            try:
                if p.video:
                    if smaller != "s":
                        continue
                    data = await run_in_threadpool(db.vthumb_get, p.cache_key(), S.image_format)
                else:
                    data = await run_in_threadpool(pthumbs.get, p.cache_key(), _pkind(smaller))
            except Exception as e:  # noqa: BLE001
                log.warning("офлайн-эскиз не читается (%s)", type(e).__name__)
                continue
        if data is not None:
            return Response(data, media_type="image/webp" if S.image_format == "webp" else "image/jpeg",
                            headers={"cache-control": "private, no-store",
                                     "x-photocloud-fallback": smaller})
    return None


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
    # в базе хранятся: самый маленький эскиз видео и эскизы фото 240 и 400 — посчитали раз,
    # дальше сразу (и без ПК). Порядок: память сервера -> база на диске -> делаем с ПК.
    vkeep = p.video and kind == "s"
    pkind = _pkind(kind) if not p.video and kind in "st" else None
    if (vkeep or pkind) and cache.get(key) is None:
        try:
            stored = await run_in_threadpool(db.vthumb_get, p.cache_key(), S.image_format) if vkeep else \
                await run_in_threadpool(pthumbs.get, p.cache_key(), pkind)
        except Exception as e:  # noqa: BLE001 — нет базы — сделаем с ПК
            log.warning("эскизы в базе: не читаются (%s)", e)
            stored = None
        if stored is not None:
            cache.put(key, stored)
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
                # Крупный эскиз может отсутствовать, но маленький уже сохранён.
                fallback = await _offline_thumbnail(p, kind)
                if fallback is not None:
                    return fallback
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
                    # ПК выключился в очереди: обработчик ConnectionError отдаст
                    # сохранённый маленький эскиз, если он есть.
                    lane.release()
                    raise ConnectionError("pc down")
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
                try:
                    if vkeep:
                        await run_in_threadpool(db.vthumb_put, p.cache_key(), S.image_format, data)
                    elif pkind:
                        await run_in_threadpool(pthumbs.put, p.cache_key(), pkind, data)
                except Exception as e:  # noqa: BLE001 — эскиз уже есть, не сохранился — сделаем в другой раз
                    log.warning("эскизы в базе: не записался (%s)", e)
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
        fallback = await _offline_thumbnail(p, kind)
        if fallback is not None:
            return fallback
        raise HTTPException(503, "pc") from None
    except video.NoVideo:
        # только звук: в ленте такого файла больше не будет
        if await run_in_threadpool(library.mark_audio, p):
            log.info("%s — только звук, убираю из ленты", p.rel)
        raise HTTPException(404, "audio") from None
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
library.thumbstore = pthumbs               # после сканирования — убрать эскизы пропавших файлов
library.snapshot = S.data_dir / "index.json.gz"   # последний список — показать после перезапуска без ПК


# ---- эскизы фото в базе (240 и 400): при просмотре — сами, «Посчитать эскизы фото» — все заранее

def _pkind(kind: str) -> str:
    """Вид эскиза фото в базе: формат:размер:качество — сменили настройки, старые не подходят."""
    box = S.thumb_small_size if kind == "s" else S.thumb_size
    return f"{S.image_format}:{box}:{S.thumb_quality}"


class PT:
    state = ""          # "" | running | stopped | done | pc
    done = total = made = failed = 0
    stop = threading.Event()
    thread: threading.Thread | None = None


def _pthumbs_run() -> None:
    ks, kt = _pkind("s"), _pkind("t")
    try:
        have_s, have_t = pthumbs.keys(ks), pthumbs.keys(kt)
    except Exception as e:  # noqa: BLE001
        log.warning("эскизы фото: база недоступна (%s)", e)
        PT.state = ""
        return
    todo = sorted((p for p in library.by_id.values() if not p.video
                   and not (p.cache_key() in have_s and p.cache_key() in have_t)), key=lambda p: p.date, reverse=True)
    PT.done, PT.total, PT.made, PT.failed, PT.state = 0, len(todo), 0, 0, "running"
    log.info("эскизы фото: считаю %d", len(todo))
    t0 = time.time()
    for p in todo:
        if PT.stop.is_set():
            PT.state = "stopped"
            break
        k = p.cache_key()
        try:
            # файл с ПК читается один раз: 400 — из оригинала (или встроенного эскиза), 240 — из 400
            t = pthumbs.get(k, kt) if k in have_t else None
            if t is None:
                t = _produce(p, S.thumb_size, S.thumb_quality, {})
                pthumbs.put(k, kt, t)
            thumb_cache.put(("t", p.id, p.mtime, p.size), t)
            if k not in have_s:
                sm = render(t, S.thumb_small_size, S.thumb_quality, S.image_format)
                pthumbs.put(k, ks, sm)
                thumb_cache.put(("s", p.id, p.mtime, p.size), sm)
            PT.made += 1
        except (ConnectionError, TimeoutError):
            PT.state = "pc"                           # ПК выключился — продолжим по кнопке
            break
        except Exception:  # noqa: BLE001 — битое фото: не сохраняем, в другой раз попробуем снова
            PT.failed += 1
        PT.done += 1
    else:
        PT.state = "done"
    pthumbs.fresh()
    log.info("эскизы фото: готово %d из %d за %.0fс, не вышло %d", PT.made, PT.total, time.time() - t0, PT.failed)


def _pt_running() -> bool:
    return PT.thread is not None and PT.thread.is_alive()


@app.post("/api/admin/pthumbs/start", dependencies=[Depends(require_csrf)])
async def admin_pthumbs_start(request: Request, s: Session = Depends(require_admin)):
    if _pt_running():
        return no_store(JSONResponse({"ok": True, "running": True}))
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    PT.stop.clear()
    # «meta…» — фоновый поток: чтение с ПК уступает эскизам и просмотру
    PT.thread = threading.Thread(target=_pthumbs_run, name="meta-pthumbs", daemon=True)
    PT.thread.start()
    audit("pthumbs", s.user, ip_of(request), "запущен подсчёт эскизов фото")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/pthumbs/stop", dependencies=[Depends(require_csrf)])
async def admin_pthumbs_stop(_: Session = Depends(require_admin)):
    PT.stop.set()
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/pthumbs/clear", dependencies=[Depends(require_csrf)])
async def admin_pthumbs_clear(request: Request, s: Session = Depends(require_admin)):
    """Удалить все эскизы фото из базы (видео не трогаем)."""
    if _pt_running():
        return _bad("идёт подсчёт эскизов фото — сначала останови его", 409)
    _, size = await run_in_threadpool(pthumbs.stats, (_pkind("s"), _pkind("t")))
    await run_in_threadpool(pthumbs.clear)
    thumb_cache.clear()                     # и из памяти: эскизы видео вернутся из базы
    PT.state = ""
    audit("pthumbs_clear", s.user, ip_of(request), f"удалено {size // 1048576} МБ")
    return no_store(JSONResponse({"ok": True}))


# ---- эскизы видео в базе: «Посчитать эскизы видео» — все, которых ещё нет (по одному, в фоне)

class VT:
    state = ""          # "" | running | stopped | done | pc
    done = total = made = failed = audio = 0
    stop = threading.Event()
    thread: threading.Thread | None = None


def _vthumbs_run() -> None:
    fmt, box = S.image_format, S.thumb_small_size
    try:
        have = db.vthumb_keys(fmt) | db.vthumb_keys("audio")
    except Exception as e:  # noqa: BLE001
        log.warning("эскизы видео: база недоступна (%s)", e)
        VT.state = ""
        return
    todo = [p for p in library.by_id.values() if p.video and not p.live and p.cache_key() not in have]
    VT.done, VT.total, VT.made, VT.failed, VT.audio, VT.state = 0, len(todo), 0, 0, 0, "running"
    log.info("эскизы видео: считаю %d", len(todo))
    t0 = time.time()
    for p in todo:
        if VT.stop.is_set():
            VT.state = "stopped"
            break
        try:
            data = _produce(p, box, S.thumb_quality, {})
            db.vthumb_put(p.cache_key(), fmt, data)
            thumb_cache.put(("s", p.id, p.mtime, p.size), data)
            VT.made += 1
        except video.NoVideo:
            if library.mark_audio(p):
                VT.audio += 1
        except (ConnectionError, TimeoutError):
            VT.state = "pc"                           # ПК выключился — продолжим по кнопке
            break
        except Exception:  # noqa: BLE001 — битое видео: пропускаем
            VT.failed += 1
        VT.done += 1
    else:
        VT.state = "done"
    log.info("эскизы видео: готово %d из %d за %.0fс, не вышло %d, только звук %d", VT.made, VT.total,
             time.time() - t0, VT.failed, VT.audio)


@app.post("/api/admin/vthumbs/start", dependencies=[Depends(require_csrf)])
async def admin_vthumbs_start(request: Request, s: Session = Depends(require_admin)):
    if VT.thread is not None and VT.thread.is_alive():
        return no_store(JSONResponse({"ok": True, "running": True}))
    if not FFMPEG:
        return _bad("нет ffmpeg")
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    VT.stop.clear()
    # «meta…» — фоновый поток: чтение с ПК уступает эскизам и просмотру
    VT.thread = threading.Thread(target=_vthumbs_run, name="meta-vthumbs", daemon=True)
    VT.thread.start()
    audit("vthumbs", s.user, ip_of(request), "запущен подсчёт эскизов видео")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/vthumbs/stop", dependencies=[Depends(require_csrf)])
async def admin_vthumbs_stop(_: Session = Depends(require_admin)):
    VT.stop.set()
    return no_store(JSONResponse({"ok": True}))


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
    p = library.get(pid)
    hid = mine.hidden.get(s.user, {}).get(p.rel) if p is not None else None
    if hid:                                           # на странице скрытых: когда скрыл
        out["hidden_at"] = int(hid)
    if p is not None and s.role == "admin":  # type: ignore[attr-defined]
        by = sorted(((w, at) for w, d in list(mine.hidden.items()) if (at := d.get(p.rel))), key=lambda x: x[1])
        if by:                                        # админу — кто и когда скрыл
            out["hidden_by"] = [{"user": w, "at": int(at)} for w, at in by]
    mk = _marks.get(p.rel) if p is not None and s.role == "admin" else None  # type: ignore[attr-defined]
    if mk:
        out["delete_by"], out["delete_at"] = mk[0], int(mk[1])
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

_hash_one = threading.Lock()


def _backup_copying() -> bool:
    """Какой-то клиент бэкапа сейчас качает файлы (свежий отчёт «копирует»)."""
    now = time.time()
    return any(t.report.get("state") == "copying" and now - t.report.get("at", 0) < 30 for t in tokens.all())


HASH_READ = 4 * 1024 * 1024      # кусок чтения для хеша: меньше запросов «вопрос — ответ» по сети


def _hash_file(p, stop) -> str | None:
    """Хеш файла. Пока клиент бэкапа качает, хеши считаются по одному файлу, а не в несколько
    потоков: диск ПК отдаёт и то и другое, и при нескольких потоках чтения отдача клиенту подвисала."""
    if _backup_copying():
        with _hash_one:
            return _hash_read(p, stop)
    return _hash_read(p, stop)


def _hash_read(p, stop) -> str | None:
    h = hashlib.sha256()
    try:
        with storage.open(p.rel) as f:
            while True:
                if stop.is_set():
                    return None
                b = f.read(HASH_READ)
                if not b:
                    break
                h.update(b)
                library.io.add(len(b))
    except Exception as e:  # noqa: BLE001
        if is_read_error(e):
            good = db.hash_get(p.cache_key())
            if good:                                # был правильный хеш — значит, файл испортился на ПК
                _damaged_found(p, good, "")
        raise
    return h.hexdigest()


library.hash_reader = _hash_file

VERIFY_EVERY = 30 * 86400        # полная сверка хешей с файлами — раз в 30 дней
_verify_checked = 0.0


def _hash_mismatch(p, old: str, new: str) -> None:
    _damaged_found(p, old, new)


library.on_mismatch = _hash_mismatch


# ---------------------------------------------------------------- повреждённые файлы на ПК
# Хеш не совпал при тех же размере и дате (или файл не читается) — похоже на порчу диска.
# Правильным остаётся прежний хеш: клиенты бэкапа испорченное не скачивают, а клиент с правильной
# копией присылает её, и сервер кладёт её в Restored\<тот же путь> (оригинал не трогает).
# Ты переносишь копию на место оригинала — сервер видит правильный хеш и закрывает запись.
restorer = RestoreWriter(S, storage)
DAMAGE_TEXT = {"found": "ждёт копию от клиента бэкапа", "nosource": "правильной копии нет ни у одного клиента (спросит и у новых)",
               "restored": "копия лежит в Restored — перенеси её на место оригинала",
               "lost": "копию из Restored удалили, а оригинал не исправлен",
               "fixed": "исправлен", "accepted": "принят как новая версия", "changed": "файл изменён на сервере",
               "gone": "файл удалён на ПК"}
_dmg_mu = threading.Lock()


def _bump_list() -> None:
    db.kv_set("hash_gen", int(db.kv_get("hash_gen") or 0) + 1)       # клиентам — свежий список


def _notify(event: str, text: str) -> None:
    try:
        loop.call_soon_threadsafe(bg, ha.notify(event, text, dedupe_s=0))
    except RuntimeError:
        pass


def _damaged_found(p, good: str, bad: str) -> None:
    with _dmg_mu:
        cur = db.damaged_get(p.rel)
        if cur and cur["state"] in db.ACTIVE and cur["key"] == p.cache_key():
            return                                    # уже знаем
        now = time.time()
        _nosource_set(p.rel, None)
        db.damaged_put({"path": p.rel, "key": p.cache_key(), "size": p.size, "mtime": int(p.mtime),
                        "sha_good": good, "sha_bad": bad, "found": now, "updated": now,
                        "state": "found", "restored": "", "note": "" if restorer.enabled else
                        "запись на ПК не настроена (SMB_RESTORE_USER)"})
        _bump_list()
    what = "не читается" if not bad else "изменился без смены размера и даты"
    log.warning("повреждённый файл на сервере: %s — %s", p.rel, what)
    audit("damaged_found", "", "", f"{p.rel}: {what}")
    _notify("damaged", f"Файл на сервере испорчен ({what}): «{clean(p.rel, 120)}». "
                       f"Правильная копия будет восстановлена из бэкапа в папку {RESTORED}.")


def _damaged_state(path: str, state: str, note: str = "", restored: str | None = None) -> dict | None:
    with _dmg_mu:
        d = db.damaged_get(path)
        if d is None:
            return None
        d.update(state=state, note=note, updated=time.time())
        if restored is not None:
            d["restored"] = restored
        db.damaged_put(d)
        if state not in ("found", "nosource"):       # недокачанная копия больше не нужна
            (RESTORE_TMP / (d["sha_good"] + ".part")).unlink(missing_ok=True)
        _bump_list()
        return d


# Какие клиенты уже ответили «правильной копии нет»: {путь: [id токенов]} — у остальных
# спрашиваем дальше (и у новых клиентов тоже). Сбрасывается, когда файл заново помечен испорченным
# или админ нажал «восстановить заново».
def _nosource_load() -> dict:
    try:
        v = json.loads(db.kv_get("restore_nosource") or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def _nosource_set(path: str, ids: list | None) -> None:
    v = _nosource_load()
    if ids:
        v[path] = sorted(set(ids))
    else:
        v.pop(path, None)
    db.kv_set("restore_nosource", json.dumps(v, ensure_ascii=False))


def _damaged_paths() -> set[str]:
    return {d["path"] for d in db.damaged_list(active_only=True)}


_dmg_checked = 0.0


def _damaged_check(force: bool = False) -> None:
    """После каждого сканирования (и не чаще раза в час для пересчёта хешей): удалён ли файл,
    изменён ли, перенесли ли восстановленную копию на место оригинала."""
    global _dmg_checked
    items = db.damaged_list(active_only=True)
    if not items:
        return
    hash_now = force or time.time() - _dmg_checked > 3600
    if hash_now:
        _dmg_checked = time.time()
    for d in items:
        p = _by_rel(d["path"])
        if p is None:
            _damaged_state(d["path"], "gone", "файла больше нет на сервере")
            audit("damaged_gone", "", "", d["path"])
            continue
        if p.cache_key() != d["key"]:
            # размер или дата другие: либо на место оригинала перенесли восстановленную копию
            # (дата могла не сохраниться), либо файл изменили — смотрим по хешу
            try:
                sha = _hash_read(p, threading.Event()) if p.size == d["size"] else None
            except Exception:  # noqa: BLE001
                continue
            if sha == d["sha_good"]:
                _damaged_state(d["path"], "fixed", "у оригинала снова правильный хеш")
                audit("damaged_fixed", "", "", d["path"])
                _notify("damaged", f"Файл на сервере исправлен: «{clean(d['path'], 120)}».")
            else:
                _damaged_state(d["path"], "changed", "файл изменён на сервере (другой размер или дата)")
                audit("damaged_changed", "", "", d["path"])
            continue
        restored_left = True
        if d["state"] == "restored" and d["restored"]:
            try:
                storage.open(RESTORED + "/" + d["restored"]).close()
            except Exception as e:  # noqa: BLE001
                restored_left = not is_missing(e)
        if not (hash_now or not restored_left):
            continue
        try:
            sha = _hash_read(p, threading.Event())
        except Exception:  # noqa: BLE001
            continue
        if sha == d["sha_good"]:
            _damaged_state(d["path"], "fixed", "у оригинала снова правильный хеш")
            log.info("повреждённый файл исправлен: %s", d["path"])
            audit("damaged_fixed", "", "", d["path"])
            _notify("damaged", f"Файл на сервере исправлен: «{clean(d['path'], 120)}».")
        elif d["state"] == "restored" and not restored_left:
            _damaged_state(d["path"], "lost", "копию из Restored удалили, а оригинал всё ещё испорчен")
            audit("damaged_lost", "", "", d["path"])
            _notify("damaged", f"Копию «{clean(d['path'], 120)}» удалили из {RESTORED}, а оригинал испорчен. "
                               f"Восстановить заново — в админке.")


def _after_scan() -> None:
    threading.Thread(target=lambda: _safe(_damaged_check), name="meta-damaged", daemon=True).start()


def _safe(fn, *a) -> None:
    try:
        fn(*a)
    except Exception:  # noqa: BLE001
        log.exception("проверка повреждённых файлов")


library.on_built = _after_scan


def _speed_eta(left_bytes: int) -> dict:
    """Скорость чтения (байт/с, за последнюю минуту) и сколько осталось секунд."""
    sp = library.io.speed()
    return {"speed": int(sp), "eta": int(left_bytes / sp) if sp > 0 else 0}


def _verify_info() -> dict:
    last, since = db.kv_get("verify_last"), db.kv_get("verify_since")
    out = {"state": library.verify_state, "done": library.verify_done, "total": library.verify_total,
           "bytes_done": library.verify_bytes_done, "bytes_total": library.verify_bytes_total,
           "bad": library.verify_bad if library.verify_state else int(db.kv_get("verify_last_bad") or 0),
           "last": int(float(last)) if last else 0,
           "since": int(float(since)) if since else 0, "paused": db.kv_get("verify_paused") == "1",
           "next": int(float(last)) + VERIFY_EVERY if last else 0, "pc": PC.up, "speed": 0, "eta": 0}
    if library.verify_state == "running":
        out.update(_speed_eta(library.verify_bytes_total - library.verify_bytes_done))
    elif since and library.verify_state != "done":
        # остановлена или прервана (в т.ч. перезапуском сервера): сколько уже сверено в этом цикле
        out["done"], out["total"] = db.hashes_checked_count(float(since))
    return out


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
    out = {"state": library.hash_state, "done": library.hash_done, "total": library.hash_total,
           "bytes_done": library.hash_bytes_done, "bytes_total": library.hash_bytes_total, "speed": 0, "eta": 0}
    if library.hash_state == "running":
        out.update(_speed_eta(library.hash_bytes_total - library.hash_bytes_done))
    return out


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
    # у клиента бэкапа токен, а не пароль: общий потолок неудач на него не действует
    wait = limiter.blocked(ip, global_cap=False)
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
    if time.time() - t.last_seen > 60:
        limiter.success(ip)
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
        "restore": (len(await run_in_threadpool(_restore_requests, t)) if restorer.enabled else 0),
    }))


@app.post("/api/backup/wake")
async def backup_wake(t=Depends(require_backup)):
    return await _wake(t.user, f"Бэкап «{clean(t.name, 40)}» будит компьютер", f"бэкап «{t.name}»")


@app.get("/api/backup/manifest")
async def backup_manifest(request: Request, damaged: int = 0, t=Depends(require_backup)):
    """Все видимые токену файлы: [путь, размер, mtime, дата снимка, sha256 | null].

    Испорченные на сервере файлы качать нельзя. Клиент 1.4+ (?damaged=1) получает их пути
    отдельным списком «damaged» и сам присылает правильную копию. Старым клиентам у таких файлов
    вместо хеша — null («хеш ещё считается»): свою копию они не трогают и порчу не качают."""
    access = _token_access(t)
    # клиенты спрашивают раз в 10 с: «ничего не поменялось» отвечаем без чтения всех хешей
    n_hashes = await run_in_threadpool(db.hashes_count)
    gen = await run_in_threadpool(db.kv_get, "hash_gen")       # растёт, когда проверка нашла изменённый файл
    ver = library.version
    modern = damaged == 1
    tag = hashlib.blake2b(f"{ver}|{n_hashes}|{gen}|{access!r}|{library.skipped}|{int(modern)}".encode(),
                          digest_size=10).hexdigest()
    etag = f'"{tag}"'
    if ver and request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"etag": etag, "cache-control": "no-store"})
    hashes = await run_in_threadpool(db.hashes_load)
    bad_all = await run_in_threadpool(_damaged_paths)

    def build() -> bytes:
        files, bad = [], []
        for p in library.by_id.values():
            if not folder_ok(p.rel, access):
                continue
            sha = hashes.get(p.cache_key())          # у испорченного — прежний, правильный хеш
            if p.rel in bad_all:
                bad.append(p.rel)
                if not modern:
                    sha = None
            files.append([p.rel, p.size, int(p.mtime), int(p.date), sha])
        out = {"v": tag, "index_version": ver,
               "complete": bool(ver) and library.state == "ready" and not library.skipped and not library.error,
               "files": files}
        if modern:
            out["damaged"] = sorted(bad)
        return json.dumps(out,
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
    if await run_in_threadpool(lambda: p.rel in _damaged_paths()):
        raise HTTPException(409, "damaged")          # испорчен на сервере: отдавать порчу незачем
    if z == 1:                                        # клиент 1.1+: сжатие блоками
        return await _framed(p, max(0, start))
    return await serve_file(request, p, {"cache-control": "no-store",
                                         "content-disposition": "attachment",
                                         "x-file-size": str(p.size), "x-file-mtime": str(int(p.mtime))})


_REPORT_NUM = ("files", "bytes", "copied", "copied_bytes", "left_files", "left_bytes", "moved",
               "versions", "deleted", "errors", "pending_delete", "speed", "cur_done", "cur_size",
               "wire_bytes", "raw_bytes", "limit_mbps", "stall", "verify_last", "verify_done", "verify_total", "verify_bad")


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


# ---- восстановление повреждённых файлов: клиент присылает правильную копию

RESTORE_CHUNK = 8 * 1024 * 1024             # кусок загрузки (лимит NPM — не меньше 9 МБ)
RESTORE_TMP = S.data_dir / "restore"


def _restore_requests(t) -> list[dict]:
    """Что просим у этого клиента: испорченные файлы из его папок, про которые он ещё не сказал
    «копии нет» (пока ни у кого копии не нашлось — спрашиваем и новых клиентов)."""
    access = _token_access(t)
    asked = _nosource_load()
    return [d for d in db.damaged_list(active_only=True)
            if d["state"] in ("found", "nosource") and t.id not in asked.get(d["path"], ())
            and d["path"] not in _writing and folder_ok(d["path"], access) and _by_rel(d["path"]) is not None]


def _restore_item(t, path: str) -> dict:
    if not restorer.enabled:
        raise HTTPException(503, "restore off")
    d = db.damaged_get(path) if 0 < len(path) <= 2000 else None
    if d is None or d["state"] not in ("found", "nosource") or not folder_ok(path, _token_access(t)):
        raise HTTPException(404)
    p = _by_rel(path)
    if p is None or p.cache_key() != d["key"]:
        raise HTTPException(409, "changed")
    return d


def _part_path(d: dict) -> Path:
    return RESTORE_TMP / (d["sha_good"] + ".part")


@app.get("/api/backup/restore")
async def backup_restore_list(t=Depends(require_backup)):
    """Что нужно восстановить: файлы, испорченные на ПК, — с правильным хешем."""
    items = await run_in_threadpool(_restore_requests, t) if restorer.enabled else []
    out = []
    for d in items:
        part = _part_path(d)
        out.append({"path": d["path"], "sha": d["sha_good"], "size": d["size"], "mtime": d["mtime"],
                    "received": part.stat().st_size if part.exists() else 0})
    return no_store(JSONResponse({"items": out, "chunk": RESTORE_CHUNK}))


@app.put("/api/backup/restore")
async def backup_restore_put(request: Request, path: str = "", offset: int = -1, t=Depends(require_backup)):
    """Кусок правильной копии. Принимается только для файла, который сервер сам пометил
    испорченным, только по порядку и не больше записанного размера; целиком — только если
    хеш равен правильному. Путь записи на ПК берётся из базы, не от клиента."""
    d = await run_in_threadpool(_restore_item, t, path)
    part = _part_path(d)
    have = part.stat().st_size if part.exists() else 0
    if offset != have:
        return no_store(JSONResponse({"received": have, "error": "offset"}, 409))
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > RESTORE_CHUNK or have + len(body) > d["size"]:
            raise HTTPException(413)
    if not body and have < d["size"]:
        raise HTTPException(400)
    RESTORE_TMP.mkdir(parents=True, exist_ok=True)

    def append() -> int:
        with open(part, "ab") as f:
            f.write(body)
        return part.stat().st_size

    if body:
        have = await run_in_threadpool(append)
    if have < d["size"]:
        return no_store(JSONResponse({"received": have, "done": False}))
    # файл получен целиком (или был получен раньше, а запись на ПК тогда не удалась) — проверяем и пишем

    def sha_part() -> str:
        h = hashlib.sha256()
        with open(part, "rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""):
                h.update(b)
        return h.hexdigest()

    if await run_in_threadpool(sha_part) != d["sha_good"]:
        part.unlink(missing_ok=True)
        audit("restore_bad", t.user, ip_of(request), f"{path}: хеш присланной копии не совпал")
        return no_store(JSONResponse({"received": 0, "error": "hash"}, 422))
    if not await PC.is_up():
        return no_store(JSONResponse({"received": have, "error": "pc"}, 503))
    # запись на ПК (и перечитывание для проверки) у большого видео — минуты: делаем в фоне,
    # клиенту отвечаем сразу — иначе прокси оборвёт ожидание по тайм-ауту
    if path not in _writing:
        _writing.add(path)
        bg(_restore_write(path, part, d, t.name, t.user, ip_of(request)))
    return no_store(JSONResponse({"received": have, "done": True, "writing": True}))


_writing: set[str] = set()


async def _restore_write(path: str, part: Path, d: dict, client: str, user: str, ip: str) -> None:
    try:
        where = await on_pc(restorer.write, path, part, float(d["mtime"]), d["sha_good"],
                            timeout=max(120, d["size"] / (5 * 1024 * 1024)))
    except Exception as e:  # noqa: BLE001
        log.warning("восстановление %s: запись на ПК не удалась: %s", path, e)
        await run_in_threadpool(_damaged_state, path, "found", f"запись в Restored не удалась: {type(e).__name__}")
        return
    finally:
        _writing.discard(path)
    part.unlink(missing_ok=True)
    await run_in_threadpool(_damaged_state, path, "restored", "", where)
    log.info("восстановлен %s → %s/%s (копия от «%s»)", path, RESTORED, where, client)
    audit("damaged_restored", user, ip, f"{path} → {RESTORED}/{where}, копия от «{client}»")
    _notify("damaged", f"Восстановлена правильная копия «{clean(path, 120)}» → {RESTORED}\\{clean(where, 120)}. "
                       f"Перенеси её на место оригинала с заменой.")


@app.post("/api/backup/restore/nosource")
async def backup_restore_nosource(request: Request, path: str = "", t=Depends(require_backup)):
    """У клиента нет правильной копии (или она не сходится по хешу)."""
    d = await run_in_threadpool(_restore_item, t, path)

    def mark() -> None:
        with _dmg_mu:
            ids = set(_nosource_load().get(d["path"], ())) | {t.id}
            _nosource_set(d["path"], list(ids))
            can = [x for x in tokens.all() if folder_ok(d["path"], _token_access(x))]
            left = [x for x in can if x.id not in ids]
            said = ", ".join(f"«{x.name}»" for x in can if x.id in ids)
        if left:      # другие клиенты ещё могут прислать копию: ждём их, их недокачанное не трогаем
            _damaged_state(d["path"], d["state"], f"нет правильной копии у {said}; ждёт остальных клиентов")
        else:
            _damaged_state(d["path"], "nosource", f"нет правильной копии у {said}")

    await run_in_threadpool(mark)
    audit("damaged_nosource", t.user, ip_of(request), f"{path}: у «{t.name}» нет правильной копии")
    return no_store(JSONResponse({"ok": True}))


# ---- админка: повреждённые файлы

DAMAGED_KEEP = 86400       # с: закрытые записи (исправлен, принят…) видны в админке сутки — история есть в журнале


@app.get("/api/admin/damaged")
async def admin_damaged(_: Session = Depends(require_admin)):
    await run_in_threadpool(db.damaged_prune, time.time() - DAMAGED_KEEP)
    items = await run_in_threadpool(db.damaged_list)
    for d in items:
        d["text"] = DAMAGE_TEXT.get(d["state"], d["state"])
        d["unreadable"] = not d["sha_bad"]
    return no_store(JSONResponse({"items": items, "restore": restorer.enabled, "folder": RESTORED}))


@app.post("/api/admin/damaged/accept", dependencies=[Depends(require_csrf)])
async def admin_damaged_accept(request: Request, s: Session = Depends(require_admin)):
    """«Это не порча»: файл изменили намеренно (программа сохранила дату) — новая версия
    становится правильной, клиенты скачают её, а старую уберут в «Версии»."""
    path = (await read_json(request)).get("path")
    d = await run_in_threadpool(db.damaged_get, path) if isinstance(path, str) else None
    if d is None or d["state"] not in db.ACTIVE:
        raise HTTPException(404)
    if not d["sha_bad"]:
        return _bad("файл не читается — принять его нельзя")
    await run_in_threadpool(db.hashes_checked_many, [(d["sha_bad"], time.time(), d["key"])])
    await run_in_threadpool(_damaged_state, path, "accepted", f"принят как новая версия ({s.user})")
    audit("damaged_accept", s.user, ip_of(request), path)
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/damaged/retry", dependencies=[Depends(require_csrf)])
async def admin_damaged_retry(request: Request, s: Session = Depends(require_admin)):
    """Восстановить заново (копию из Restored удалили или ни у кого её не было)."""
    path = (await read_json(request)).get("path")
    d = await run_in_threadpool(db.damaged_get, path) if isinstance(path, str) else None
    if d is None or d["state"] not in db.ACTIVE:
        raise HTTPException(404)
    def retry() -> None:
        _nosource_set(path, None)                    # спросить заново у всех клиентов
        _damaged_state(path, "found", "", "")

    await run_in_threadpool(retry)
    audit("damaged_retry", s.user, ip_of(request), path)
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/damaged/dismiss", dependencies=[Depends(require_csrf)])
async def admin_damaged_dismiss(request: Request, s: Session = Depends(require_admin)):
    """Убрать закрытую запись (исправлен, принят…) из списка, не дожидаясь суток."""
    path = (await read_json(request)).get("path")
    d = await run_in_threadpool(db.damaged_get, path) if isinstance(path, str) else None
    if d is None:
        raise HTTPException(404)
    if d["state"] in db.ACTIVE:
        return _bad("файл ещё не исправлен")

    def drop() -> None:
        with _dmg_mu:
            db.damaged_delete(path)
            _nosource_set(path, None)

    await run_in_threadpool(drop)
    audit("damaged_dismiss", s.user, ip_of(request), path)
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/damaged/check", dependencies=[Depends(require_csrf)])
async def admin_damaged_check(_: Session = Depends(require_admin)):
    """Проверить сейчас, исправлены ли файлы (перечитать оригиналы)."""
    if not await PC.is_up():
        raise HTTPException(409, "pc down")
    await on_pc(_damaged_check, True, timeout=600)
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
    if since and (library.verify_state == "done"
                  or not await run_in_threadpool(db.hashes_unchecked, float(since))):
        # прошлая проверка закончилась, но её ещё не закрыли (раз в минуту, или сервер перезапустили
        # раньше) — закрываем и начинаем новую
        await run_in_threadpool(db.kv_set, "verify_last", time.time())
        await run_in_threadpool(db.kv_set, "verify_last_bad", library.verify_bad)
        since = None
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
    photos = [p for p in library.by_id.values() if not (p.video and p.live) and not library.is_audio(p)]
    videos = sum(1 for p in photos if p.video)
    unhashed = await run_in_threadpool(_unhashed) if tokens.any() else 0
    n_hidden = await run_in_threadpool(db.hidden_count)                     # у всех пользователей
    vt_n, vt_b = await run_in_threadpool(db.vthumb_stats)
    pt_n, pt_b = await run_in_threadpool(pthumbs.stats, (_pkind("s"), _pkind("t")))
    return no_store(JSONResponse({
        "pthumbs": {"stored": pt_n, "bytes": pt_b, "photos": len(photos) - videos, "state": PT.state, "done": PT.done,
                    "total": PT.total, "failed": PT.failed},
        "hidden": n_hidden,
        "vthumbs": {"stored": vt_n, "bytes": vt_b, "videos": videos, "state": VT.state, "done": VT.done,
                    "total": VT.total, "failed": VT.failed, "audio": len(library.audio)},
        "delete_marks": sum(1 for rel in list(_marks) if (q := _by_rel(rel)) is not None and not (q.video and q.live)),
        "version": config.app_version(),
        "uptime": int(time.time() - STARTED),
        "pc": pc_state(up),
        "index": {"state": library.state, "error": library.error, "files": len(photos), "videos": videos,
                  "with_date": sum(1 for p in photos if p.taken), "with_name_date": sum(1 for p in photos if not p.taken and p.named),
                  "with_folder_year": sum(1 for p in photos if p.folder_only()),
                  "built_at": int(library.built_at),
                  "meta": [library.meta_done, library.meta_total]},
        # хеши — у всех файлов индекса (и роликов живых фото), поэтому своё «из скольких»
        "hashes": {**_hash_progress(), "unhashed": unhashed, "files": len(library.by_id)} if tokens.any() else None,
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
            "yandex": bool(yandex), "yandex_redirect": yandex.redirect_uri if yandex else "",
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
    keys = await run_in_threadpool(db.passkey_counts)
    return no_store(JSONResponse({"users": [{**u, "passkeys": keys.get(u["user"], 0)} for u in users.list()]}))


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
    return await _user_ext(request, name, "google", s)


@app.post("/api/admin/users/{name}/yandex", dependencies=[Depends(require_csrf)])
async def admin_user_yandex(request: Request, name: str, s: Session = Depends(require_admin)):
    return await _user_ext(request, name, "yandex", s)


async def _user_ext(request: Request, name: str, kind: str, s: Session):
    """Привязка внешнего аккаунта для входа (google, yandex) — по email."""
    name = _user_arg(name)
    d = await read_json(request)
    email = d.get("email")
    if email is not None and not isinstance(email, str):
        return _bad("email строкой")
    try:
        await run_in_threadpool(users.set_ext, kind, name, email or None)
    except UserError as e:
        return _bad(str(e))
    audit("user_" + kind, s.user, ip_of(request), f"{name} -> {email or 'отвязан'}")
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


@app.get("/api/admin/pc")
async def admin_pc(_: Session = Depends(require_admin)):
    from .pc import b64d, fingerprint
    c = await run_in_threadpool(db.pc_get)
    client = None
    if c:
        client = {"name": c["name"], "key_type": c["key_type"], "fp": fingerprint(b64d(c["pub"])),
                  "created": int(c["created"]), "last_seen": int(c["last_seen"]), "last_ip": c["last_ip"]}
    return no_store(JSONResponse({"client": client, "pair_until": int(pcauth.pair_until), "now": int(time.time()),
                                  "marks": len(_marks)}))


@app.post("/api/admin/pc/pair", dependencies=[Depends(require_csrf)])
async def admin_pc_pair(request: Request, s: Session = Depends(require_admin)):
    pcauth.open_window()
    audit("pc_pair_window", s.user, ip_of(request), "10 минут")
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/pc/unpair", dependencies=[Depends(require_csrf)])
async def admin_pc_unpair(request: Request, s: Session = Depends(require_admin)):
    had = await run_in_threadpool(pcauth.unpair)
    if had:
        audit("pc_unpair", s.user, ip_of(request))
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/passkey", dependencies=[Depends(require_csrf)])
async def admin_user_passkey(request: Request, name: str, s: Session = Depends(require_admin)):
    """offer — предложить создать ключ при следующем входе; cancel — не предлагать; delete — удалить его ключи."""
    name = _user_arg(name)
    mode = (await read_json(request)).get("mode")
    if mode not in ("offer", "cancel", "delete"):
        return _bad("mode: offer, cancel или delete")
    try:
        await run_in_threadpool(users.set_passkey_offer, name, mode == "offer")
    except UserError as e:
        return _bad(str(e))
    detail = name
    if mode == "delete":
        detail += f", удалено ключей: {await run_in_threadpool(db.passkeys_delete_user, name)}"
    audit({"offer": "passkey_offer", "cancel": "passkey_cancel", "delete": "passkey_delete"}[mode],
          s.user, ip_of(request), detail)
    return no_store(JSONResponse({"ok": True}))


@app.post("/api/admin/users/{name}/2fa", dependencies=[Depends(require_csrf)])
async def admin_user_2fa(request: Request, name: str, s: Session = Depends(require_admin)):
    """on — требовать (пользователь настроит приложение при следующем входе); reset — новый
    телефон: настройка заново при следующем входе; off — выключить."""
    name = _user_arg(name)
    mode = (await read_json(request)).get("mode")
    try:
        await run_in_threadpool(users.totp_set, name, mode)
    except UserError as e:
        return _bad(str(e))
    audit({"on": "2fa_on", "off": "2fa_off", "reset": "2fa_reset"}[mode], s.user, ip_of(request), name)
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
    await run_in_threadpool(db.user_forget, name)          # его скрытые, группы, избранное
    mine.forget(name)
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
    sessions.short_s = S.session_short_minutes * 60
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
