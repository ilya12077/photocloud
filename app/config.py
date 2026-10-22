"""Конфигурация из переменных окружения. Всё валидируется при старте —
если что-то не так, контейнер падает сразу, а не в рантайме."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


PROJECT_ROOT = Path(__file__).resolve().parent.parent

def app_version() -> str:
    """Версия сборки: из образа (PHOTOCLOUD_VERSION) или из файла VERSION рядом с проектом."""
    v = os.environ.get("PHOTOCLOUD_VERSION", "").strip()
    if v:
        return v
    try:
        return (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


def load_dotenv(path: Path) -> None:
    """Минимальный загрузчик .env: KEY=VALUE, # комментарии, без подстановок
    (значит $ в паролях и хэшах можно писать как есть). Переменные окружения
    имеют приоритет над файлом."""
    if not path.is_file():
        return
    for ln, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if not sep or not re.match(r"^[A-Z_][A-Z0-9_]*$", key):
            raise ConfigError(f".env строка {ln}: ожидается KEY=VALUE")
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        os.environ.setdefault(key, val)


def _get(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v


def _secret(name: str, default: str | None = None) -> str | None:
    """Секрет из NAME или из файла NAME_FILE (docker secrets)."""
    path = _get(name + "_FILE")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ConfigError(f"не удалось прочитать {name}_FILE: {e}") from e
    return _get(name, default)


def _bool(name: str, default: bool) -> bool:
    v = _get(name)
    if v is None:
        return default
    if v.lower() in ("1", "true", "yes", "on"):
        return True
    if v.lower() in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name}: ожидается true/false, получено {v!r}")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    v = _get(name)
    if v is None:
        return default
    try:
        n = int(v)
    except ValueError:
        raise ConfigError(f"{name}: ожидается целое число") from None
    if not lo <= n <= hi:
        raise ConfigError(f"{name}: значение вне диапазона [{lo}, {hi}]")
    return n


def _networks(name: str) -> list[ipaddress._BaseNetwork]:
    v = _get(name, "")
    nets = []
    for part in (p.strip() for p in v.split(",")):
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ConfigError(f"{name}: неверная сеть {part!r}") from None
    return nets


_SERVICE_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
# уведомления: либо сервис notify.*, либо сущность, в которой записано имя такого сервиса
_NOTIFY_RE = re.compile(r"^(notify|input_text|input_select|sensor|text|select)\.[a-z0-9_]+$")

ALL_NOTIFY_EVENTS = {"login", "login_new_ip", "login_failed", "lockout", "wake", "wake_timeout", "index_error"}


@dataclass
class Settings:
    # хранилище
    storage: str = "smb"                 # smb | local
    local_root: str = "/photos"
    smb_host: str = ""
    smb_port: int = 445
    smb_share: str = ""
    smb_subdir: str = ""
    smb_user: str = ""
    smb_password: str = ""
    smb_encrypt: bool = True

    # пробуждение (только через Home Assistant)
    wake_timeout: int = 180

    # Home Assistant
    ha_url: str = "http://127.0.0.1:8123"
    ha_token: str = ""
    ha_verify_ssl: bool = True
    ha_wake_service: str = ""            # напр. script.wake_pc или wake_on_lan.send_magic_packet
    ha_wake_data: dict = field(default_factory=dict)
    ha_notify_service: str = ""          # напр. notify.mobile_app_pixel_8
    notify_events: set = field(default_factory=set)
    public_name: str = "Фотоархив"

    # веб / безопасность
    cookie_secure: bool = True
    session_idle_hours: int = 24 * 7
    session_max_hours: int = 24 * 30
    trusted_proxies: list = field(default_factory=list)
    require_proxy: bool = True
    allowed_origins: set = field(default_factory=set)

    bind: str = "127.0.0.1"
    port: int = 8099
    public_url: str = ""
    google_client_id: str = ""
    google_client_secret: str = ""
    data_dir: Path = PROJECT_ROOT / "data"
    tz: object = None
    ffmpeg: str = ""
    transcode: bool = True
    transcode_cache_mb: int = 256
    transcode_slots: int = 2
    meta_threads: int = 4

    # производительность
    image_format: str = "webp"
    thumb_small_size: int = 240
    thumb_size: int = 400
    thumb_large_size: int = 900
    thumb_quality: int = 60
    preview_quick_size: int = 720
    preview_quick_quality: int = 32
    preview_size: int = 1600
    preview_quality: int = 72
    thumb_cache_mb: int = 128
    preview_cache_mb: int = 64
    max_decode_mb: int = 150
    workers: int = 5
    index_ttl: int = 600


def load() -> Settings:
    load_dotenv(Path(os.environ.get("ENV_FILE", PROJECT_ROOT / ".env")))
    s = Settings()
    s.storage = _get("STORAGE", "smb")
    if s.storage not in ("smb", "local"):
        raise ConfigError("STORAGE: smb или local")
    if s.storage == "local" and os.environ.get("PHOTOCLOUD_DOCKER") == "1":
        raise ConfigError("в контейнере доступен только STORAGE=smb (локальный режим — для теста на компе)")
    s.local_root = _get("LOCAL_ROOT", s.local_root)
    if s.storage == "local" and not Path(s.local_root).is_dir():
        raise ConfigError(f"LOCAL_ROOT: папка не найдена: {s.local_root}")

    s.smb_host = _get("SMB_HOST", "") or ""
    s.smb_port = _int("SMB_PORT", 445, 1, 65535)
    s.smb_share = _get("SMB_SHARE", "")
    s.smb_subdir = (_get("SMB_SUBDIR", "") or "").strip("\\/")
    s.smb_user = _get("SMB_USER", "")
    s.smb_password = _secret("SMB_PASSWORD", "") or ""
    s.smb_encrypt = _bool("SMB_ENCRYPT", True)
    if s.storage == "smb":
        if not (s.smb_host and s.smb_share and s.smb_user and s.smb_password):
            raise ConfigError("для STORAGE=smb нужны SMB_HOST, SMB_SHARE, SMB_USER, SMB_PASSWORD")
        if s.smb_share == s.smb_host or re.fullmatch(r"[\d.]+", s.smb_share):
            raise ConfigError(f"SMB_SHARE: здесь только имя шары (например «фото»), а не адрес компа — "
                              f"адрес уже в SMB_HOST. Сейчас: {s.smb_share!r}")
        if any(c in s.smb_share for c in "\\/:*?\"<>|"):
            raise ConfigError("SMB_SHARE: только имя шары, без слэшей")
        if ".." in re.split(r"[\\/]", s.smb_subdir):
            raise ConfigError("SMB_SUBDIR не может содержать ..")

    s.wake_timeout = _int("WAKE_TIMEOUT", 180, 10, 1800)

    s.ha_url = (_get("HA_URL", s.ha_url) or "").rstrip("/")
    if not re.match(r"^https?://[^/\s]+$", s.ha_url):
        raise ConfigError("HA_URL: вида http://127.0.0.1:8123 (без пути)")
    s.ha_token = _secret("HA_TOKEN", "") or ""
    s.ha_verify_ssl = _bool("HA_VERIFY_SSL", True)
    s.ha_wake_service = _get("HA_WAKE_SERVICE", "") or ""
    s.ha_notify_service = _get("HA_NOTIFY_SERVICE", "") or ""
    for n in ("ha_wake_service", "ha_notify_service"):
        v = getattr(s, n)
        if v and not _SERVICE_RE.match(v):
            raise ConfigError(f"{n.upper()}: формат domain.service")
    if s.ha_notify_service and not _NOTIFY_RE.match(s.ha_notify_service):
        raise ConfigError("HA_NOTIFY_SERVICE: notify.… или сущность с его именем (input_text.…)")
    raw = _get("HA_WAKE_DATA", "") or ""
    if raw:
        try:
            s.ha_wake_data = json.loads(raw)
        except json.JSONDecodeError:
            raise ConfigError("HA_WAKE_DATA: невалидный JSON") from None
        if not isinstance(s.ha_wake_data, dict):
            raise ConfigError("HA_WAKE_DATA: должен быть JSON-объект")
    if s.storage == "smb" and not (s.ha_token and s.ha_wake_service):
        raise ConfigError("нужны HA_TOKEN и HA_WAKE_SERVICE (пробуждение ПК идёт через Home Assistant)")
    ev = _get("NOTIFY_EVENTS", "login_new_ip,login_failed,lockout,wake_timeout,index_error") or ""
    s.notify_events = {e.strip() for e in ev.split(",") if e.strip()}
    bad = s.notify_events - ALL_NOTIFY_EVENTS
    if bad:
        raise ConfigError(f"NOTIFY_EVENTS: неизвестные события {sorted(bad)}")
    if s.ha_notify_service and not s.ha_token:
        raise ConfigError("HA_NOTIFY_SERVICE требует HA_TOKEN")
    s.public_name = (_get("PUBLIC_NAME", s.public_name) or "")[:40]

    s.cookie_secure = _bool("COOKIE_SECURE", True)
    s.session_idle_hours = _int("SESSION_IDLE_HOURS", 24 * 7, 1, 24 * 90)
    s.session_max_hours = _int("SESSION_MAX_HOURS", 24 * 30, 1, 24 * 365)
    s.trusted_proxies = _networks("TRUSTED_PROXIES")
    s.require_proxy = _bool("REQUIRE_PROXY", bool(s.trusted_proxies))
    if s.require_proxy and not s.trusted_proxies:
        raise ConfigError("REQUIRE_PROXY=true без TRUSTED_PROXIES заблокирует всех")
    s.allowed_origins = {o.strip().rstrip("/") for o in (_get("ALLOWED_ORIGINS", "") or "").split(",") if o.strip()}

    s.bind = _get("BIND", "127.0.0.1")
    try:
        ipaddress.ip_address(s.bind)
    except ValueError:
        raise ConfigError("BIND: нужен IP (127.0.0.1 или 0.0.0.0)") from None
    s.port = _int("PORT", 8099, 1, 65535)

    s.public_url = (_get("PUBLIC_URL", "") or "").rstrip("/")
    if s.public_url and not re.match(r"^(https://[A-Za-z0-9.-]+(:\d+)?|http://(localhost|127\.0\.0\.1)(:\d+)?)$", s.public_url):
        raise ConfigError("PUBLIC_URL: https://домен (или http://localhost:порт для теста), без пути")
    s.google_client_id = _get("GOOGLE_CLIENT_ID", "") or ""
    s.google_client_secret = _secret("GOOGLE_CLIENT_SECRET", "") or ""
    if (s.google_client_id or s.google_client_secret) and not (s.google_client_id and s.google_client_secret and s.public_url):
        raise ConfigError("для входа через Google нужны GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET и PUBLIC_URL")
    s.data_dir = Path(_get("DATA_DIR", str(PROJECT_ROOT / "data")))
    tzname = _get("TIMEZONE", "Europe/Moscow")
    try:
        from zoneinfo import ZoneInfo
        s.tz = ZoneInfo(tzname)
    except Exception:  # noqa: BLE001
        raise ConfigError(f"TIMEZONE: неизвестный часовой пояс {tzname!r} (на Windows нужен пакет tzdata)") from None
    s.ffmpeg = _get("FFMPEG", "") or ""
    s.transcode = _bool("TRANSCODE", True)
    s.transcode_cache_mb = _int("TRANSCODE_CACHE_MB", 256, 16, 4096)
    # 2 ffmpeg одновременно: ролик живого фото не задерживает куски видео
    s.transcode_slots = _int("TRANSCODE_SLOTS", 2, 1, 8)
    # с ПК фоновое чтение дат идёт не больше чем в 4 потока (storage.SMB_BACKGROUND) — больше бессмысленно
    s.meta_threads = _int("META_THREADS", 4, 1, 32)

    s.image_format = (_get("IMAGE_FORMAT", "webp") or "").lower()
    if s.image_format not in ("webp", "jpeg"):
        raise ConfigError("IMAGE_FORMAT: webp или jpeg")
    s.thumb_small_size = _int("THUMB_SMALL_SIZE", 240, 64, 1024)
    s.thumb_size = _int("THUMB_SIZE", 400, 64, 1024)
    s.thumb_large_size = _int("THUMB_LARGE_SIZE", 900, 256, 2048)
    s.thumb_quality = _int("THUMB_QUALITY", 60, 30, 95)
    s.preview_quick_size = _int("PREVIEW_QUICK_SIZE", 720, 320, 2048)
    s.preview_quick_quality = _int("PREVIEW_QUICK_QUALITY", 32, 20, 90)
    s.preview_size = _int("PREVIEW_SIZE", 1600, 512, 8192)
    s.preview_quality = _int("PREVIEW_QUALITY", 72, 30, 95)
    s.thumb_cache_mb = _int("THUMB_CACHE_MB", 128, 0, 4096)
    s.preview_cache_mb = _int("PREVIEW_CACHE_MB", 64, 0, 4096)
    s.max_decode_mb = _int("MAX_DECODE_MB", 150, 1, 2048)
    # по умолчанию на 1 ядро меньше, чем есть (но не больше 3) — чтобы HA рядом не тормозил
    # декодирование в Pillow отпускает GIL, так что потоки реально работают параллельно;
    # по умолчанию ядер − 1 (одно оставляем остальным сервисам), но не больше 8
    # ядра + 1: около половины времени эскиз ждёт чтения файла по сети, процессор при этом свободен
    s.workers = _int("WORKERS", max(2, min(8, (os.cpu_count() or 2) + 1)), 1, 32)
    s.index_ttl = _int("INDEX_TTL", 600, 30, 86400)
    load_overrides(s)   # то, что поменяли в админке, важнее .env
    return s


# ---------------------------------------------------------------- настройки из админки
# Только то, что безопасно менять на лету. Секреты и пути — в .env.
EDITABLE = ("public_name", "notify_events", "ha_notify_service", "ha_wake_service", "ha_wake_data",
            "wake_timeout", "index_ttl", "session_idle_hours")


def validate_override(s: Settings, key: str, val):
    if key == "public_name":
        if not isinstance(val, str) or not (1 <= len(val.strip()) <= 40):
            raise ConfigError("название: 1–40 символов")
        return val.strip()
    if key == "notify_events":
        if not isinstance(val, list) or not all(isinstance(e, str) for e in val) or set(val) - ALL_NOTIFY_EVENTS:
            raise ConfigError("неизвестные события уведомлений")
        return set(val)
    if key in ("ha_notify_service", "ha_wake_service"):
        if not isinstance(val, str) or (val and not _SERVICE_RE.match(val)):
            raise ConfigError("сервис HA: формат domain.service")
        if key == "ha_notify_service" and val and not _NOTIFY_RE.match(val):
            raise ConfigError("уведомления: notify.… или сущность с его именем (input_text.…)")
        if key == "ha_wake_service" and not val and s.storage == "smb":
            raise ConfigError("сервис пробуждения обязателен")
        return val
    if key == "ha_wake_data":
        if not isinstance(val, dict) or len(json.dumps(val)) > 2000:
            raise ConfigError("данные пробуждения: JSON-объект")
        return val
    limits = {"wake_timeout": (10, 1800), "index_ttl": (30, 86400), "session_idle_hours": (1, 24 * 90)}
    if key in limits:
        lo, hi = limits[key]
        if not isinstance(val, int) or isinstance(val, bool) or not lo <= val <= hi:
            raise ConfigError(f"{key}: целое от {lo} до {hi}")
        return val
    raise ConfigError(f"неизвестная настройка {key}")


def export_editable(s: Settings) -> dict:
    out = {}
    for k in EDITABLE:
        v = getattr(s, k)
        out[k] = sorted(v) if isinstance(v, set) else v
    return out


def load_overrides(s: Settings) -> None:
    path = s.data_dir / "settings.json"
    if not path.is_file():
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"{path}: не читается ({type(e).__name__})") from None
    for k, v in (raw or {}).items():
        if k in EDITABLE:
            setattr(s, k, validate_override(s, k, v))


def save_overrides(s: Settings) -> None:
    path = s.data_dir / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(export_editable(s), ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
