"""Photocloud — клиент на ПК с архивом: удаляет в корзину Windows фото, помеченные в галерее «на удаление».

Один файл, двойной щелчок (откроется через pythonw, без консоли). Без автозапуска и без трея:
запустил, посмотрел, удалил, закрыл. Недостающие библиотеки (httpx, pillow, cryptography)
программа предложит поставить сама. Настройки и журнал — в %USERPROFILE%\\.photocloud-pc.

Вход на сервер — ключом в TPM этого ПК (ключ не извлекается из чипа):
1) в админке: «Бэкап» → «Клиент на ПК» → «Привязать» (окно на 10 минут);
2) программа присылает открытый ключ, кладёт подписанный файл в служебную папку шары
   (.photocloud\\ — скрытая), сервер читает его по сети и запоминает ключ;
3) дальше каждый сеанс открывается подписью ключа, каждый запрос подписан ключом сеанса,
   а отчёт об удалении — ещё и свежей подписью ключа TPM над точным списком файлов.

Перед удалением программа сама проверяет каждый файл на диске: путь внутри папки архива,
размер, дата изменения и SHA-256 — как в момент пометки. Изменённый после пометки файл не удаляется.
Удаляет только в корзину; что удалить — выбираешь ты, глядя на превью.
"""
from __future__ import annotations

import os
import sys
import time
import traceback


def _boot_log(text: str) -> None:
    try:
        base = os.environ.get("USERPROFILE") if sys.platform == "win32" else \
            os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))
        d = os.path.join(base or os.path.expanduser("~"), ".photocloud-pc" if sys.platform == "win32" else "photocloud-pc")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "pc.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " " + text.rstrip() + "\n")
    except Exception:  # noqa: BLE001
        pass


sys.excepthook = lambda t, e, tb: _boot_log("CRITICAL программа упала:\n" + "".join(traceback.format_exception(t, e, tb)))

import base64
import concurrent.futures
import datetime
import hashlib
import hmac
import importlib
import importlib.util
import io
import json
import logging
import logging.handlers
import queue
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import httpx
except ImportError:
    httpx = None
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    ec = None

VERSION = "1.0.3"           # по этой строке программа сравнивает себя с версией на GitHub
DEPS = (("httpx", "httpx>=0.27"), ("PIL", "pillow>=10"), ("cryptography", "cryptography>=42"))
KEY_NAME = "photocloud-pc"
APP = "Photocloud — удаление"
IS_WIN = sys.platform == "win32"
log = logging.getLogger("pcclient")


def app_dir() -> Path:
    if IS_WIN:
        d = Path(os.environ.get("USERPROFILE") or Path.home()) / ".photocloud-pc"
    else:
        d = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "photocloud-pc"
    d.mkdir(parents=True, exist_ok=True)
    return d


class Config:
    FIELDS = ("server", "root", "client_id", "key_type", "fp")

    def __init__(self):
        self.path = app_dir() / "config.json"
        self.server = self.root = self.client_id = self.key_type = self.fp = ""
        self.updates = True                              # проверять обновления при запуске
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            for k in self.FIELDS:
                if isinstance(d.get(k), str):
                    setattr(self, k, d[k])
            if isinstance(d.get("updates"), bool):
                self.updates = d["updates"]
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        d = {k: getattr(self, k) for k in self.FIELDS}
        d["updates"] = self.updates
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def human(n: int) -> str:
    for u in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or u == "ГБ":
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


# ======================================================================== ключ (TPM)
# Windows CNG: «Microsoft Platform Crypto Provider» — ключи в TPM, наружу не выдаются.
# Нет TPM 2.0 — можно (с предупреждением) «Microsoft Software Key Storage Provider»: ключ
# не экспортируемый, но лежит в профиле Windows, а не в чипе. На Linux (только для проверки
# программы) — ключ в файле.

class KeyError_(Exception):
    pass


if IS_WIN:
    import ctypes
    import winreg
    from ctypes import wintypes

    _nc = ctypes.WinDLL("ncrypt")
    _H = ctypes.c_size_t
    _ok = lambda r: (r & 0xFFFFFFFF) == 0  # noqa: E731
    NTE_BAD_KEYSET = 0x80090016
    PROVIDERS = {"tpm": "Microsoft Platform Crypto Provider", "software": "Microsoft Software Key Storage Provider"}

    class NKey:
        def __init__(self, kind: str, create: bool):
            self.kind = kind
            self.prov, self.key = _H(), _H()
            r = _nc.NCryptOpenStorageProvider(ctypes.byref(self.prov), PROVIDERS[kind], 0)
            if not _ok(r):
                raise KeyError_(f"хранилище ключей «{PROVIDERS[kind]}» недоступно (0x{r & 0xFFFFFFFF:08X})")
            r = _nc.NCryptOpenKey(self.prov, ctypes.byref(self.key), KEY_NAME, 0, 0)
            if not _ok(r):
                if (r & 0xFFFFFFFF) != NTE_BAD_KEYSET or not create:
                    raise KeyError_(f"ключ не открылся (0x{r & 0xFFFFFFFF:08X})")
                r = _nc.NCryptCreatePersistedKey(self.prov, ctypes.byref(self.key), "ECDSA_P256", KEY_NAME, 0, 0)
                if not _ok(r):
                    raise KeyError_(f"ключ не создался (0x{r & 0xFFFFFFFF:08X}) — нет TPM 2.0 с ECC P-256?")
                r = _nc.NCryptFinalizeKey(self.key, 0)
                if not _ok(r):
                    raise KeyError_(f"ключ не создался (0x{r & 0xFFFFFFFF:08X})")
                log.info("создан ключ %s в «%s»", KEY_NAME, PROVIDERS[kind])

        def public_raw(self) -> bytes:
            n = wintypes.DWORD()
            _nc.NCryptExportKey(self.key, 0, "ECCPUBLICBLOB", None, None, 0, ctypes.byref(n), 0)
            buf = ctypes.create_string_buffer(n.value)
            r = _nc.NCryptExportKey(self.key, 0, "ECCPUBLICBLOB", None, buf, n, ctypes.byref(n), 0)
            if not _ok(r):
                raise KeyError_(f"открытый ключ не прочитался (0x{r & 0xFFFFFFFF:08X})")
            blob = buf.raw[:n.value]
            cb = int.from_bytes(blob[4:8], "little")          # BCRYPT_ECCKEY_BLOB: magic, cbKey, X, Y
            return blob[8:8 + 2 * cb]

        def sign(self, message: bytes) -> bytes:
            """Подпись r||s над SHA-256 сообщения — подписывает сам TPM."""
            digest = hashlib.sha256(message).digest()
            hb = ctypes.create_string_buffer(digest, len(digest))
            n = wintypes.DWORD()
            sig = ctypes.create_string_buffer(256)
            r = _nc.NCryptSignHash(self.key, None, hb, len(digest), sig, 256, ctypes.byref(n), 0)
            if not _ok(r):
                raise KeyError_(f"подпись не удалась (0x{r & 0xFFFFFFFF:08X})")
            return sig.raw[:n.value]

        def delete(self) -> None:
            _nc.NCryptDeleteKey(self.key, 0)
            self.key = _H()

    def open_key(kind: str, create: bool):
        return NKey(kind, create)

    def machine_guid() -> str:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
        except OSError:
            return ""

    def share_path(name: str) -> str:
        """Локальная папка общей папки Windows по её имени (реестр LanmanServer\\Shares)."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares") as k:
                i = 0
                while True:
                    try:
                        vname, val, _t = winreg.EnumValue(k, i)
                    except OSError:
                        return ""
                    i += 1
                    if vname.lower() == name.lower():
                        for line in val if isinstance(val, list) else str(val).split("\0"):
                            if line.lower().startswith("path="):
                                return line[5:]
        except OSError:
            return ""

    def set_hidden(p: Path) -> None:
        ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x2)

    class _SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR),
                    ("pTo", wintypes.LPCWSTR), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                    ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]

    def to_recycle_bin(paths: list[Path]) -> str:
        """Пачку файлов — в корзину (можно восстановить) одним вызовом SHFileOperation с FOF_ALLOWUNDO:
        по одному файлу это в разы дольше. Если в корзину нельзя (файл больше её размера, корзина
        отключена) — FOF_WANTNUKEWARNING: Windows спросит, а не удалит молча.
        -> пояснение ошибки или ""; что удалилось, вызывающий проверяет сам (файла больше нет)."""
        buf = ctypes.create_unicode_buffer("\0".join(str(p) for p in paths) + "\0\0")
        op = _SHFILEOPSTRUCTW(None, 3, ctypes.cast(buf, wintypes.LPCWSTR), None,
                              0x40 | 0x10 | 0x4 | 0x400 | 0x4000, False, None, None)
        r = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if op.fAnyOperationsAborted:
            return "отменено"
        return f"не удалось отправить в корзину (код {r})" if r else ""

    def open_folder(p: Path) -> None:
        os.startfile(str(p))  # noqa: S606
else:
    class FileKey:
        """ТОЛЬКО ДЛЯ ПРОВЕРКИ НА LINUX: ключ в файле."""

        def __init__(self, kind: str, create: bool):
            self.kind, self.path = kind, app_dir() / "test-key.pem"
            if self.path.exists():
                self.k = serialization.load_pem_private_key(self.path.read_bytes(), None)
            elif create:
                self.k = ec.generate_private_key(ec.SECP256R1())
                self.path.write_bytes(self.k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
            else:
                raise KeyError_("нет ключа")

        def public_raw(self) -> bytes:
            n = self.k.public_key().public_numbers()
            return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

        def sign(self, message: bytes) -> bytes:
            r, s = decode_dss_signature(self.k.sign(message, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        def delete(self) -> None:
            self.path.unlink(missing_ok=True)

    def open_key(kind: str, create: bool):
        return FileKey(kind, create)

    def machine_guid() -> str:
        try:
            return Path("/etc/machine-id").read_text().strip()
        except OSError:
            return ""

    def share_path(name: str) -> str:
        return os.environ.get("PHOTOCLOUD_TEST_ROOT", "")

    def set_hidden(p: Path) -> None:
        pass

    def to_recycle_bin(paths: list[Path]) -> str:
        trash = app_dir() / "trash"
        trash.mkdir(exist_ok=True)
        for p in paths:
            shutil.move(str(p), str(trash / f"{time.time_ns()}-{p.name}"))
        return ""

    def open_folder(p: Path) -> None:
        subprocess.Popen(["xdg-open", str(p)])


# ======================================================================== сервер

def pair_message(nonce: str, pub: str) -> bytes:
    return f"photocloud-pair\n{nonce}\n{pub}".encode()


def session_message(cid: str, eph: str, ts: int, guid: str) -> bytes:
    return f"photocloud-session\n{cid}\n{eph}\n{ts}\n{guid}".encode()


def delete_message(sid: str, ts: int, items: list) -> bytes:
    return ("photocloud-delete\n" + sid + "\n" + str(ts) + "\n"
            + json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))).encode()


class NotPaired(Exception):
    pass


class ServerError(Exception):
    pass


class Api:
    """Сеанс с сервером: открывается подписью ключа TPM над одноразовым ключом ECDH,
    дальше каждый запрос подписан ключом сеанса (HMAC)."""

    def __init__(self, cfg: Config, key):
        self.cfg, self.key = cfg, key
        self.c = httpx.Client(base_url=cfg.server, timeout=httpx.Timeout(60, connect=15),
                              headers={"user-agent": f"photocloud-pc/{VERSION}"})
        self.mu = threading.Lock()
        self.sid, self.skey, self.exp, self.ctr = "", b"", 0, 0

    def close(self) -> None:
        self.c.close()

    def _session(self) -> None:
        mine = ec.generate_private_key(ec.SECP256R1())
        n = mine.public_key().public_numbers()
        eph_raw = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
        eph, ts, guid = b64e(eph_raw), int(time.time()), machine_guid()
        sig = b64e(self.key.sign(session_message(self.cfg.client_id, eph, ts, guid)))
        r = self.c.post("/api/pc/session", json={"id": self.cfg.client_id, "eph": eph, "ts": ts, "guid": guid, "sig": sig})
        if r.status_code in (401, 403):
            err = _err(r)
            if "не привязан" in err:
                raise NotPaired(err)
            raise ServerError(err)
        if r.status_code != 200:
            raise ServerError(f"сервер: {r.status_code} {_err(r)}")
        d = r.json()
        srv = b64d(d["eph"])
        peer = ec.EllipticCurvePublicNumbers(int.from_bytes(srv[:32], "big"), int.from_bytes(srv[32:], "big"),
                                             ec.SECP256R1()).public_key()
        shared = mine.exchange(ec.ECDH(), peer)
        self.skey = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_raw + srv,
                         info=b"photocloud-pc-session").derive(shared)
        self.sid, self.exp, self.ctr = d["sid"], int(d["exp"]), 0
        log.info("сеанс открыт до %s", time.strftime("%H:%M", time.localtime(self.exp)))

    def call(self, method: str, path: str, body: dict | None = None, _again: bool = True):
        with self.mu:
            if not self.sid or time.time() > self.exp - 60:
                self._session()
            self.ctr += 1
            sid, skey, ctr = self.sid, self.skey, self.ctr
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else b""
        ts = int(time.time())
        msg = f"{method}\n{path}\n{hashlib.sha256(data).hexdigest()}\n{ts}\n{ctr}".encode()
        h = {"x-pc-sid": sid, "x-pc-ts": str(ts), "x-pc-ctr": str(ctr),
             "x-pc-mac": hmac.new(skey, msg, hashlib.sha256).hexdigest()}
        if body is not None:
            h["content-type"] = "application/json"
        r = self.c.request(method, path, content=data if body is not None else None, headers=h)
        if r.status_code == 401 and _again:          # сеанс истёк или сервер перезапускался — новый сеанс
            with self.mu:
                self.sid = ""
            return self.call(method, path, body, False)
        return r


def _err(r) -> str:
    try:
        d = r.json()
        return str(d.get("error") or d.get("detail") or r.status_code)
    except ValueError:
        return f"HTTP {r.status_code}"


# ======================================================================== проверка файлов

def safe_rel(rel: str) -> list[str]:
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") or "\\" in p or ":" in p or "\x00" in p for p in parts):
        raise ValueError("недопустимый путь")
    return parts


def check_file(root: Path, item: dict) -> tuple[str, Path | None, str]:
    """-> (состояние, путь, пояснение). ok — можно удалять: путь внутри архива, файл тот же, что помечали."""
    try:
        p = root.joinpath(*safe_rel(item["path"]))
        rp = p.resolve()
        if root.resolve() not in rp.parents:
            return "bad", None, "путь ведёт за пределы папки архива"
    except (ValueError, OSError) as e:
        return "bad", None, str(e)
    try:
        st = os.stat(p, follow_symlinks=False)
    except FileNotFoundError:
        return "missing", p, "файла уже нет"
    except OSError as e:
        return "bad", p, f"не читается: {e}"
    if not os.path.isfile(p) or os.path.islink(p):
        return "bad", p, "не обычный файл"
    if st.st_size != item["size"] or int(st.st_mtime) != item["mtime"]:
        return "changed", p, "файл изменили после пометки (размер или дата)"
    if item.get("sha"):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
                h.update(chunk)
        if h.hexdigest() != item["sha"]:
            return "changed", p, "содержимое отличается от помеченного (SHA-256)"
        return "ok", p, "проверен: размер, дата, SHA-256"
    return "ok", p, "проверен: размер и дата (хеша на сервере нет)"


# ======================================================================== обновление с GitHub
# Как у клиента бэкапа: последний коммит master, оттуда pc/photocloud_pc.pyw; если VERSION новее —
# файл проверяется (компилируется), подменяет этот, программа перезапускается.

REPO = "ilya12077/photocloud"
REMOTE_PATH = "pc/photocloud_pc.pyw"
SCRIPT = Path(__file__).resolve()
_VERSION_RE = re.compile(r'^VERSION = "([0-9][0-9A-Za-z.\-+]{0,30})"', re.M)


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def fetch_update() -> tuple[str, str, str] | None:
    """-> (версия, текст файла, коммит), если на GitHub версия новее; иначе None. Сбой — исключение."""
    with httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=True,
                      headers={"user-agent": f"photocloud-pc/{VERSION}"}) as c:
        r = c.get(f"https://api.github.com/repos/{REPO}/commits/master", headers={"accept": "application/vnd.github.sha"})
        sha = r.text.strip() if r.status_code == 200 and re.fullmatch(r"[0-9a-f]{40}", r.text.strip()) else "master"
        r = c.get(f"https://raw.githubusercontent.com/{REPO}/{sha}/{REMOTE_PATH}", headers={"cache-control": "no-cache"})
    if r.status_code != 200:
        raise ServerError(f"GitHub: HTTP {r.status_code}")
    m = _VERSION_RE.search(r.text)
    if not m:
        raise ServerError("на GitHub нет клиента")
    return (m.group(1), r.text, sha) if _ver(m.group(1)) > _ver(VERSION) else None


def install(text: str) -> None:
    compile(text, str(SCRIPT), "exec")                 # битый файл не поставится
    tmp = SCRIPT.with_name(SCRIPT.name + ".new")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, SCRIPT)


def restart() -> None:
    exe = Path(sys.executable)
    if IS_WIN and exe.with_name("pythonw.exe").exists():
        exe = exe.with_name("pythonw.exe")
    subprocess.Popen([str(exe), str(SCRIPT)], close_fds=True,
                     creationflags=(0x00000008 | 0x00000200) if IS_WIN else 0)


# ======================================================================== окно

CARD_W, THUMB, GAP = 236, 220, 10
CARD_H = THUMB + 104
BG, CARD, IMGBG, TEXT, DIM, ACCENT = "#ececec", "#ffffff", "#e2e2e2", "#1f1f1f", "#6b6f75", "#e8a33d"
STATE = {"ok": ("✔", "#1e9e50"), "changed": ("⚠", "#d9822b"), "missing": ("—", DIM), "bad": ("✖", "#d93b3b"),
         "checking": ("…", DIM)}


class App:
    """Сетка рисуется на одном холсте и только видимая часть: сотни отдельных виджетов и картинок
    исчерпывают ресурсы окон Windows (пустые карточки, мусор на экране)."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.root = tk.Tk()
        self.root.title(f"{APP} {VERSION}")
        self.root.geometry("1100x760")
        self.root.minsize(820, 420)
        self.q: queue.Queue = queue.Queue()          # из рабочих потоков — в окно
        self.check_pool = concurrent.futures.ThreadPoolExecutor(2)   # проверка файлов на диске
        self.thumb_pool = concurrent.futures.ThreadPoolExecutor(4)   # превью с сервера — отдельно, не тормозит проверку
        self.key = None
        self.api: Api | None = None
        self.items: list[dict] = []
        self.index: dict[str, int] = {}
        self.thumbs: dict[str, bytes] = {}           # путь -> превью (WebP), пока программа открыта
        self.asked: set[str] = set()                 # превью уже запрошено
        self.want: set[str] = set()                  # видно сейчас (и экран вокруг)
        self.drawn: dict[int, object] = {}           # нарисованные карточки -> их картинка
        self.cols, self.gen, self._pending = 1, 0, False
        self.busy, self.stop = False, False              # идёт удаление; просили остановить
        self._build()
        h = _UiLog(self)
        log.addHandler(h)
        self.root.after(100, self._pump)
        self.root.after(200, self.start)

    # ---- разметка
    def _build(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True)
        main = ttk.Frame(self.nb)
        self.nb.add(main, text="Удаление")
        self._build_main(main)
        lg = ttk.Frame(self.nb)
        self.nb.add(lg, text="Журнал")
        self._build_log(lg)
        st = ttk.Frame(self.nb)
        self.nb.add(st, text="Настройки")
        self._build_settings(st)
        self._buttons(False)

    def _build_main(self, main) -> None:
        top = ttk.Frame(main, padding=(12, 10))
        top.pack(fill="x")
        self.b_reload = ttk.Button(top, text="Обновить список", command=self.load)
        self.b_reload.pack(side="right", padx=4)          # сначала кнопка — длинная строка её не вытеснит
        self.status = ttk.Label(top, text="Запуск…")
        self.status.pack(side="left", fill="x", expand=True)
        bar = ttk.Frame(main, padding=(12, 0, 12, 8))
        bar.pack(fill="x")
        self.b_del = ttk.Button(bar, text="Удалить выбранные в корзину", command=self.delete)
        self.b_del.pack(side="left")
        self.b_restore = ttk.Button(bar, text="Вернуть в галерею", command=self.restore)
        self.b_restore.pack(side="left", padx=(8, 0))
        self.b_unmark = ttk.Button(bar, text="Снять пометку на удаление", command=self.unmark)
        self.b_unmark.pack(side="left", padx=8)
        ttk.Button(bar, text="Выбрать все проверенные", command=lambda: self._select(True)).pack(side="left")
        ttk.Button(bar, text="Снять выбор", command=lambda: self._select(False)).pack(side="left", padx=8)
        self.summary = ttk.Label(main, text="", padding=(12, 0, 12, 8))
        self.summary.pack(fill="x")
        self.prog = ttk.Frame(main, padding=(12, 0, 12, 8))       # прогресс: проверка файлов, удаление
        self.prog_text = ttk.Label(self.prog, text="")
        self.prog_text.pack(side="left")
        self.b_stop = ttk.Button(self.prog, text="Остановить", command=self._stop)
        self.prog_bar = ttk.Progressbar(self.prog, maximum=1)
        self.prog_bar.pack(side="left", fill="x", expand=True, padx=(10, 0))
        wrap = ttk.Frame(main)
        wrap.pack(fill="both", expand=True)
        self._wrap = wrap
        self.canvas = tk.Canvas(wrap, highlightthickness=0, background=BG, yscrollincrement=20)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=lambda a, b: (sb.set(a, b), self._soon()))
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self._layout())
        self.canvas.tag_bind("card", "<Button-1>", self._click)
        self.canvas.tag_bind("img", "<Double-Button-1>", self._dbl)
        self.root.bind_all("<MouseWheel>", self._wheel)
        self.root.bind_all("<Button-4>", self._wheel)
        self.root.bind_all("<Button-5>", self._wheel)

    def _build_log(self, lg) -> None:
        bot = ttk.Frame(lg, padding=(8, 6))
        bot.pack(fill="x", side="bottom")
        ttk.Button(bot, text="Открыть папку", command=lambda: open_folder(app_dir())).pack(side="right")
        ttk.Label(bot, text=f"Подробный журнал: {app_dir() / 'pc.log'}", foreground="#777").pack(side="left")
        self.logbox = tk.Text(lg, wrap="none", state="disabled", font=("Consolas", 9), height=10)
        ys = ttk.Scrollbar(lg, orient="vertical", command=self.logbox.yview)
        xs = ttk.Scrollbar(lg, orient="horizontal", command=self.logbox.xview)
        self.logbox.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        self.logbox.pack(fill="both", expand=True)
        try:                                             # прошлые запуски — последние строки файла
            with open(app_dir() / "pc.log", encoding="utf-8", errors="replace") as f:
                tail = f.readlines()[-300:]
            for line in tail:
                self._log_line(line.rstrip("\n"))
        except OSError:
            pass

    def _log_line(self, line: str) -> None:
        b = self.logbox
        at_end = b.yview()[1] >= 0.999
        b.configure(state="normal")
        b.insert("end", line + "\n")
        if int(b.index("end-1c").split(".")[0]) > 3000:
            b.delete("1.0", "500.0")
        b.configure(state="disabled")
        if at_end:
            b.see("end")

    def _build_settings(self, s) -> None:
        s.columnconfigure(1, weight=1)
        pad = {"padx": 12, "pady": 4}
        self.v_server = tk.StringVar(value=self.cfg.server)
        self.v_root = tk.StringVar(value=self.cfg.root)
        self.v_setmsg, self.v_key, self.v_updmsg = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.v_upd = tk.BooleanVar(value=self.cfg.updates)
        r = 0
        ttk.Label(s, text="Адрес сайта:").grid(row=r, column=0, sticky="w", padx=12, pady=(14, 4))
        ttk.Entry(s, textvariable=self.v_server).grid(row=r, column=1, columnspan=2, sticky="ew", padx=12, pady=(14, 4))
        r += 1
        ttk.Label(s, text="Папка архива:").grid(row=r, column=0, sticky="w", **pad)
        ttk.Entry(s, textvariable=self.v_root).grid(row=r, column=1, sticky="ew", padx=(12, 4), pady=4)
        ttk.Button(s, text="Выбрать…", command=self._pick_root).grid(row=r, column=2, padx=(0, 12), pady=4)
        r += 1
        b = ttk.Frame(s)
        b.grid(row=r, column=1, columnspan=2, sticky="w", **pad)
        ttk.Button(b, text="Сохранить", command=self.save_settings).pack(side="left")
        ttk.Label(b, textvariable=self.v_setmsg, foreground="#666", wraplength=520).pack(side="left", padx=10)
        r += 1
        ttk.Separator(s).grid(row=r, column=0, columnspan=3, sticky="ew", padx=12, pady=10)
        r += 1
        ttk.Label(s, text="Ключ входа:").grid(row=r, column=0, sticky="w", **pad)
        kb = ttk.Frame(s)
        kb.grid(row=r, column=1, columnspan=2, sticky="w", **pad)
        ttk.Label(kb, textvariable=self.v_key).pack(side="left")
        ttk.Button(kb, text="Привязать заново", command=self.repair).pack(side="left", padx=10)
        r += 1
        ttk.Separator(s).grid(row=r, column=0, columnspan=3, sticky="ew", padx=12, pady=10)
        r += 1
        ttk.Label(s, text="Версия:").grid(row=r, column=0, sticky="w", **pad)
        ttk.Label(s, text=VERSION).grid(row=r, column=1, sticky="w", **pad)
        r += 1
        ttk.Checkbutton(s, text="Проверять обновления на GitHub при запуске", variable=self.v_upd,
                        command=self._save_upd).grid(row=r, column=1, columnspan=2, sticky="w", **pad)
        r += 1
        ub = ttk.Frame(s)
        ub.grid(row=r, column=1, columnspan=2, sticky="w", **pad)
        ttk.Button(ub, text="Проверить обновления", command=self.check_update).pack(side="left")
        ttk.Label(ub, textvariable=self.v_updmsg, foreground="#666", wraplength=520).pack(side="left", padx=10)
        r += 1
        ttk.Label(s, text="Автозапуска нет: программа работает, только пока открыто окно. Настройки и журнал — "
                          f"в {app_dir()}.", foreground="#777", wraplength=700).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(18, 4))
        self._key_text()

    def _key_text(self) -> None:
        if self.cfg.client_id and self.cfg.fp:
            kind = "программный, не в TPM" if self.cfg.key_type == "software" else "в TPM"
            self.v_key.set(f"{self.cfg.fp} ({kind})")
        else:
            self.v_key.set("не привязан")

    def _wheel(self, e) -> None:
        try:
            if e.widget.winfo_toplevel() is not self.root:
                return
        except (AttributeError, tk.TclError):
            return
        if e.num in (4, 5):
            n = -3 if e.num == 4 else 3
        else:
            n = int(-e.delta / 40) or (-1 if e.delta > 0 else 1)
        self.canvas.yview_scroll(n, "units")

    def _buttons(self, on: bool) -> None:
        for b in (self.b_del, self.b_restore, self.b_unmark, self.b_reload):
            b.state(["!disabled"] if on else ["disabled"])

    def say(self, text: str) -> None:
        self.status.configure(text=text)

    def _pump(self) -> None:
        try:
            while True:
                fn = self.q.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def ui(self, fn) -> None:
        self.q.put(fn)

    def bg(self, fn) -> None:
        def run():
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                log.exception("ошибка")
                msg = str(e) or type(e).__name__

                def show():
                    self.busy = False
                    self.b_stop.pack_forget()
                    self._progress(None)
                    self._buttons(True)
                    messagebox.showerror(APP, f"Ошибка: {msg}\n\nПодробности — на вкладке «Журнал».")
                self.ui(show)
        threading.Thread(target=run, daemon=True).start()

    # ---- запуск: адрес сервера, ключ, привязка
    def start(self) -> None:
        if not self.cfg.server:
            s = ask_text(self.root, APP, "Адрес фотоархива (как в браузере), например https://photos.example.com:")
            if not s:
                self.root.destroy()
                return
            s = s.strip().rstrip("/")
            if not valid_server(s):
                messagebox.showerror(APP, "Нужен адрес вида https://домен")
                self.root.after(10, self.start)
                return
            self.cfg.server = s
            self.cfg.save()
        try:
            self.key = self._open_key()
        except KeyError_ as e:
            messagebox.showerror(APP, f"Ключ входа недоступен: {e}")
            self.root.destroy()
            return
        if self.key is None:
            self.root.destroy()
            return
        self.api = Api(self.cfg, self.key)
        if self.cfg.updates and "--no-update" not in sys.argv:
            self.root.after(1500, lambda: self.check_update(quiet=True))
        if not self.cfg.client_id:
            self.bg(self._pair)
        else:
            self.load()

    def _open_key(self):
        kind = self.cfg.key_type or "tpm"
        try:
            return open_key(kind, create=True)
        except KeyError_ as e:
            if kind != "tpm" or self.cfg.client_id:
                raise
            log.warning("TPM: %s", e)
            if not messagebox.askyesno(APP, f"Ключ в TPM создать не получилось:\n{e}\n\nСоздать программный ключ? Он тоже "
                                            "не извлекается штатно, но хранится в профиле Windows, а не в чипе — защита слабее."):
                return None
            self.cfg.key_type = "software"
            self.cfg.save()
            return open_key("software", create=True)

    def _pair(self) -> None:
        pub = b64e(self.key.public_raw())
        self.ui(lambda: self.say("Привязка к серверу…"))
        r = self.api.c.post("/api/pc/pair/start", json={"pub": pub, "name": socket.gethostname()[:60],
                                                         "key_type": getattr(self.key, "kind", "tpm")})
        if r.status_code != 200:
            err = _err(r)
            self.ui(lambda: self._pair_failed(err))
            return
        d = r.json()
        root = self.cfg.root
        if not root:
            found = share_path(d.get("share") or "")
            if found and d.get("subdir"):
                found = str(Path(found).joinpath(*d["subdir"].replace("\\", "/").split("/")))
            box: dict = {}
            ev = threading.Event()
            self.ui(lambda: (box.update(root=self._ask_root(found, d.get("share") or "")), ev.set()))
            ev.wait()
            root = box.get("root") or ""
            if not root:
                self.ui(self.root.destroy)
                return
        rootp = Path(root)
        folder = rootp / ".photocloud"
        folder.mkdir(exist_ok=True)
        set_hidden(folder)
        f = rootp.joinpath(*d["file"].split("/"))
        f.write_text(json.dumps({"nonce": d["nonce"], "pub": pub,
                                 "sig": b64e(self.key.sign(pair_message(d["nonce"], pub)))}), encoding="utf-8")
        try:
            r = self.api.c.post("/api/pc/pair/finish", json={"nonce": d["nonce"]})
        finally:
            try:
                f.unlink()
            except OSError:
                pass
        if r.status_code != 200:
            err = _err(r)
            self.ui(lambda: self._pair_failed(err))
            return
        res = r.json()
        self.cfg.client_id, self.cfg.root, self.cfg.fp = res["id"], str(rootp), res["fp"]
        self.cfg.key_type = getattr(self.key, "kind", "tpm")
        self.cfg.save()
        self.ui(lambda: (self.v_root.set(self.cfg.root), self._key_text()))
        log.info("привязан: ключ %s, папка %s", res["fp"], rootp)
        self.ui(lambda: messagebox.showinfo(APP, f"Привязано.\n\nОтпечаток ключа: {res['fp']}\nСверь его с админкой "
                                                 "(«Бэкап» → «Клиент на ПК»)."))
        self.ui(self.load)

    def _pair_failed(self, err: str) -> None:
        log.warning("привязка: %s", err)
        if messagebox.askretrycancel(APP, f"Привязка не удалась:\n{err}\n\nВ админке: «Бэкап» → «Клиент на ПК» → "
                                          "«Привязать», затем «Повторить»."):
            self.bg(self._pair)
        else:
            self.root.destroy()

    def _ask_root(self, found: str, share: str) -> str:
        if found and Path(found).is_dir():
            if messagebox.askyesno(APP, f"Папка архива (общая папка «{share}»):\n{found}\n\nВерно?"):
                return found
        messagebox.showinfo(APP, f"Укажи папку архива на этом ПК — ту, что открыта по сети как «{share}».")
        return filedialog.askdirectory(title="Папка архива") or ""

    # ---- список
    def load(self) -> None:
        self._buttons(False)
        self.say("Загружаю список помеченных…")
        self.bg(self._load)

    def _load(self) -> None:
        try:
            r = self.api.call("GET", "/api/pc/marks")
        except NotPaired as e:
            log.warning("не привязан: %s", e)
            self.cfg.client_id = ""
            self.cfg.save()
            self.ui(lambda: messagebox.showwarning(APP, "Сервер не знает этот ключ (отвязан или привязан другой). "
                                                        "Привяжем заново: в админке нажми «Привязать»."))
            self._pair()
            return
        if r.status_code != 200:
            raise ServerError(f"сервер: {_err(r)}")
        items = r.json()["items"]
        for it in items:
            it["state"], it["file"], it["note"], it["pick"] = "checking", None, "проверяю…", False
        self.ui(lambda: self._show(items))

    def _show(self, items: list[dict]) -> None:
        self.gen += 1
        self.items, self.index = items, {it["path"]: i for i, it in enumerate(items)}
        self.asked, self.want = set(), set()
        self.canvas.yview_moveto(0)
        self._layout()
        self._buttons(True)
        self._count()
        root, gen = Path(self.cfg.root), self.gen
        for it in items:
            self.check_pool.submit(self._check, root, it, gen)

    def _check(self, root: Path, it: dict, gen: int) -> None:
        if gen != self.gen:
            return
        try:
            it["state"], it["file"], it["note"] = check_file(root, it)
        except OSError as e:
            it["state"], it["note"] = "bad", f"не читается: {e}"
        self.ui(lambda: (self._redraw(it), self._count()))

    def _thumb(self, it: dict, gen: int) -> None:
        path = it["path"]
        if gen != self.gen or path not in self.want:      # пока ждали очереди, уже пролистали
            self.asked.discard(path)
            return
        try:
            r = self.api.call("GET", f"/api/pc/preview/{it['id']}?k=s")
            if r.status_code == 200:
                self.thumbs[path] = r.content
            else:
                it["nothumb"] = True
        except Exception as e:  # noqa: BLE001
            log.info("превью %s: %s", path, e)
            self.asked.discard(path)
            return
        self.ui(lambda: self._redraw(it))

    # ---- сетка на холсте
    def _layout(self) -> None:
        w, h = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
        self.cols = max(1, (w - GAP) // (CARD_W + GAP))
        rows = -(-len(self.items) // self.cols)
        self.canvas.configure(scrollregion=(0, 0, w, max(h, rows * (CARD_H + GAP) + GAP)))
        self.canvas.delete("all")
        self.drawn = {}
        if not self.items:
            self.canvas.create_text(w // 2, 60, text="Ничего не помечено на удаление.", fill=DIM, font=("Segoe UI", 12))
            return
        self._render()

    def _soon(self) -> None:
        if not self._pending:
            self._pending = True
            self.root.after_idle(self._render)

    def _render(self) -> None:
        self._pending = False
        if not self.items:
            return
        top, h, rh = self.canvas.canvasy(0), self.canvas.winfo_height(), CARD_H + GAP
        r0, r1 = max(0, int((top - h) // rh)), int((top + 2 * h) // rh) + 1     # экран и по экрану сверху и снизу
        want = set(range(r0 * self.cols, min(len(self.items), r1 * self.cols)))
        for i in [i for i in self.drawn if i not in want]:
            self.canvas.delete(f"c{i}")
            del self.drawn[i]
        for i in sorted(want - self.drawn.keys()):
            self._card(i)
        self.want = {self.items[i]["path"] for i in want}
        v0, v1 = int(top // rh) * self.cols, (int((top + h) // rh) + 1) * self.cols       # сперва видимые
        for i in sorted(want, key=lambda i: (not v0 <= i < v1, i)):
            it = self.items[i]
            if it.get("id") and not it.get("nothumb") and it["path"] not in self.thumbs and it["path"] not in self.asked:
                self.asked.add(it["path"])
                self.thumb_pool.submit(self._thumb, it, self.gen)

    def _card(self, i: int) -> None:
        it, c, t = self.items[i], self.canvas, f"c{i}"
        x, y = GAP + (i % self.cols) * (CARD_W + GAP), GAP + (i // self.cols) * (CARD_H + GAP)
        pick = it["pick"]
        c.create_rectangle(x, y, x + CARD_W, y + CARD_H, fill=CARD, outline=ACCENT if pick else "#d6d6d6",
                           width=3 if pick else 1, tags=(t, "card"))
        ix, iy = x + (CARD_W - THUMB) // 2, y + 8
        c.create_rectangle(ix, iy, ix + THUMB, iy + THUMB, fill=IMGBG, outline="", tags=(t, "card", "img"))
        ph = None
        if data := self.thumbs.get(it["path"]):
            try:
                im = Image.open(io.BytesIO(data))
                im.thumbnail((THUMB, THUMB))
                ph = ImageTk.PhotoImage(im)
            except Exception:  # noqa: BLE001
                ph = None
        if ph is not None:
            c.create_image(ix + THUMB // 2, iy + THUMB // 2, image=ph, tags=(t, "card", "img"))
        else:
            c.create_text(ix + THUMB // 2, iy + THUMB // 2, fill=DIM, font=("Segoe UI", 9), tags=(t, "card", "img"),
                          text="нет превью" if not it.get("id") or it.get("nothumb") else "▶ видео…" if it["video"] else "…")
        ty = iy + THUMB + 6
        c.create_text(x + 8, ty, anchor="nw", text="☑" if pick else "☐", font=("Segoe UI Symbol", 14),
                      fill=TEXT if it["state"] != "checking" else "#bbbbbb", tags=(t, "card"))
        sym, color = STATE[it["state"]]
        c.create_text(x + 32, ty + 3, anchor="nw", text=sym, fill=color, font=("Segoe UI", 11, "bold"), tags=(t, "card"))
        name = it["path"].rsplit("/", 1)[-1]
        c.create_text(x + 52, ty + 5, anchor="nw", text=name if len(name) < 26 else name[:24] + "…", fill=TEXT,
                      font=("Segoe UI", 9), tags=(t, "card"))
        when = datetime.datetime.fromtimestamp(it["mtime"]).strftime("%d.%m.%Y") if it["mtime"] > 0 else "—"
        info = f"{human(it['size'])} · {when} · пометил {it['by']}" + (" · ролик живого фото" if it["live"] else "")
        note = it["note"]
        if it["state"] != "ok":
            note += "\n" + (it["path"] if len(it["path"]) <= 70 else "…" + it["path"][-69:])
        c.create_text(x + 8, ty + 30, anchor="nw", width=CARD_W - 16, text=info + "\n" + note, fill=DIM,
                      font=("Segoe UI", 8), tags=(t, "card"))
        self.drawn[i] = ph                          # держим ссылку, иначе картинка пропадёт

    def _redraw(self, it: dict) -> None:
        i = self.index.get(it["path"])
        if i is None or self.items[i] is not it or i not in self.drawn:
            return
        self.canvas.delete(f"c{i}")
        self._card(i)

    def _hit(self) -> dict | None:
        for tag in self.canvas.gettags("current"):
            if tag.startswith("c") and tag[1:].isdigit() and int(tag[1:]) < len(self.items):
                return self.items[int(tag[1:])]
        return None

    def _click(self, _e) -> None:
        it = self._hit()
        if it is None or it["state"] == "checking":
            return
        it["pick"] = not it["pick"]
        self._redraw(it)
        self._count()

    def _dbl(self, _e) -> None:
        if (it := self._hit()) is not None:
            self._big(it)

    def _big(self, it: dict) -> None:
        if not it.get("id"):
            return
        w = tk.Toplevel(self.root)
        w.title(it["path"])
        w.configure(bg="#000")
        lab = tk.Label(w, text="Загружаю…", fg="#ccc", bg="#000")
        lab.pack(fill="both", expand=True)

        def get():
            r = self.api.call("GET", f"/api/pc/preview/{it['id']}?k=p")
            if r.status_code == 200:
                im = Image.open(io.BytesIO(r.content))
                sw, sh = self.root.winfo_screenwidth() - 80, self.root.winfo_screenheight() - 160
                im.thumbnail((sw, sh))

                def show():
                    try:
                        ph = ImageTk.PhotoImage(im)
                        lab.configure(image=ph, text="")
                        lab.image = ph
                    except tk.TclError:
                        pass                        # окно уже закрыли
                self.ui(show)
        self.bg(get)

    def _select(self, on: bool) -> None:
        for it in self.items:
            it["pick"] = on and it["state"] == "ok"
        self._layout()
        self._count()

    def _count(self) -> None:
        picked = [it for it in self.items if it["pick"]]
        ok = sum(1 for it in self.items if it["state"] == "ok")
        wait = sum(1 for it in self.items if it["state"] == "checking")
        if not self.busy:
            n = len(self.items)
            self._progress(f"Проверяю файлы на диске: {n - wait} из {n}" if wait else None, n - wait, n)
        self.summary.configure(text=f"Помечено: {len(self.items)} · проверены: {ok}" + (f" · проверяю: {wait}" if wait else "")
                                    + f" · выбрано: {len(picked)} ({human(sum(max(0, it['size']) for it in picked))})"
                                    + "\nЩелчок по карточке — выбрать, двойной щелчок по фото — открыть крупно")
        if self.cfg.fp:
            self.say(f"Сервер {self.cfg.server} · ключ {self.cfg.fp}"
                     f"{' (программный, не в TPM)' if self.cfg.key_type == 'software' else ' (TPM)'}\n"
                     f"Папка архива: {self.cfg.root if len(self.cfg.root) <= 70 else '…' + self.cfg.root[-69:]}")

    # ---- действия
    def delete(self) -> None:
        picked = [it for it in self.items if it["pick"] and it["state"] == "ok"]
        skip = sum(1 for it in self.items if it["pick"] and it["state"] != "ok")
        if not picked:
            messagebox.showinfo(APP, "Ничего не выбрано (удалить можно только проверенные — с ✔).")
            return
        if not messagebox.askyesno(APP, f"Отправить в корзину {len(picked)} файл(ов), "
                                        f"{human(sum(it['size'] for it in picked))}?\n\nИз корзины их можно восстановить."
                                        + (f"\n\nНе проверенные ({skip}) удалены не будут." if skip else "")):
            return
        self._buttons(False)
        self.busy, self.stop = True, False
        self.b_stop.state(["!disabled"])
        self.b_stop.pack(side="right", padx=(10, 0))
        self._progress(f"Удаляю в корзину: 0 из {len(picked)}", 0, len(picked))
        self.bg(lambda: self._delete(picked))

    def _delete(self, picked: list[dict]) -> None:
        """Пачками по 50: перепроверка, в корзину одним вызовом, отчёт серверу с подписью TPM —
        после каждой пачки сетка и сервер уже знают, что удалено (можно остановить в любой момент)."""
        total, done, reported, failed, rep_err = len(picked), 0, 0, [], ""
        root = Path(self.cfg.root)
        for k in range(0, total, 50):
            if self.stop:
                break
            ready = []
            for it in picked[k:k + 50]:
                state, p, _n = check_file(root, it)      # перепроверка прямо перед удалением
                if state == "ok":
                    ready.append((it, p))
                else:
                    failed.append((it["path"], "изменился после проверки"))
            if ready:
                err = to_recycle_bin([p for _it, p in ready])
                gone = []
                for it, p in ready:
                    if p.exists():
                        failed.append((it["path"], err or "остался на месте"))
                        log.error("не удалён %s: %s", it["path"], err or "остался на месте")
                    else:
                        gone.append(it)
                        log.info("в корзину: %s", it["path"])
                if gone:
                    done += len(gone)
                    try:
                        reported += self._report(gone)
                    except Exception as e:  # noqa: BLE001
                        rep_err = str(e)
                        log.error("отчёт об удалении не принят: %s", e)
                    self.ui(lambda g=gone: self._drop(g))
            n = min(total, k + 50)
            self.ui(lambda n=n: self._progress(f"Удаляю в корзину: {n} из {total}", n, total))
        msg = f"В корзине: {done} из {total}." + (" Остановлено." if self.stop and done + len(failed) < total else "")
        if done:
            msg += f" Сервер отметил: {reported}."
        if rep_err:
            msg += f"\n\nСервер не принял отчёт ({rep_err}) — у удалённых останется пометка, в списке они будут " \
                   "«файла уже нет»: выбери их и «Снять пометку на удаление»."
        if failed:
            msg += f"\n\nНе удалены ({len(failed)}):\n" + "\n".join(f"{p} — {why}" for p, why in failed[:15])
        log.info("удаление: %s", msg.replace("\n", " "))

        def finish():
            self.busy = False
            self.b_stop.pack_forget()
            self._progress(None)
            messagebox.showinfo(APP, msg)
            self.load()
        self.ui(finish)

    def _report(self, gone: list[dict]) -> int:
        items = [{"path": it["path"], "sha": it.get("sha"), "size": it["size"]} for it in gone]
        ts = int(time.time())
        with self.api.mu:
            if not self.api.sid or time.time() > self.api.exp - 60:
                self.api._session()
            sid = self.api.sid
        sig = b64e(self.key.sign(delete_message(sid, ts, items)))      # свежая подпись ключа TPM
        r = self.api.call("POST", "/api/pc/deleted", {"items": items, "ts": ts, "sig": sig})
        if r.status_code != 200:
            raise ServerError(_err(r))
        return int(r.json().get("count", 0))

    def _drop(self, gone: list[dict]) -> None:
        """Удалённое — сразу из сетки."""
        g = {it["path"] for it in gone}
        self.items = [it for it in self.items if it["path"] not in g]
        self.index = {it["path"]: i for i, it in enumerate(self.items)}
        self._layout()
        self._count()

    def _stop(self) -> None:
        self.stop = True
        self.b_stop.state(["disabled"])
        self.prog_text.configure(text="Останавливаю после текущей пачки…")

    def _progress(self, text: str | None, done: int = 0, total: int = 1) -> None:
        if text is None:
            self.prog.pack_forget()
            return
        if not self.prog.winfo_ismapped():
            self.prog.pack(fill="x", before=self._wrap)
        self.prog_text.configure(text=text)
        self.prog_bar.configure(maximum=max(1, total), value=done)

    def unmark(self) -> None:
        self._send("/api/pc/unmark", "Снять пометку «на удаление» с {n} файл(ов)? Файлы останутся на месте "
                                     "и в скрытых — их можно будет пометить снова.")

    def restore(self) -> None:
        self._send("/api/pc/restore", "Вернуть {n} файл(ов) в галерею? Снимется пометка «на удаление» и «скрыто» "
                                      "у всех, кто их скрыл, — фото снова появятся в ленте.")

    def _send(self, url: str, question: str) -> None:
        picked = [it["path"] for it in self.items if it["pick"]]
        if not picked:
            messagebox.showinfo(APP, "Ничего не выбрано.")
            return
        if not messagebox.askyesno(APP, question.format(n=len(picked))):
            return
        self._buttons(False)

        def go():
            r = self.api.call("POST", url, {"paths": picked})
            if r.status_code == 404:
                raise ServerError("сервер не знает эту команду — обнови сервер")
            if r.status_code != 200:
                raise ServerError(_err(r))
            self.ui(self.load)
        self.bg(go)

    # ---- настройки
    def _pick_root(self) -> None:
        d = filedialog.askdirectory(title="Папка архива", initialdir=self.v_root.get() or None)
        if d:
            self.v_root.set(str(Path(d)))

    def save_settings(self) -> None:
        if self.busy:
            messagebox.showinfo(APP, "Дождись окончания удаления.")
            return
        srv = self.v_server.get().strip().rstrip("/")
        if not valid_server(srv):
            self.v_setmsg.set("Нужен адрес вида https://домен")
            return
        root = self.v_root.get().strip()
        if not root or not Path(root).is_dir():
            self.v_setmsg.set("Такой папки нет")
            return
        moved = srv != self.cfg.server
        self.cfg.server, self.cfg.root = srv, str(Path(root))
        if moved:                                        # другой сервер — другая привязка
            self.cfg.client_id = self.cfg.fp = ""
        self.cfg.save()
        log.info("настройки: сервер %s, папка %s", self.cfg.server, self.cfg.root)
        self.v_setmsg.set("Сохранено.")
        self._key_text()
        if self.api is None:
            return
        if moved:
            self.api.close()
            self.api = Api(self.cfg, self.key)
            self.v_setmsg.set("Сохранено. Новый адрес — нужна привязка: в админке «Привязать».")
            self.bg(self._pair)
        else:
            self.load()

    def repair(self) -> None:
        if self.busy or self.api is None:
            return
        if not messagebox.askyesno(APP, "Привязать этот ПК заново?\n\nСначала в админке: «Бэкап» → «Клиент на ПК» → "
                                        "«Привязать заново», потом «Да» здесь."):
            return
        self.cfg.client_id = self.cfg.fp = ""
        self.cfg.save()
        self._key_text()
        self.bg(self._pair)

    def _save_upd(self) -> None:
        self.cfg.updates = bool(self.v_upd.get())
        self.cfg.save()

    def check_update(self, quiet: bool = False) -> None:
        """quiet — сама при запуске: спрашивает, только если есть новая версия."""
        self.v_updmsg.set("Проверяю…")

        def run():
            try:
                u = fetch_update()
            except Exception as e:  # noqa: BLE001
                log.warning("проверка обновлений: %s", e)
                self.ui(lambda: self.v_updmsg.set(f"Не удалось проверить: {e}"))
                return
            self.ui(lambda: self._update_found(u))
        threading.Thread(target=run, daemon=True).start()

    def _update_found(self, u) -> None:
        if not u:
            self.v_updmsg.set(f"Установлена последняя версия {VERSION}.")
            return
        ver, text, sha = u
        self.v_updmsg.set(f"Доступна версия {ver} (сейчас {VERSION}).")
        if self.busy:
            return
        if not messagebox.askyesno(APP, f"Доступно обновление: {ver} (сейчас {VERSION}).\n\nОбновить сейчас? "
                                        "Программа перезапустится."):
            return
        try:
            install(text)
        except Exception as e:  # noqa: BLE001
            log.exception("обновление не удалось")
            messagebox.showerror(APP, f"Обновление не удалось: {e}")
            return
        log.info("обновлено до %s (коммит %s), перезапуск", ver, sha[:10])
        restart()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
        self.check_pool.shutdown(wait=False, cancel_futures=True)
        self.thumb_pool.shutdown(wait=False, cancel_futures=True)
        if self.api:
            self.api.close()


class _UiLog(logging.Handler):
    """Журнал — и во вкладку «Журнал» (через очередь окна: из рабочих потоков в tk нельзя)."""

    def __init__(self, app: "App"):
        super().__init__(logging.INFO)
        self.app = app
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

    def emit(self, record) -> None:
        try:
            line = self.format(record).split("\n", 1)[0]
        except Exception:  # noqa: BLE001
            return
        self.app.ui(lambda: self.app._log_line(line))


def valid_server(s: str) -> bool:
    return bool(re.match(r"^https://[^/\s]+$", s) or re.match(r"^http://(localhost|127\.0\.0\.1)(:\d+)?$", s))


def ask_text(parent, title: str, prompt: str) -> str:
    from tkinter import simpledialog
    return simpledialog.askstring(title, prompt, parent=parent) or ""


def _ensure_deps() -> bool:
    global httpx, Image, ImageTk, ec, hashes, serialization, decode_dss_signature, HKDF
    missing = [pip for mod, pip in DEPS if importlib.util.find_spec(mod) is None]
    if missing:
        root = tk.Tk()
        root.withdraw()
        py = Path(sys.executable)
        py = py.with_name("python.exe") if py.name.lower() == "pythonw.exe" and py.with_name("python.exe").exists() else py
        cmd = [str(py), "-m", "pip", "install", *missing]
        if not messagebox.askyesno(APP, "Для работы нужны библиотеки: " + ", ".join(missing) +
                                   f".\n\nУстановить их сейчас в этот Python?\n{py}"):
            root.destroy()
            return False
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900, creationflags=0x08000000 if IS_WIN else 0)
            log.info("pip install %s: %s\n%s", " ".join(missing), r.returncode, (r.stdout + r.stderr)[-3000:])
            ok = r.returncode == 0
        except Exception as e:  # noqa: BLE001
            log.error("pip install: %s", e)
            ok = False
        if not ok:
            messagebox.showerror(APP, "Не получилось установить. Выполните в командной строке:\n" + " ".join(cmd))
            root.destroy()
            return False
        root.destroy()
        importlib.invalidate_caches()
    try:
        import httpx as _h
        from PIL import Image as _i, ImageTk as _t
        from cryptography.hazmat.primitives import hashes as _hs, serialization as _se
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as _dd
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _hk
    except ImportError as e:
        log.error("нет библиотеки %s", e.name)
        return False
    httpx, Image, ImageTk, hashes, serialization, ec, decode_dss_signature, HKDF = _h, _i, _t, _hs, _se, _ec, _dd, _hk
    return True


def main() -> None:
    h = logging.handlers.RotatingFileHandler(app_dir() / "pc.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[h], format="%(asctime)s %(levelname)s %(message)s")
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    log.info("старт %s: %s", VERSION, SCRIPT)
    if not _ensure_deps():
        return
    App(Config()).run()


if __name__ == "__main__":
    main()
