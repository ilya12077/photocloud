"""Photocloud — бэкап: копирует оригиналы фото и видео с сервера photocloud на этот компьютер.

Один файл, больше ничего не нужно: двойной щелчок (откроется через pythonw, без консоли).
Недостающие библиотеки (httpx, pystray, pillow) программа предложит поставить сама.
Дальше живёт значком в трее; автозапуск при входе в Windows и обновление с GitHub — в настройках.
Настройки, журнал и служебные файлы — в %USERPROFILE%\\.photocloud-backup.

Папка бэкапа:
    Архив\\…        — копия архива один в один (пути и даты изменения как на ПК)
    Версии\\…       — прежние варианты изменённых файлов и повреждённые копии, хранятся всегда
    Удалённые\\…    — файлы, которых больше нет на ПК, хранятся всегда
    .photocloud-backup\\state.db, tmp\\ — своя база и недокачанные файлы
"""
from __future__ import annotations

import base64
import collections
import datetime
import hashlib
import importlib
import importlib.util
import json
import logging
import logging.handlers
import os
import queue
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# сторонние библиотеки: если их нет, main() предложит поставить и подгрузит
try:
    import httpx
except ImportError:
    httpx = None
try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = ImageDraw = None

VERSION = "1.3.0"           # по этой строке клиент сравнивает себя с версией на GitHub
DEPS = (("httpx", "httpx>=0.27"), ("pystray", "pystray>=0.19"), ("PIL", "pillow>=10"))
log = logging.getLogger("pcbackup")
IS_WIN = sys.platform == "win32"


# ======================================================================== настройки
# Настройки клиента: %USERPROFILE%\\.photocloud-backup\\config.json.
# Токен хранится зашифрованным средствами Windows (DPAPI): расшифровать его может
# только эта учётная запись на этом компьютере.
def app_dir() -> Path:
    """Настройки, журнал и служебные файлы. В Windows — %USERPROFILE%\\.photocloud-backup, а не %APPDATA%:
    Python из Microsoft Store (и venv на его основе) прячет записанное в %APPDATA% в свою песочницу,
    и в Проводнике этих файлов не видно. Настройки из старого места переносятся один раз."""
    if not IS_WIN:
        d = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "photocloud-backup"
        d.mkdir(parents=True, exist_ok=True)
        return d
    d = Path(os.environ.get("USERPROFILE") or Path.home()) / ".photocloud-backup"
    d.mkdir(parents=True, exist_ok=True)
    old = Path(os.environ.get("APPDATA") or Path.home()) / "photocloud-backup" / "config.json"
    if not (d / "config.json").exists() and old.exists():
        try:
            shutil.copyfile(old, d / "config.json")
        except OSError:
            pass
    return d


# ---------------------------------------------------------------- DPAPI

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> _Blob:
        buf = ctypes.create_string_buffer(data, len(data))
        b = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        b._buf = buf                      # буфер живёт, пока жив сам blob
        return b

    def _take(b: _Blob) -> bytes:
        out = ctypes.string_at(b.pbData, b.cbData)
        ctypes.windll.kernel32.LocalFree(b.pbData)
        return out

    _ENTROPY = b"photocloud-backup"

    def protect(data: bytes) -> bytes:
        out, src, ent = _Blob(), _blob(data), _blob(_ENTROPY)
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(src), "photocloud", ctypes.byref(ent),
                                                      None, None, 0x1, ctypes.byref(out)):   # UI_FORBIDDEN
            raise OSError("CryptProtectData")
        return _take(out)

    def unprotect(data: bytes) -> bytes:
        out, src, ent = _Blob(), _blob(data), _blob(_ENTROPY)
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent),
                                                        None, None, 0x1, ctypes.byref(out)):
            raise OSError("CryptUnprotectData")
        return _take(out)
else:                                      # для проверки на Linux: без шифрования
    def protect(data: bytes) -> bytes:
        return data

    def unprotect(data: bytes) -> bytes:
        return data


class Config:
    FIELDS = ("server", "root", "limit_mbps", "paused", "wake_on_start", "autostart", "min_free_gb", "hide_on_autostart",
              "check_updates", "update_branch")

    def __init__(self, path: Path | None = None):
        self.path = path or app_dir() / "config.json"
        self.server = ""
        self.token = ""
        self.root = ""
        self.limit_mbps = 0.0
        self.min_free_gb = 10.0           # меньше стольких ГБ свободно на диске — новые файлы не скачиваем
        self.paused = False
        self.wake_on_start = True
        self.autostart = True
        self.hide_on_autostart = True     # при автозапуске — только значок в трее, без окна
        self.check_updates = True         # искать новую версию клиента на GitHub
        self.update_branch = ""           # пусто — основная ветка (master)
        self._mu = threading.Lock()
        self.load()

    def load(self) -> None:
        self.load_error = ""
        if not self.path.exists():
            log.info("настройки: %s — файла нет, нужна настройка", self.path)
            return
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            self.load_error = f"{type(e).__name__}: {e}"
            log.error("настройки: %s не читается: %s", self.path, self.load_error)
            return
        for k in self.FIELDS:
            if k in d:
                setattr(self, k, d[k])
        enc = d.get("token_dpapi")
        if enc:
            try:
                self.token = unprotect(base64.b64decode(enc)).decode()
            except (OSError, ValueError) as e:
                self.token = ""               # другой пользователь/компьютер — токен надо ввести заново
                self.load_error = "токен не расшифровался (другая учётная запись Windows?)"
                log.error("настройки: токен не расшифровался: %s", e)
        log.info("настройки: %s — сервер %s, папка %s, токен %s", self.path, self.server or "—",
                 self.root or "—", "есть" if self.token else "нет")

    def save(self) -> None:
        with self._mu:
            d = {k: getattr(self, k) for k in self.FIELDS}
            try:
                if self.token:
                    d["token_dpapi"] = base64.b64encode(protect(self.token.encode())).decode()
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
                os.replace(tmp, self.path)
            except Exception:
                log.exception("настройки: не удалось сохранить %s", self.path)
                raise


# ======================================================================== Windows: автозапуск, один экземпляр
# Windows: автозапуск, один экземпляр, открыть папку.
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "PhotocloudBackup"


def _pythonw() -> str:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if w.exists() else exe)


def set_autostart(on: bool, script: Path) -> None:
    """Запуск при входе в Windows — запись в реестре текущего пользователя (без прав админа)."""
    if not IS_WIN:
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{_pythonw()}" "{script}" --tray')
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except FileNotFoundError:
                pass


def wait_pid(pid: int, timeout: float) -> None:
    """Дождаться завершения процесса pid (не дольше timeout секунд)."""
    import time
    if IS_WIN:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)        # SYNCHRONIZE
        if h:
            ctypes.windll.kernel32.WaitForSingleObject(h, int(timeout * 1000))
            ctypes.windll.kernel32.CloseHandle(h)
        return
    t = time.time()
    while time.time() - t < timeout:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.2)


def open_folder(p: str) -> None:
    if IS_WIN:
        os.startfile(p)  # noqa: S606
    else:
        subprocess.Popen(["xdg-open", p])


class SingleInstance:
    """Второй запуск не создаёт второй клиент, а показывает окно первого.
    Первый экземпляр слушает 127.0.0.1 на случайном порту, номер — в файле рядом с настройками."""

    def __init__(self, folder: Path, on_show):
        self.port_file = folder / "instance.port"
        self.on_show = on_show
        self.sock: socket.socket | None = None
        self._mutex = None

    def acquire(self) -> bool:
        if IS_WIN:
            import ctypes
            self._mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\PhotocloudBackup")
            if ctypes.windll.kernel32.GetLastError() == 183:       # ERROR_ALREADY_EXISTS
                self._poke()
                return False
        elif self._poke():
            return False
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(2)
        self.sock = s
        self.port_file.write_text(str(s.getsockname()[1]))
        threading.Thread(target=self._serve, name="instance", daemon=True).start()
        return True

    def _poke(self) -> bool:
        try:
            port = int(self.port_file.read_text())
            with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                c.sendall(b"show")
            return True
        except (OSError, ValueError):
            return False

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                c.settimeout(2)
                try:
                    if c.recv(16) == b"show":
                        self.on_show()
                except OSError:
                    pass

winutil = SimpleNamespace(set_autostart=set_autostart, open_folder=open_folder, wait_pid=wait_pid,
                          SingleInstance=SingleInstance)


# ======================================================================== движок бэкапа
# Движок бэкапа: сверка с сервером photocloud и копирование оригиналов.
#
# Без интерфейса — окно и значок в трее только читают состояние (Engine.snapshot())
# и вызывают методы управления (pause/resume/sync_now/wake_now/confirm_delete).
#
# Папка бэкапа:
#     Архив\\…        — копия архива один в один (пути и даты изменения как на ПК)
#     Версии\\…       — прежние варианты изменённых файлов, хранятся всегда
#     Удалённые\\…    — файлы, которых больше нет на ПК, хранятся всегда
#     .photocloud-backup\\state.db, tmp\\ — своя база и недокачанные файлы

ARCHIVE, VERSIONS, DELETED, META = "Архив", "Версии", "Удалённые", ".photocloud-backup"
CHUNK = 256 * 1024
PASS_MAX = 15 * 60          # с: проход не дольше — потом свежий список (досчитались новые хеши)
IDLE_EVERY = 10             # с: всё скопировано — спрашивать сервер о новом так часто
PC_OFF_EVERY = 10           # с: ПК выключен — проверять так часто
LOCAL_EVERY = 60            # с: сверять папку бэкапа с базой (на месте ли файлы): удалил копию — через минуту скачается
DISK_EVERY = 10             # с: мало места — так часто смотреть, не освободилось ли
VERIFY_EVERY = 30 * 86400   # с: проверка копий (пересчёт хешей скопированного) — раз в 30 дней
VERIFY_SLICE = 20           # с: проверять кусками, между ними — обычный опрос сервера
REPORT_EVERY = 5 * 60       # с: отчёт серверу, если состояние не меняется
REPORT_COPYING = 5          # с: а во время копирования — так часто (админка видит ход в реальном времени)
DELETE_SUSPICIOUS = (100, 0.05)   # больше стольких И больше такой доли — ждём подтверждения


class Stop(Exception):
    """Пауза, выход или смена настроек — текущую загрузку прерываем, недокачанное остаётся."""


class PcOff(Exception):
    pass


class Gone(Exception):
    """Файла уже нет на ПК: список на сервере ещё старый, сервер его сейчас обновляет."""


class DiskFull(Exception):
    def __init__(self, free: int, keep: int, need: int):
        super().__init__(f"свободно {human(free)}, порог {human(keep)}")
        self.free, self.keep, self.need = free, keep, need


class AuthError(Exception):
    pass


def lp(p: Path) -> str:
    """Windows: длинные пути (> 260 символов) — через префикс \\\\?\\."""
    s = str(p)
    if IS_WIN and not s.startswith("\\\\?\\"):
        s = os.path.abspath(s)
        s = "\\\\?\\UNC\\" + s[2:] if s.startswith("\\\\") else "\\\\?\\" + s
    return s


def safe_rel(rel: str) -> list[str]:
    """Путь с сервера -> части пути. Никаких «..», дисков и абсолютных путей."""
    parts = rel.split("/")
    bad = '<>:"\\|?*'
    if not rel or len(rel) > 2000 or any(not x or x in (".", "..") or any(c in x for c in bad)
                                         or any(ord(c) < 32 for c in x) for x in parts):
        raise ValueError(f"недопустимый путь: {rel!r}")
    return parts


def stamp(ts: float | None = None) -> str:
    return datetime.datetime.fromtimestamp(ts or time.time()).strftime("%Y-%m-%d %H-%M-%S")


def human(n: float) -> str:
    for unit, k in (("ГБ", 2**30), ("МБ", 2**20), ("КБ", 2**10)):
        if n >= k:
            return f"{n / k:.1f} {unit}".replace(".", ",")
    return f"{int(n)} Б"


class State:
    """Своя база в папке бэкапа: что уже лежит в Архиве и журнал событий."""

    def __init__(self, root: Path):
        d = root / META
        os.makedirs(lp(d / "tmp"), exist_ok=True)
        if IS_WIN:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(lp(d), 0x2)      # скрытая папка
        self.path = d / "state.db"
        self.con = sqlite3.connect(lp(self.path), check_same_thread=False, isolation_level=None, timeout=10)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        self.con.execute("""CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime INTEGER NOT NULL,
            sha TEXT NOT NULL, copied REAL NOT NULL) WITHOUT ROWID""")
        self.con.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL, detail TEXT NOT NULL)""")
        self.con.execute("""CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID""")
        cols = {r[1] for r in self.con.execute("PRAGMA table_info(files)")}
        if "verified" not in cols:            # когда копию последний раз сверяли с хешем (клиент 1.2+)
            self.con.execute("ALTER TABLE files ADD COLUMN verified REAL NOT NULL DEFAULT 0")
            self.con.execute("UPDATE files SET verified = copied")
        self.mu = threading.Lock()

    def files(self) -> dict[str, tuple[int, int, str]]:
        with self.mu:
            return {p: (s, m, h) for p, s, m, h in self.con.execute("SELECT path, size, mtime, sha FROM files")}

    _PUT = "INSERT OR REPLACE INTO files(path, size, mtime, sha, copied, verified) VALUES(?, ?, ?, ?, ?, ?)"

    def put(self, path: str, size: int, mtime: int, sha: str) -> None:
        now = time.time()                       # только что скачан и сверен — он же проверен
        with self.mu:
            self.con.execute(self._PUT, (path, size, mtime, sha, now, now))

    def put_many(self, rows) -> None:
        """rows: (path, size, mtime, sha, ts)"""
        with self.mu:
            self.con.execute("BEGIN")
            self.con.executemany(self._PUT, [(*r, r[4]) for r in rows])
            self.con.execute("COMMIT")

    def unverified(self, since: float, limit: int) -> list[tuple[str, int, str]]:
        with self.mu:
            return list(self.con.execute("SELECT path, size, sha FROM files WHERE verified < ? LIMIT ?", (since, limit)))

    def count_unverified(self, since: float) -> int:
        with self.mu:
            return self.con.execute("SELECT count(*) FROM files WHERE verified < ?", (since,)).fetchone()[0]

    def set_verified(self, path: str, ts: float) -> None:
        with self.mu:
            self.con.execute("UPDATE files SET verified = ? WHERE path = ?", (ts, path))

    def kv_get(self, key: str) -> str | None:
        with self.mu:
            r = self.con.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return r[0] if r else None

    def kv_set(self, key: str, value) -> None:
        with self.mu:
            if value is None:
                self.con.execute("DELETE FROM kv WHERE key = ?", (key,))
            else:
                self.con.execute("INSERT OR REPLACE INTO kv(key, value) VALUES(?, ?)", (key, str(value)))

    def drop(self, path: str) -> None:
        with self.mu:
            self.con.execute("DELETE FROM files WHERE path = ?", (path,))

    def event(self, kind: str, path: str, detail: str = "") -> None:
        with self.mu:
            self.con.execute("INSERT INTO events(ts, kind, path, detail) VALUES(?, ?, ?, ?)",
                             (time.time(), kind, path, detail))

    def events(self, n: int = 300) -> list[tuple]:
        with self.mu:
            return list(self.con.execute("SELECT ts, kind, path, detail FROM events ORDER BY id DESC LIMIT ?", (n,)))

    def close(self) -> None:
        with self.mu:
            self.con.close()


class Api:
    def __init__(self, server: str, token: str):
        self.base = server.rstrip("/")
        self.c = httpx.Client(headers={"authorization": f"Bearer {token}",
                                       "user-agent": f"photocloud-backup/{VERSION}"},
                              timeout=httpx.Timeout(60, connect=15), follow_redirects=False)

    def _check(self, r: httpx.Response) -> httpx.Response:
        if r.status_code == 401:
            raise AuthError("сервер не принял токен")
        if r.status_code == 429:
            raise AuthError(f"сервер временно заблокировал адрес (подождите {r.headers.get('retry-after', '?')} с)")
        if r.status_code == 503:
            raise PcOff()
        r.raise_for_status()
        return r

    def status(self) -> dict:
        return self._check(self.c.get(self.base + "/api/backup/status")).json()

    def wake(self) -> dict:
        r = self.c.post(self.base + "/api/backup/wake")
        if r.status_code == 403:
            raise AuthError("этому пользователю нельзя включать компьютер")
        return self._check(r).json()

    def manifest(self, etag: str | None):
        h = {"accept-encoding": "gzip"}
        if etag:
            h["if-none-match"] = etag
        r = self.c.get(self.base + "/api/backup/manifest", headers=h)
        if r.status_code == 304:
            return None, etag
        self._check(r)
        return r.json(), r.headers.get("etag")

    def report(self, rep: dict) -> None:
        try:
            self.c.post(self.base + "/api/backup/report", json=rep, timeout=20)
        except httpx.HTTPError:
            pass

    def stream(self, rel: str, start: int):
        h = {"accept-encoding": "identity"}
        if start:
            h["range"] = f"bytes={start}-"
        # z=1 — сжатие блоками (сервер 1.6+); старый сервер параметр не знает и отдаёт файл как есть по Range
        return self.c.stream("GET", f"{self.base}/api/backup/file?path={quote(rel, safe='')}&z=1&start={start}", headers=h,
                             timeout=httpx.Timeout(90, connect=15))

    def close(self) -> None:
        self.c.close()


class Throttle:
    """Ограничение скорости: limit() -> байт/с (0 — без ограничения)."""

    def __init__(self, limit):
        self.limit = limit
        self.t0, self.sent = time.monotonic(), 0

    def wait(self, n: int, stop: threading.Event) -> None:
        rate = self.limit()
        now = time.monotonic()
        if not rate:
            self.t0, self.sent = now, 0
            return
        if now - self.t0 > 2:                 # окно 2 с: лимит меняется на лету
            self.t0, self.sent = now, 0
        self.sent += n
        delay = self.sent / rate - (now - self.t0)
        while delay > 0 and not stop.is_set():
            time.sleep(min(delay, 0.2))
            delay -= 0.2


class Engine(threading.Thread):
    def __init__(self, cfg):
        super().__init__(name="engine", daemon=True)
        self.cfg = cfg                          # объект с полями server, token, root, limit_mbps, paused, wake_on_start
        self.ev = threading.Event()             # разбудить цикл (кнопки, смена настроек)
        self.halt = threading.Event()           # прервать текущую работу
        self.quit = False
        self._want_sync = self._want_wake = self._confirm = self._want_verify = False
        self._reload = True
        self.mu = threading.Lock()
        self.log = collections.deque(maxlen=300)
        self.st = dict(state="setup", text="Укажите сервер, токен и папку в настройках", detail="",
                       files=0, bytes=0, have_files=0, have_bytes=0, left_files=0, left_bytes=0,
                       waiting_hash=0, current="", cur_done=0, cur_size=0, speed=0.0, errors=0,
                       pending_delete=0, copied=0, copied_bytes=0, last_ok=0.0, server="",
                       wire_bytes=0, raw_bytes=0,
                       verifying=False, verify_done=0, verify_total=0, verify_bad=0, verify_last=0.0,
                       verify_next=0.0)
        self.api: Api | None = None
        self.db: State | None = None
        self.root: Path | None = None
        self._woke = False
        self._speed_t, self._speed_b = time.monotonic(), 0
        self._last_report = 0.0
        self._reported = ""                    # состояние из последнего отчёта
        self._checked_local = 0.0              # когда последний раз проверяли папку бэкапа
        self._idle = False                     # прошлый проход всё сделал — ждём новое
        self._manifest = None
        self._etag = None

    # ------------------------------------------------------------ управление (из интерфейса)

    def snapshot(self) -> dict:
        with self.mu:
            d = dict(self.st)
        d["paused"] = self.cfg.paused
        d["log"] = list(self.log)
        return d

    def pause(self) -> None:
        self.cfg.paused = True
        self.cfg.save()
        self.halt.set()
        self.ev.set()

    def resume(self) -> None:
        self.cfg.paused = False
        self.cfg.save()
        self.ev.set()

    def sync_now(self) -> None:
        self._want_sync = True
        self._checked_local = 0.0              # и папку бэкапа сверить сразу
        self.ev.set()

    def wake_now(self) -> None:
        self._want_wake = True
        self.ev.set()

    def verify_now(self) -> None:
        self._want_verify = True
        self.ev.set()

    def confirm_delete(self) -> None:
        self._confirm = True
        self.ev.set()

    def reconfigure(self) -> None:
        self._reload = True
        self.halt.set()
        self.ev.set()

    def shutdown(self) -> None:
        self.quit = True
        self.halt.set()
        self.ev.set()

    # ------------------------------------------------------------ состояние

    def _set(self, **kw) -> None:
        with self.mu:
            self.st.update(kw)

    def _note(self, text: str, kind: str = "info", path: str = "") -> None:
        log.info("%s %s", text, path)
        self.log.appendleft((time.time(), kind, text, path))

    def _sleep(self, sec: float) -> None:
        self.ev.wait(sec)
        self.ev.clear()

    # ------------------------------------------------------------ главный цикл

    def run(self) -> None:
        while not self.quit:
            try:
                self._loop_once()
            except Stop:
                pass
            except DiskFull as e:
                self._disk_full(e)
            except AuthError as e:
                self._set(state="error", text=str(e), detail="Проверьте токен в настройках")
                self._note(str(e), "error")
                self._sleep(3600)            # не долбим сервер: каждая ошибка токена — шаг к блокировке IP
            except httpx.HTTPError as e:
                self._set(state="error", text="Нет связи с сервером", detail=type(e).__name__)
                self._sleep(60)
            except Exception as e:  # noqa: BLE001
                log.exception("ошибка")
                self._set(state="error", text="Ошибка", detail=f"{type(e).__name__}: {e}"[:200])
                self._note(f"ошибка: {type(e).__name__}: {e}", "error")
                self._sleep(120)
        self._close()

    def _disk_full(self, e: "DiskFull") -> None:
        """Места мало: раз в 10 с смотрим диск (без запросов к серверу). Как только места хватает
        на файл, который не влез, или поменяли порог в настройках — продолжаем."""
        self._note(f"мало места на диске ({e}) — новые файлы не скачиваю", "error")
        self._report("disk_full", f"мало места: {e}")
        self._want_sync = False                   # «Проверить сейчас» — заново проверить и место тоже
        while not (self.quit or self._reload or self.cfg.paused or self._want_sync):
            keep = int(max(0.0, float(self.cfg.min_free_gb or 0)) * 2**30)
            try:
                free = shutil.disk_usage(str(self.root)).free
            except OSError:
                free = 0
            if free - e.need >= keep:
                self._note(f"место освободилось ({human(free)}) — продолжаю")
                return
            self._set(state="disk_full", text="Мало места на диске", current="", speed=0.0,
                      detail=f"Свободно {human(free)}, а оставлять нужно {human(keep)}. Новые файлы не "
                             f"скачиваются — освободите место или уменьшите порог в настройках.")
            self._sleep(DISK_EVERY)

    def _close(self) -> None:
        if self.api:
            self.api.close()
            self.api = None
        if self.db:
            self.db.close()
            self.db = None

    def _open(self) -> bool:
        self._reload = False
        self.halt.clear()
        self._close()
        c = self.cfg
        if not (c.server and c.token and c.root):
            self._set(state="setup", text="Укажите сервер, токен и папку в настройках", detail="")
            return False
        self.root = Path(c.root)
        os.makedirs(lp(self.root / ARCHIVE), exist_ok=True)
        self.db = State(self.root)
        self.api = Api(c.server, c.token)
        self._manifest, self._etag, self._woke = None, None, False
        if not self.db.files() and any(os.scandir(lp(self.root / ARCHIVE))):
            self._rebuild_db()
        return True

    def _loop_once(self) -> None:
        if self._reload and not self._open():
            self._sleep(3600)
            return
        if self.cfg.paused:
            self._set(state="paused", text="Пауза", detail="Копирование остановлено, интернет не используется",
                      current="", speed=0.0)
            self._report("paused")
            self.halt.clear()
            self._sleep(3600)
            return
        self.halt.clear()
        st = self.api.status()
        self._set(server=st.get("server", ""))
        if st["pc"] != "up" and ((self.cfg.wake_on_start and not self._woke) or self._want_wake):
            self._wake(st)
            return
        self._want_wake = False
        if st["pc"] != "up":
            waking = st["pc"] == "waking"
            self._set(state="pc_off", text="Компьютер просыпается…" if waking else "Компьютер выключен",
                      detail="Копирование продолжится, когда он включится", current="", speed=0.0)
            self._report("pc_off")
            more = self._verify_slice()        # проверке копий ПК не нужен — можно и сейчас
            self._sleep(0 if more else (15 if waking else PC_OFF_EVERY))
            return
        self._woke = True              # ПК уже включён — будить при запуске не нужно
        if self._pass():
            # всё скопировано — в свободное время проверяем уже скопированное (кусками по 20 с)
            more = self._verify_slice() if self.st["state"] in ("done", "waiting") else False
            self._sleep(0 if (more or self._want_sync) else IDLE_EVERY)
        self._want_sync = False

    def _wake(self, st: dict) -> None:
        self._woke, self._want_wake = True, False
        if not st.get("can_wake"):
            self._note("этому пользователю нельзя включать компьютер — жду, пока его включат", "warn")
            return
        try:
            self.api.wake()
            self._note("разбудил компьютер")
            self._set(state="pc_off", text="Компьютер просыпается…", detail="")
        except AuthError as e:
            self._note(str(e), "warn")
        except httpx.HTTPStatusError as e:
            self._note(f"не удалось разбудить компьютер (HTTP {e.response.status_code})", "warn")
        self._sleep(10)

    # ------------------------------------------------------------ проход

    def _pass(self) -> bool:
        """True — всё, что можно, сделано (дальше ждём новое); False — сразу следующий проход
        (прервали по времени, выключился ПК, обрыв связи)."""
        m, etag = self.api.manifest(self._etag)
        if m is None and self._idle and time.monotonic() - self._checked_local < LOCAL_EVERY:
            # на сервере ничего не поменялось, у нас всё скопировано — проверять нечего
            self._set(detail=f"Проверено в {time.strftime('%H:%M:%S')}. Новое проверяется каждые {IDLE_EVERY} с.")
            self._report(self.st["state"])
            return True
        if m is not None:
            self._manifest, self._etag = m, etag
        m = self._manifest
        self._idle = False
        self._checked_local = time.monotonic()
        files = {f[0]: f for f in m["files"]}            # путь -> [путь, размер, mtime, дата, sha]
        local = self._verify_local(self.db.files())
        plan = self._plan(files, local)
        moves, copies, downloads, deletes, waiting = plan
        total_bytes = sum(f[1] for f in files.values())
        left_bytes = sum(files[p][1] for p in downloads)
        self._set(files=len(files), bytes=total_bytes, waiting_hash=waiting,
                  left_files=len(downloads) + waiting, left_bytes=left_bytes + sum(f[1] for f in files.values() if not f[4]),
                  have_files=len(files) - len(downloads) - waiting,     # переносы/копии рядом — секунды
                  have_bytes=total_bytes - left_bytes - sum(f[1] for f in files.values() if not f[4]))

        for src, dst in moves:
            self._move(src, files[dst])
        for src, dst in copies:
            self._copy_local(src, files[dst])
        self._deletes(deletes, local, complete=m.get("complete", False))

        t0 = time.monotonic()
        downloads.sort(key=lambda p: files[p][3], reverse=True)      # сначала новые снимки
        left_files, left_b = len(downloads) + waiting, left_bytes + sum(f[1] for f in files.values() if not f[4])
        gone = 0
        for p in downloads:
            if self.cfg.paused or self._reload or self.quit:
                raise Stop()
            f = files[p]
            self._set(state="copying", text="Копирую", detail="", left_files=left_files, left_bytes=left_b)
            try:
                self._download(f)
                left_files -= 1
                left_b -= f[1]
            except PcOff:
                self._note("компьютер выключился — продолжу, когда включится", "warn")
                self._set(state="pc_off", text="Компьютер выключен", current="", speed=0.0)
                self._report("pc_off")
                return False
            except (Stop, AuthError, DiskFull):
                raise
            except Gone:
                gone += 1
                self._note("удалён на компьютере — уберу в «Удалённые», когда сервер обновит список", "info", p)
                if gone >= 20:
                    return True                    # много подряд — сервер пересканирует папки, ждём список
                continue
            except httpx.HTTPError as e:
                self._error(p, f"сеть: {type(e).__name__}")
                return False
            except Exception as e:  # noqa: BLE001
                self._error(p, f"{type(e).__name__}: {e}")
            self._set(have_files=self.st["have_files"] + 1, have_bytes=self.st["have_bytes"] + f[1],
                      left_files=left_files, left_bytes=left_b)
            self._report("copying")
            if time.monotonic() - t0 > PASS_MAX:
                return False                       # свежий список: могли досчитаться новые хеши
        self._set(current="", speed=0.0, last_ok=time.time())
        if waiting:
            self._set(state="waiting", text="Жду хеши с сервера",
                      detail=f"Сервер ещё считает контрольные суммы: {waiting} файлов")
        elif self.st.get("pending_delete"):
            pass                                   # ждём «Подтвердить» — состояние уже выставлено
        else:
            self._set(state="done", text="Всё скопировано",
                      detail=f"Проверено в {time.strftime('%H:%M:%S')}. Новое проверяется каждые {IDLE_EVERY} с.")
        self._report(self.st["state"])
        self._idle = not waiting and not self.st.get("pending_delete")
        return True                              # подождать IDLE_EVERY (и когда ждём хеши — тоже)

    def _plan(self, files: dict, local: dict):
        missing = {p: v for p, v in local.items() if p not in files}
        by_sha_missing: dict[str, list[str]] = {}
        for p, (_s, _m, h) in missing.items():
            by_sha_missing.setdefault(h, []).append(p)
        by_sha_have = {h: p for p, (_s, _m, h) in local.items() if p in files}
        moves, copies, downloads, waiting = [], [], [], 0
        for p, f in files.items():
            sha = f[4]
            if not sha:
                waiting += 1
                continue
            have = local.get(p)
            if have and have[2] == sha:
                if have[1] != f[2]:                               # тот же файл, другая дата изменения
                    self._touch(p, f)
                continue
            if not have and by_sha_missing.get(sha):
                moves.append((by_sha_missing[sha].pop(), p))      # переименован / перенесён
                continue
            if not have and sha in by_sha_have:
                copies.append((by_sha_have[sha], p))              # такой же файл уже есть рядом
                continue
            downloads.append(p)
        used = {src for src, _ in moves}
        deletes = [p for p in missing if p not in used]
        return moves, copies, downloads, deletes, waiting

    def _scan_archive(self) -> dict[str, int]:
        """Что реально лежит в Архиве: путь -> размер. Обход папок (os.scandir) — в Windows размер
        приходит вместе со списком файла, без открытия каждого: 40 тысяч файлов — доли секунды."""
        top = lp(self.root / ARCHIVE)
        out: dict[str, int] = {}
        stack = [(top, "")]
        while stack:
            d, prefix = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    rel = f"{prefix}/{e.name}" if prefix else e.name
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append((e.path, rel))
                        elif e.is_file(follow_symlinks=False):
                            out[rel] = e.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        return out

    def _verify_local(self, local: dict) -> dict:
        """Файлы, которые пропали из Архива или изменились руками, считаем отсутствующими —
        их скачаем заново (изменённый сначала уйдёт в Версии)."""
        have = self._scan_archive()
        out, gone = {}, []
        for p, v in local.items():
            if have.get(p) != v[0]:
                gone.append(p)
            else:
                out[p] = v
        for p in gone:
            self.db.drop(p)
        if gone:
            self._note(f"в папке бэкапа пропали или изменились {len(gone)} файлов — скопирую заново", "warn",
                       gone[0] if len(gone) == 1 else "")
        return out

    # ------------------------------------------------------------ проверка копий

    def _verify_since(self) -> float | None:
        """Начало текущей проверки: продолжаем начатую, начинаем новую раз в 30 дней или по кнопке."""
        db, now = self.db, time.time()
        since, last = db.kv_get("verify_since"), db.kv_get("verify_last")
        if self._want_verify and not since:
            since = str(now)
            db.kv_set("verify_since", since)
        self._want_verify = False
        if last is None and not since:
            db.kv_set("verify_last", now)           # всё только что скачано и сверено — следующая через месяц
            last = str(now)
        if not since and now - float(last) >= VERIFY_EVERY:
            since = str(now)
            db.kv_set("verify_since", since)
        lastf = float(db.kv_get("verify_last") or now)
        self._set(verify_last=lastf, verify_next=lastf + VERIFY_EVERY)
        return float(since) if since else None

    def _verify_slice(self) -> bool:
        """Пересчитать хеши части копий (до 20 с). True — есть ещё что проверять."""
        if not self.db or self.cfg.paused:
            return False
        since = self._verify_since()
        if since is None:
            self._set(verifying=False)
            return False
        if not self.st["verifying"]:
            left = self.db.count_unverified(since)
            self._set(verifying=True, verify_total=left + self.st["verify_done"])
            self._note(f"проверяю скопированное: {left} файлов")
        t0 = time.monotonic()
        while time.monotonic() - t0 < VERIFY_SLICE:
            rows = self.db.unverified(since, 50)
            if not rows:
                n, bad = self.st["verify_done"], self.st["verify_bad"]
                now = time.time()
                self.db.kv_set("verify_last", now)
                self.db.kv_set("verify_since", None)
                self.db.event("verify", "", f"проверено {n}, повреждено {bad}")
                self._note(f"проверка копий завершена: {n} файлов, повреждено {bad}", "error" if bad else "info")
                self._set(verifying=False, verify_done=0, verify_total=0, verify_last=now,
                          verify_next=now + VERIFY_EVERY)
                self._report(self.st["state"], f"повреждённых копий: {bad}" if bad else "")
                return False
            for rel, size, sha in rows:
                if self._reload or self.quit or self.cfg.paused or self._want_sync:
                    return False
                try:
                    a = self._arch(rel)
                    got = self._sha(a) if os.path.exists(lp(a)) else None
                except (OSError, ValueError) as e:
                    got = None
                    log.warning("проверка %s: %s", rel, e)
                if got == sha:
                    self.db.set_verified(rel, time.time())
                else:
                    self._set(verify_bad=self.st["verify_bad"] + 1)
                    if got is not None:
                        dst = self._aside(a, VERSIONS, rel, tag="повреждён")
                        self.db.event("corrupt", rel, str(dst))
                        self._note(f"копия повреждена — отложена в «{VERSIONS}», скачаю заново", "error", rel)
                    else:
                        self._note("копии нет в папке — скачаю заново", "warn", rel)
                    self.db.drop(rel)                    # следующий проход скачает файл снова
                    self._idle = False                   # и не через минуту, а сразу
                self._set(verify_done=self.st["verify_done"] + 1)
        return True

    # ------------------------------------------------------------ операции с файлами

    def _arch(self, rel: str) -> Path:
        return self.root.joinpath(ARCHIVE, *safe_rel(rel))

    def _aside(self, src: Path, folder: str, rel: str, tag: str = "") -> Path:
        """Убрать файл в Версии/Удалённые, не затирая то, что там уже лежит."""
        dst = self.root.joinpath(folder, *safe_rel(rel))
        if folder == VERSIONS or tag or os.path.exists(lp(dst)):
            dst = dst.with_name(f"{dst.stem} ({(tag + ' ') if tag else ''}{stamp()}){dst.suffix}")
        n = 1
        while os.path.exists(lp(dst)):
            dst = dst.with_name(f"{dst.stem}-{n}{dst.suffix}")
            n += 1
        os.makedirs(lp(dst.parent), exist_ok=True)
        os.replace(lp(src), lp(dst))
        return dst

    def _set_mtime(self, p: Path, mtime: int) -> None:
        try:
            os.utime(lp(p), (time.time(), mtime))
        except OSError:
            pass

    def _touch(self, rel: str, f) -> None:
        self._set_mtime(self._arch(rel), f[2])
        self.db.put(rel, f[1], f[2], f[4])

    def _move(self, src: str, f) -> None:
        rel = f[0]
        a, b = self._arch(src), self._arch(rel)
        os.makedirs(lp(b.parent), exist_ok=True)
        if os.path.exists(lp(b)) and os.path.normcase(str(a)) != os.path.normcase(str(b)):
            self._aside(b, VERSIONS, rel)
        os.replace(lp(a), lp(b))
        self._set_mtime(b, f[2])
        self.db.drop(src)
        self.db.put(rel, f[1], f[2], f[4])
        self.db.event("move", rel, src)
        self._note("перенесён", "move", f"{src} → {rel}")
        self._prune_dirs(a.parent)

    def _space(self, need: int) -> None:
        """Перед записью нового файла: после него на диске должно остаться не меньше порога."""
        keep = int(max(0.0, float(self.cfg.min_free_gb or 0)) * 2**30)
        free = shutil.disk_usage(str(self.root)).free
        if free - need < keep:
            raise DiskFull(free, keep, need)

    def _copy_local(self, src: str, f) -> None:
        rel = f[0]
        self._space(f[1])
        b = self._arch(rel)
        os.makedirs(lp(b.parent), exist_ok=True)
        if os.path.exists(lp(b)):
            self._aside(b, VERSIONS, rel)
        shutil.copyfile(lp(self._arch(src)), lp(b))
        self._set_mtime(b, f[2])
        self.db.put(rel, f[1], f[2], f[4])
        self.db.event("copy", rel, src)
        self._note("скопирован с соседнего", "copy", rel)

    def _deletes(self, deletes: list[str], local: dict, complete: bool) -> None:
        self._set(pending_delete=0)
        if not deletes:
            return
        if not complete:
            self._note(f"сервер прочитал не все папки — {len(deletes)} файлов пока не убираю в «{DELETED}»", "warn")
            return
        lim_n, lim_share = DELETE_SUSPICIOUS
        if len(deletes) > lim_n and len(deletes) > lim_share * max(1, len(local)) and not self._confirm:
            self._set(state="confirm", pending_delete=len(deletes),
                      text=f"С компьютера пропало {len(deletes)} файлов",
                      detail=f"Нажмите «Подтвердить», чтобы убрать их в «{DELETED}»")
            self._note(f"пропало сразу {len(deletes)} файлов — жду подтверждения", "warn")
            return
        self._confirm = False
        for p in deletes:
            a = self._arch(p)
            try:
                dst = self._aside(a, DELETED, p) if os.path.exists(lp(a)) else None
            except OSError as e:
                self._error(p, f"не перенести в «{DELETED}»: {e}")
                continue
            self.db.drop(p)
            self.db.event("delete", p, str(dst or ""))
            self._note(f"удалён на компьютере → «{DELETED}»", "delete", p)
            self._prune_dirs(a.parent)

    def _prune_dirs(self, d: Path) -> None:
        """Пустые папки в Архиве после переноса/удаления убираем."""
        top = self.root / ARCHIVE
        while d != top and top in d.parents:
            try:
                os.rmdir(lp(d))
            except OSError:
                return
            d = d.parent

    def _error(self, rel: str, msg: str) -> None:
        self._set(errors=self.st["errors"] + 1)
        self.db.event("error", rel, msg)
        self._note(f"ошибка: {msg}", "error", rel)

    # ------------------------------------------------------------ загрузка

    def _download(self, f) -> None:
        rel, size, mtime, _date, sha = f
        b = self._arch(rel)                         # проверка пути — до любых обращений к диску
        tmp = self.root / META / "tmp" / f"{sha}.part"
        have = os.path.getsize(lp(tmp)) if os.path.exists(lp(tmp)) else 0
        if have > size:
            os.remove(lp(tmp))
            have = 0
        self._space(size - have)
        self._set(current=rel, cur_done=have, cur_size=size)
        if have < size:
            self._fetch(rel, tmp, have, size)
        got = self._sha(tmp)
        if got != sha:
            os.remove(lp(tmp))
            raise ValueError("контрольная сумма не совпала (файл менялся во время копирования?) — повторю позже")
        os.makedirs(lp(b.parent), exist_ok=True)
        replaced = False
        if os.path.exists(lp(b)):
            self._aside(b, VERSIONS, rel)
            replaced = True
        os.replace(lp(tmp), lp(b))
        self._set_mtime(b, mtime)
        self.db.put(rel, size, mtime, sha)
        self.db.event("update" if replaced else "copy", rel, str(size))
        self._set(copied=self.st["copied"] + 1, copied_bytes=self.st["copied_bytes"] + size)
        if replaced:
            self._note(f"изменился — старый вариант в «{VERSIONS}»", "update", rel)

    def _fetch(self, rel: str, tmp: Path, have: int, size: int) -> None:
        thr = Throttle(lambda: int(max(0.0, float(self.cfg.limit_mbps or 0)) * 125_000))
        with self.api.stream(rel, have) as r:
            if r.status_code == 503:
                raise PcOff()
            if r.status_code == 404:
                raise Gone()
            if r.status_code == 416:
                os.remove(lp(tmp))
                raise ValueError("размер файла изменился — повторю позже")
            if r.status_code in (401, 429):
                self.api._check(r)
            r.raise_for_status()
            if r.headers.get("x-pc-frames") == "1":
                if int(r.headers.get("x-start", "-1")) != have:
                    raise ValueError("сервер начал не с того места")
                done = self._frames(r, tmp, have, thr)
            else:
                done = self._plain(r, tmp, have, thr)
        if done < size:
            raise PcOff()

    def _halted(self) -> bool:
        return self.halt.is_set() or self.cfg.paused or self.quit

    def _plain(self, r, tmp: Path, have: int, thr) -> int:
        if r.status_code == 200:
            have = 0                              # сервер отдал целиком — пишем с начала
        done = have
        with open(lp(tmp), "ab" if have else "wb") as out:
            try:
                for chunk in r.iter_bytes(CHUNK if not self.cfg.limit_mbps else 64 * 1024):
                    if self._halted():
                        raise Stop()
                    out.write(chunk)
                    done += len(chunk)
                    self._wire(len(chunk), len(chunk))
                    self._progress(len(chunk), done)
                    thr.wait(len(chunk), self.halt)
            except (httpx.RemoteProtocolError, httpx.ReadError):
                raise PcOff() from None             # ПК пропал посреди файла
        return done

    def _frames(self, r, tmp: Path, have: int, thr) -> int:
        """Кадры [тип][длина][данные]: тип 0 — как есть, 1 — zlib. В файл пишутся только целые
        кадры, поэтому после обрыва файл ровно на границе блока и докачка идёт с этого места."""
        done, buf = have, bytearray()
        with open(lp(tmp), "ab" if have else "wb") as out:
            try:
                for chunk in r.iter_raw(64 * 1024):
                    if self._halted():
                        raise Stop()
                    buf += chunk
                    thr.wait(len(chunk), self.halt)
                    while len(buf) >= 5:
                        kind, n = buf[0], int.from_bytes(buf[1:5], "big")
                        if kind not in (0, 1) or n > 4 * 1024 * 1024:
                            raise ValueError("повреждённый ответ сервера")
                        if len(buf) < 5 + n:
                            break
                        payload = bytes(buf[5:5 + n])
                        del buf[:5 + n]
                        data = zlib.decompress(payload) if kind == 1 else payload
                        out.write(data)
                        done += len(data)
                        self._wire(5 + n, len(data))
                        self._progress(len(data), done)
            except (httpx.RemoteProtocolError, httpx.ReadError):
                raise PcOff() from None
        return done

    def _wire(self, wire: int, raw: int) -> None:
        with self.mu:
            self.st["wire_bytes"] += wire
            self.st["raw_bytes"] += raw

    def _progress(self, n: int, done: int) -> None:
        now = time.monotonic()
        self._speed_b += n
        dt = now - self._speed_t
        if dt >= 1:
            sp = self.st["speed"]
            cur = self._speed_b / dt
            self._set(speed=cur if not sp else sp * 0.6 + cur * 0.4)
            self._speed_t, self._speed_b = now, 0
        with self.mu:
            self.st["cur_done"] = done
        if time.monotonic() - self._last_report > REPORT_COPYING:
            self._report("copying")              # большой файл — ход виден в админке и посреди него

    @staticmethod
    def _sha(p: Path) -> str:
        h = hashlib.sha256()
        with open(lp(p), "rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""):
                h.update(b)
        return h.hexdigest()

    def _rebuild_db(self) -> None:
        """Базы нет, а файлы в Архиве есть (перенесли диск, удалили базу) — пересчитываем хеши."""
        top = self.root / ARCHIVE
        self._set(state="scan", text="Проверяю уже скопированное", detail="Считаю контрольные суммы файлов в Архиве")
        self._note("база бэкапа пуста — пересчитываю хеши уже скопированных файлов")
        rows, n = [], 0
        for dirpath, _dirs, names in os.walk(lp(top)):
            for name in names:
                if self._reload or self.quit:
                    raise Stop()
                full = Path(dirpath) / name
                rel = os.path.relpath(full, lp(top)).replace(os.sep, "/")
                try:
                    st = os.stat(full)
                    rows.append((rel, st.st_size, int(st.st_mtime), self._sha(full), time.time()))
                except OSError:
                    continue
                n += 1
                self._set(detail=f"Проверено файлов: {n}")
                if len(rows) >= 200:
                    self.db.put_many(rows)
                    rows = []
        self.db.put_many(rows)
        self._note(f"в Архиве найдено {n} файлов")

    # ------------------------------------------------------------ отчёт серверу

    def _report(self, state: str, error: str = "") -> None:
        """Отчёт серверу — при смене состояния или раз в 5 минут, а не на каждый опрос."""
        if not self.api:
            return
        every = REPORT_COPYING if state == "copying" or self.st["verifying"] else REPORT_EVERY
        if state == self._reported and not error and time.monotonic() - self._last_report < every:
            return
        self._reported = state
        self._last_report = time.monotonic()
        s = self.snapshot()
        self.api.report({"state": state, "client": f"photocloud-backup {VERSION}", "files": s["files"],
                         "bytes": s["bytes"], "left_files": s["left_files"], "left_bytes": s["left_bytes"],
                         "copied": s["copied"], "copied_bytes": s["copied_bytes"], "errors": s["errors"],
                         "pending_delete": s["pending_delete"], "speed": int(s["speed"]),
                         "current": s["current"] if state == "copying" else "",
                         "cur_done": s["cur_done"], "cur_size": s["cur_size"],
                         "wire_bytes": s["wire_bytes"], "raw_bytes": s["raw_bytes"],
                         "limit_mbps": int(float(self.cfg.limit_mbps or 0)),
                         "verify_last": int(s["verify_last"]), "verify_done": s["verify_done"],
                         "verify_total": s["verify_total"] if s["verifying"] else 0, "verify_bad": s["verify_bad"],
                         **({"error": error} if error else {})})


# ======================================================================== обновление
# Обновление с GitHub (репозиторий публичный). Клиент — один файл, обновляется он сам:
# берётся последний коммит ветки (API GitHub, без пятиминутного кэша raw-ссылок), из этого
# коммита — backup/photocloud_backup.pyw, версия читается из строки VERSION = "…".
# Новый файл проверяется (компилируется) и подменяет этот; затем программа перезапускается.

REPO = "ilya12077/photocloud"
REMOTE_PATH = "backup/photocloud_backup.pyw"
SCRIPT = Path(__file__).resolve()
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_VERSION_RE = re.compile(r'^VERSION = "([0-9][0-9A-Za-z.\-+]{0,30})"', re.M)
_fetched: dict[str, str] = {}             # коммит -> текст файла (чтобы не качать дважды)


def local_version() -> str:
    return VERSION


def parse(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def default_branch() -> str:
    """Обновления — из основной ветки репозитория (в настройках можно указать другую)."""
    return "master"


def _gh() -> "httpx.Client":
    return httpx.Client(timeout=httpx.Timeout(60, connect=15), follow_redirects=True,
                        headers={"user-agent": f"photocloud-backup/{VERSION}"})


def head_sha(branch: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch):
        return None
    try:
        with _gh() as c:
            r = c.get(f"https://api.github.com/repos/{REPO}/commits/{branch}",
                      headers={"accept": "application/vnd.github.sha"})
    except httpx.HTTPError:
        return None
    sha = r.text.strip() if r.status_code == 200 else ""
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def _fetch(branch: str, ref: str) -> str | None:
    if ref in _fetched:
        return _fetched[ref]
    url = f"https://raw.githubusercontent.com/{REPO}/{ref}/{REMOTE_PATH}"
    if ref == branch:
        url += f"?t={int(time.time())}"          # API не ответил: хотя бы мимо кэша
    with _gh() as c:
        r = c.get(url, headers={"cache-control": "no-cache"})
    if r.status_code != 200:
        return None
    _fetched.clear()
    _fetched[ref] = r.text
    return r.text


def remote_version(branch: str) -> str | None:
    """Версия клиента в ветке на GitHub; None — в ветке нет клиента (или GitHub недоступен)."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch):
        return None
    ref = head_sha(branch) or branch
    text = _fetch(branch, ref)
    m = _VERSION_RE.search(text or "")
    return m.group(1) if m else None


def newer(remote: str | None) -> bool:
    return bool(remote) and parse(remote) > parse(VERSION)


def apply(branch: str) -> str:
    """Скачать новую версию этого файла и подменить им себя. Возвращает новую версию."""
    ref = head_sha(branch) or branch
    text = _fetch(branch, ref)
    m = _VERSION_RE.search(text or "")
    if not text or not m:
        raise ValueError("в ветке нет клиента бэкапа")
    compile(text, str(SCRIPT), "exec")                    # битый файл не ставим
    tmp = SCRIPT.with_name(SCRIPT.name + ".new")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, SCRIPT)
    log.info("обновлено до %s (ветка %s, коммит %s)", m.group(1), branch, ref[:10])
    return m.group(1)


def restart(hidden: bool) -> None:
    """Запустить новую копию программы; она дождётся, пока эта завершится."""
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    if sys.platform == "win32" and w.exists():
        exe = w
    args = [str(exe), str(SCRIPT), "--wait-pid", str(os.getpid())]
    if hidden:
        args.append("--tray")
    flags = (0x00000008 | 0x00000200) if sys.platform == "win32" else 0   # DETACHED_PROCESS | NEW_PROCESS_GROUP
    subprocess.Popen(args, close_fds=True, creationflags=flags)


updater = SimpleNamespace(local_version=local_version, default_branch=default_branch, remote_version=remote_version,
                          newer=newer, apply=apply, restart=restart)


# ======================================================================== окно и трей
# Окно (tkinter) и значок в трее (pystray). Движок работает в своём потоке;
# сюда — только чтение его состояния раз в 0,7 с и кнопки.
COLORS = {"copying": "#2f80ed", "done": "#27ae60", "paused": "#9aa0a6", "pc_off": "#f2994a", "waiting": "#2f80ed",
          "error": "#eb5757", "confirm": "#eb5757", "disk_full": "#eb5757", "setup": "#9aa0a6", "scan": "#2f80ed"}
TITLES = {"copying": "копирует", "done": "всё скопировано", "paused": "пауза", "pc_off": "компьютер выключен",
          "waiting": "ждёт хеши с сервера", "error": "ошибка", "disk_full": "мало места на диске", "confirm": "ждёт подтверждения", "setup": "не настроен",
          "scan": "проверяет папку бэкапа"}
KIND = {"info": "", "warn": "⚠ ", "error": "✖ ", "move": "↪ ", "copy": "", "update": "✎ ", "delete": "🗑 "}


def num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def eta(sec: float) -> str:
    sec = int(sec)
    if sec < 90:
        return "меньше 2 мин"
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return " ".join(x for x in (f"{d} д" if d else "", f"{h} ч" if h else "", f"{m} мин" if not d else "") if x)


def tray_image(color: str) -> Image.Image:
    im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((2, 2, 62, 62), 14, fill=color)
    d.ellipse((17, 19, 47, 49), outline="white", width=6)        # объектив, как у значка сайта
    d.rectangle((40, 10, 52, 18), fill="white")
    return im


class App:
    def __init__(self, cfg, engine, script: Path, start_hidden: bool, log_path: Path | None = None):
        self.cfg, self.engine, self.script = cfg, engine, script
        self._closing = False
        self.log_path = log_path
        self.q: queue.Queue = queue.Queue()
        self._last_state, self._last_paused, self._log_top = None, None, None
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:  # noqa: BLE001
                pass
        self.root = tk.Tk()
        self.root.report_callback_exception = self._tk_error     # под pythonw консоли нет — пишем в журнал
        self.root.title("Photocloud — бэкап")
        if sys.platform == "win32":
            try:                                   # своя группа на панели задач и свой значок, а не python.exe
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("photocloud.backup")
            except Exception:  # noqa: BLE001
                pass
        self.root.geometry("700x620")
        self.root.minsize(600, 540)
        self.root.protocol("WM_DELETE_WINDOW", self.hide)
        try:
            self._icon_img = tk.PhotoImage(data=self._png(tray_image(COLORS["done"])))
            self.root.iconphoto(True, self._icon_img)
        except tk.TclError:
            pass
        self._build()
        self.tray = None
        self._tray_thread = None
        self._tray_status = "Photocloud — бэкап"
        self._start_tray()
        configured = bool(cfg.server and cfg.token and cfg.root)
        if not configured:
            self.nb.select(self.tab_set)
        if getattr(cfg, "load_error", ""):
            self.root.after(500, lambda: messagebox.showwarning(
                "Бэкап", f"Настройки не прочитались: {cfg.load_error}\nФайл: {cfg.path}", parent=self.root))
        if start_hidden and configured and cfg.hide_on_autostart and not getattr(self, "_no_pystray", False):
            self.root.withdraw()
        self.root.after(300, self.tick)
        self._offered: set[str] = set()
        self.root.after(30_000, self._auto_update)          # через полминуты после запуска, потом раз в 6 ч

    def _tk_error(self, exc, val, tb) -> None:
        log.error("ошибка в окне", exc_info=(exc, val, tb))
        if self._closing:
            return                               # окно уже закрывается — показывать некуда
        try:
            messagebox.showerror("Бэкап", f"Ошибка: {exc.__name__}: {val}", parent=self.root)
        except tk.TclError:
            pass

    @staticmethod
    def _png(im: Image.Image) -> bytes:
        import base64
        import io
        b = io.BytesIO()
        im.resize((32, 32)).save(b, "PNG")
        return base64.b64encode(b.getvalue())

    # ------------------------------------------------------------ окно

    def _build(self) -> None:
        pad = {"padx": 12, "pady": 4}
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        # --- состояние
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="Состояние")
        self.v_state = tk.StringVar()
        self.v_detail = tk.StringVar()
        self.v_counts = tk.StringVar()
        self.v_current = tk.StringVar()
        self.v_speed = tk.StringVar()
        self.v_verify = tk.StringVar()
        ttk.Label(t, textvariable=self.v_state, font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=12, pady=(12, 0))
        ttk.Label(t, textvariable=self.v_detail, foreground="#666", wraplength=640).pack(anchor="w", **pad)
        self.bar = ttk.Progressbar(t, maximum=1000)
        self.bar.pack(fill="x", padx=12, pady=(8, 4))
        ttk.Label(t, textvariable=self.v_counts).pack(anchor="w", **pad)
        ttk.Label(t, textvariable=self.v_current, foreground="#666", wraplength=640).pack(anchor="w", **pad)
        ttk.Label(t, textvariable=self.v_speed).pack(anchor="w", **pad)
        ttk.Label(t, textvariable=self.v_verify, foreground="#666", wraplength=600).pack(anchor="w", **pad)

        self.confirm = ttk.Frame(t)
        ttk.Label(self.confirm, text="Файлы уберутся в папку «Удалённые» внутри бэкапа — ничего не стирается.",
                  wraplength=420).pack(side="left", padx=(0, 8))
        ttk.Button(self.confirm, text="Подтвердить", command=self.engine.confirm_delete).pack(side="left")

        row = ttk.Frame(t)
        row.pack(fill="x", padx=12, pady=(12, 4), side="bottom")
        self.b_pause = ttk.Button(row, text="Пауза", command=self.toggle_pause, width=14)
        self.b_pause.pack(side="left")
        ttk.Button(row, text="Проверить сейчас", command=self.engine.sync_now).pack(side="left", padx=6)
        ttk.Button(row, text="Разбудить ПК", command=self.engine.wake_now).pack(side="left")
        ttk.Button(row, text="Открыть папку", command=self.open_root).pack(side="right")
        ttk.Button(row, text="Проверить копии", command=self.engine.verify_now).pack(side="right", padx=6)

        lim = ttk.Frame(t)
        lim.pack(fill="x", padx=12, pady=4, side="bottom")
        ttk.Label(lim, text="Лимит скорости, Мбит/с (0 — без ограничения):").pack(side="left")
        self.v_limit = tk.StringVar(value=self._fmt_limit(self.cfg.limit_mbps))
        sp = ttk.Spinbox(lim, from_=0, to=1000, increment=1, width=7, textvariable=self.v_limit,
                         command=self.apply_limit)
        sp.pack(side="left", padx=6)
        sp.bind("<Return>", lambda _e: self.apply_limit())
        sp.bind("<FocusOut>", lambda _e: self.apply_limit())

        # --- журнал
        lg = ttk.Frame(self.nb)
        self.nb.add(lg, text="Журнал")
        lb = ttk.Frame(lg)
        lb.pack(fill="x", side="bottom", pady=(6, 0))
        if self.log_path:
            ttk.Label(lb, text=f"Подробный журнал: {self.log_path}", foreground="#999", wraplength=480).pack(
                side="left", padx=4)
            ttk.Button(lb, text="Открыть", command=lambda: winutil.open_folder(str(self.log_path))).pack(side="right")
        self.logbox = tk.Text(lg, wrap="none", height=10, state="disabled", font=("Consolas", 9))
        ys = ttk.Scrollbar(lg, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=ys.set)
        ys.pack(side="right", fill="y")
        self.logbox.pack(fill="both", expand=True)

        # --- настройки
        s = ttk.Frame(self.nb)
        self.tab_set = s
        self.nb.add(s, text="Настройки")
        s.columnconfigure(1, weight=1)
        self.v_server = tk.StringVar(value=self.cfg.server)
        self.v_token = tk.StringVar()
        self.v_root = tk.StringVar(value=self.cfg.root)
        self.v_auto = tk.BooleanVar(value=self.cfg.autostart)
        self.v_hide = tk.BooleanVar(value=self.cfg.hide_on_autostart)
        self.v_wake = tk.BooleanVar(value=self.cfg.wake_on_start)
        self.v_upd = tk.BooleanVar(value=self.cfg.check_updates)
        self.v_branch = tk.StringVar(value=self.cfg.update_branch)
        self.v_updmsg = tk.StringVar()
        self.v_free = tk.StringVar(value=self._fmt_limit(self.cfg.min_free_gb))
        self.v_test = tk.StringVar()
        r = 0
        ttk.Label(s, text="Адрес сайта:").grid(row=r, column=0, sticky="w", padx=12, pady=(14, 4))
        ttk.Entry(s, textvariable=self.v_server).grid(row=r, column=1, columnspan=2, sticky="ew", padx=12, pady=(14, 4))
        r += 1
        ttk.Label(s, text="Токен:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        ttk.Entry(s, textvariable=self.v_token, show="•").grid(row=r, column=1, columnspan=2, sticky="ew", padx=12, pady=4)
        r += 1
        self.l_token = ttk.Label(s, foreground="#666", wraplength=420)
        self.l_token.grid(row=r, column=1, columnspan=2, sticky="w", padx=12)
        r += 1
        ttk.Label(s, text="Папка бэкапа:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        ttk.Entry(s, textvariable=self.v_root).grid(row=r, column=1, sticky="ew", padx=(12, 4), pady=4)
        ttk.Button(s, text="Выбрать…", command=self.pick_root).grid(row=r, column=2, padx=(0, 12), pady=4)
        r += 1
        ttk.Label(s, text="Оставлять свободным:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        fr = ttk.Frame(s)
        fr.grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=4)
        ttk.Spinbox(fr, from_=0, to=10000, increment=1, width=7, textvariable=self.v_free).pack(side="left")
        ttk.Label(fr, text="ГБ на диске (иначе новые файлы не качаются)", foreground="#666").pack(
            side="left", padx=6)
        r += 1
        ttk.Checkbutton(s, text="Запускать при входе в Windows", variable=self.v_auto,
                        command=self._sync_hide).grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=(10, 2))
        r += 1
        self.c_hide = ttk.Checkbutton(s, text="Не показывать окно при автозапуске (только значок в трее)",
                                      variable=self.v_hide)
        self.c_hide.grid(row=r, column=1, columnspan=2, sticky="w", padx=(32, 12), pady=2)
        self._sync_hide()
        r += 1
        ttk.Checkbutton(s, text="Будить домашний компьютер при запуске", variable=self.v_wake).grid(
            row=r, column=1, columnspan=2, sticky="w", padx=12, pady=2)
        r += 1
        ttk.Checkbutton(s, text="Проверять обновления на GitHub и предлагать обновиться", variable=self.v_upd).grid(
            row=r, column=1, columnspan=2, sticky="w", padx=12, pady=2)
        r += 1
        ttk.Label(s, text="Ветка обновлений:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        ub = ttk.Frame(s)
        ub.grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=4)
        ttk.Entry(ub, textvariable=self.v_branch, width=18).pack(side="left")
        ttk.Label(ub, text=f"пусто — {updater.default_branch()}", foreground="#666").pack(side="left", padx=6)
        ttk.Button(ub, text="Проверить обновления", command=lambda: self.check_update(manual=True)).pack(side="left")
        r += 1
        ttk.Label(s, textvariable=self.v_updmsg, foreground="#666", wraplength=560).grid(
            row=r, column=1, columnspan=2, sticky="w", padx=12)
        r += 1
        b = ttk.Frame(s)
        b.grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=12)
        ttk.Button(b, text="Сохранить", command=self.save_settings).pack(side="left")
        ttk.Button(b, text="Проверить связь", command=self.test_conn).pack(side="left", padx=6)
        r += 1
        ttk.Label(s, textvariable=self.v_test, wraplength=440).grid(row=r, column=1, columnspan=2, sticky="w", padx=12)
        r += 1
        ttk.Label(s, text="Закрытие окна оставляет программу в трее (значок у часов; в Windows 11 он может "
                          "быть спрятан под стрелкой ^ — его можно перетащить на панель). Выход — правой кнопкой "
                          "по значку → «Выход».", foreground="#666", wraplength=640).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 0))
        r += 1
        ttk.Label(s, text=f"Настройки: {self.cfg.path}", foreground="#999", wraplength=640).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 0))
        r += 1
        ttk.Label(s, text=f"photocloud-backup {VERSION}", foreground="#999").grid(
            row=r, column=0, columnspan=3, sticky="sw", padx=12, pady=12)
        s.rowconfigure(r, weight=1)
        self._token_hint()

    def _sync_hide(self) -> None:
        self.c_hide.state(["!disabled"] if self.v_auto.get() else ["disabled"])

    def _token_hint(self) -> None:
        self.l_token.configure(text="Токен сохранён (зашифрован). Оставьте поле пустым, чтобы не менять."
                               if self.cfg.token else "Токен выдаёт администратор: Админка → Бэкап → Новый клиент.")

    @staticmethod
    def _fmt_limit(v) -> str:
        v = float(v or 0)
        return str(int(v)) if v == int(v) else str(v)

    def apply_limit(self) -> None:
        try:
            v = float(self.v_limit.get().replace(",", "."))
        except ValueError:
            v = -1
        if not 0 <= v <= 10000:
            self.v_limit.set(self._fmt_limit(self.cfg.limit_mbps))
            return
        if v != self.cfg.limit_mbps:
            self.cfg.limit_mbps = v
            self.cfg.save()

    def pick_root(self) -> None:
        d = filedialog.askdirectory(title="Папка для бэкапа", initialdir=self.v_root.get() or str(Path.home()))
        if d:
            self.v_root.set(str(Path(d)))

    def _server(self) -> str | None:
        srv = self.v_server.get().strip().rstrip("/")
        if srv and "://" not in srv:
            srv = "https://" + srv
        local = srv.startswith(("http://localhost", "http://127.0.0.1"))
        if not (srv.startswith("https://") or local):
            messagebox.showerror("Бэкап", "Адрес сайта должен начинаться с https://", parent=self.root)
            return None
        return srv

    def save_settings(self) -> None:
        srv = self._server()
        if srv is None:
            return
        root = self.v_root.get().strip()
        if not root:
            messagebox.showerror("Бэкап", "Выберите папку для бэкапа", parent=self.root)
            return
        try:
            Path(root).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Бэкап", f"Не создать папку: {e}", parent=self.root)
            return
        try:
            free_gb = float(self.v_free.get().replace(",", "."))
            if not 0 <= free_gb <= 100000:
                raise ValueError
        except ValueError:
            messagebox.showerror("Бэкап", "Свободное место: число ГБ, 0 — без ограничения", parent=self.root)
            return
        tok = self.v_token.get().strip()
        if not tok and not self.cfg.token:
            messagebox.showerror("Бэкап", "Вставьте токен", parent=self.root)
            return
        moved = self.cfg.root and Path(root) != Path(self.cfg.root)
        if moved and not messagebox.askyesno(
                "Бэкап", "Сменить папку бэкапа? Старая папка останется как есть; "
                         "в новую файлы будут скопированы заново (если там уже лежит бэкап — он будет проверен).",
                parent=self.root):
            return
        self.cfg.server, self.cfg.root = srv, root
        if tok:
            self.cfg.token = tok
        self.cfg.autostart, self.cfg.wake_on_start = self.v_auto.get(), self.v_wake.get()
        self.cfg.hide_on_autostart = self.v_hide.get()
        self.cfg.check_updates = self.v_upd.get()
        self.cfg.update_branch = self.v_branch.get().strip()
        self.cfg.min_free_gb = free_gb
        try:
            self.cfg.save()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Бэкап", f"Не удалось сохранить настройки в {self.cfg.path}:\n{type(e).__name__}: {e}",
                                 parent=self.root)
            return
        try:
            winutil.set_autostart(self.cfg.autostart, self.script)
        except OSError as e:
            messagebox.showwarning("Бэкап", f"Автозапуск не настроен: {e}", parent=self.root)
        self.v_token.set("")
        self._token_hint()
        self.v_server.set(srv)
        self.engine.reconfigure()
        self.v_test.set("Сохранено.")
        self.test_conn()

    # ------------------------------------------------------------ обновления

    def _branch(self) -> str:
        return (self.cfg.update_branch or "").strip() or updater.default_branch()

    def _auto_update(self) -> None:
        if self.cfg.check_updates:
            self.check_update(manual=False)
        self.root.after(6 * 3600 * 1000, self._auto_update)

    def check_update(self, manual: bool) -> None:
        branch = self._branch()
        if manual:
            self.v_updmsg.set(f"Проверяю ветку {branch}…")

        def run():
            try:
                remote = updater.remote_version(branch)
                err = ""
            except httpx.HTTPError as e:
                remote, err = None, type(e).__name__
            self.q.put(lambda: self._update_found(branch, remote, err, manual))

        threading.Thread(target=run, daemon=True).start()

    def _update_found(self, branch: str, remote: str | None, err: str, manual: bool) -> None:
        cur = updater.local_version()
        if err:
            self.v_updmsg.set(f"Не удалось проверить обновления: {err}")
            return
        if remote is None:
            self.v_updmsg.set(f"В ветке {branch} нет клиента бэкапа (или GitHub недоступен).")
            return
        if not updater.newer(remote):
            self.v_updmsg.set(f"Установлена последняя версия {cur} (ветка {branch}).")
            return
        self.v_updmsg.set(f"Доступна версия {remote} (сейчас {cur}).")
        if remote in self._offered and not manual:
            return                                       # уже предлагали — не надоедаем до следующего запуска
        self._offered.add(remote)
        self.show()
        if messagebox.askyesno("Photocloud — бэкап", f"Доступно обновление клиента: {remote} (сейчас {cur}).\n\n"
                               "Обновить сейчас? Программа перезапустится, копирование продолжится с того же места.",
                               parent=self.root):
            self.update_now(branch)

    def update_now(self, branch: str) -> None:
        self.v_updmsg.set("Скачиваю обновление…")
        hidden = self.root.state() == "withdrawn"

        def run():
            try:
                new = updater.apply(branch)
                self.q.put(lambda: self._restart(new, hidden))
            except Exception as e:  # noqa: BLE001
                import logging
                logging.getLogger("pcbackup").exception("обновление не удалось")
                msg = f"{type(e).__name__}: {e}"
                self.q.put(lambda: (self.v_updmsg.set(f"Обновление не удалось: {msg}"),
                                    messagebox.showerror("Бэкап", f"Обновление не удалось:\n{msg}", parent=self.root)))

        threading.Thread(target=run, daemon=True).start()

    def _restart(self, new: str, hidden: bool) -> None:
        import logging
        logging.getLogger("pcbackup").info("перезапуск после обновления до %s", new)
        self._closing = True
        self.engine.shutdown()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:  # noqa: BLE001
                pass
        self.engine.join(10)
        updater.restart(hidden)
        self.root.destroy()

    def test_conn(self) -> None:
        srv = self._server()
        if srv is None:
            return
        tok = self.v_token.get().strip() or self.cfg.token
        self.v_test.set("Проверяю…")

        def run():
            api = Api(srv, tok)
            try:
                st = api.status()
                pc = {"up": "включён", "down": "выключен", "waking": "просыпается"}.get(st.get("pc"), st.get("pc"))
                msg = f"✔ Связь есть: «{st.get('name')}», сервер {st.get('server')}, компьютер {pc}."
            except AuthError as e:
                msg = f"✖ {e}"
            except PcOff:
                msg = "✔ Сервер отвечает, компьютер выключен."
            except httpx.HTTPError as e:
                msg = f"✖ Нет связи с сервером: {type(e).__name__}"
            finally:
                api.close()
            self.q.put(lambda: self.v_test.set(msg))

        threading.Thread(target=run, daemon=True).start()

    def open_root(self) -> None:
        if self.cfg.root:
            winutil.open_folder(self.cfg.root)

    def toggle_pause(self) -> None:
        if self.cfg.paused:
            self.engine.resume()
        else:
            self.engine.pause()
        self.tick(once=True)

    def show(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide(self) -> None:
        """Крестик — окно прячется совсем (и из панели задач); программа остаётся значком в трее.
        Значка нет (pystray не установлен) — прятать некуда: спрашиваем и закрываем программу."""
        if getattr(self, "_no_pystray", False):
            if messagebox.askyesno("Бэкап", "Значка в трее нет (не установлена библиотека pystray), поэтому "
                                   "свернуть в трей нельзя. Закрыть программу? Копирование остановится.",
                                   parent=self.root):
                self.quit()
            return
        self.root.withdraw()

    def quit(self) -> None:
        self._closing = True
        self.engine.shutdown()
        if self.tray:
            try:
                self.tray.stop()
                self._tray_thread.join(3)
            except Exception:  # noqa: BLE001
                pass
        self.engine.join(5)
        self.root.destroy()

    # ------------------------------------------------------------ трей

    def _start_tray(self) -> None:
        """Значок в трее (pystray). Важно для Windows: значок создаётся и работает в ОДНОМ своём
        потоке — его цикл сообщений видит только окна своего потока; если создать Icon в потоке
        окна, а run() вызвать в другом, значок висит или не появляется (pystray #94).
        Окно tkinter — в главном потоке; из меню значка команды идут в окно через очередь."""
        try:
            import pystray
        except ImportError:
            import logging
            logging.getLogger("pcbackup").error("нет библиотеки pystray (python: %s) — значка в трее не будет",
                                                sys.executable)
            self._no_pystray = True
            self.root.after(800, self._offer_pystray)
            return
        self._no_pystray = False
        call = lambda fn: (lambda *_a: self.q.put(fn))        # noqa: E731 — из потока трея в поток окна
        self._tray_status = "Photocloud — бэкап"
        self._tray_menu = pystray.Menu(
            pystray.MenuItem(lambda _i: self._tray_status, None, enabled=False),      # состояние
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Открыть окно", call(self.show), default=True),        # и по щелчку по значку
            pystray.MenuItem(lambda _i: "Продолжить копирование" if self.cfg.paused else "Пауза",
                             call(self.toggle_pause)),
            pystray.MenuItem("Проверить сейчас", call(self.engine.sync_now)),
            pystray.MenuItem("Разбудить домашний ПК", call(self.engine.wake_now)),
            pystray.MenuItem("Проверить копии", call(self.engine.verify_now)),
            pystray.MenuItem("Открыть папку бэкапа", call(self.open_root)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", call(self.quit)),
        )
        self._tray_imgs = {c: tray_image(c) for c in set(COLORS.values())}
        base = pystray.Icon
        if sys.platform == "win32":
            from pystray._util import win32 as w32

            class TrayIcon(base):
                def _on_notify(self, wparam, lparam):
                    # меню собираем заново прямо перед показом, в потоке значка: всегда свежее состояние
                    if lparam == w32.WM_RBUTTONUP:
                        try:
                            self._update_menu()
                        except Exception:  # noqa: BLE001
                            pass
                    return super()._on_notify(wparam, lparam)
            self._tray_cls = TrayIcon
        else:
            self._tray_cls = base
        self._tray_attempt = 0
        self._launch_tray()

    def _offer_pystray(self) -> None:
        """pystray не установлен в тот Python, которым запущена программа (часто — другой venv):
        предлагаем поставить прямо отсюда, тем же интерпретатором."""
        import subprocess
        self.show()
        cmd = [sys.executable, "-m", "pip", "install", "pystray"]
        if not messagebox.askyesno(
                "Бэкап", "Для значка в трее нужна библиотека pystray, а в этом Python её нет:\n"
                         f"{sys.executable}\n\nУстановить сейчас?", parent=self.root):
            return

        def run():
            import logging
            lg = logging.getLogger("pcbackup")
            flags = 0x08000000 if sys.platform == "win32" else 0        # CREATE_NO_WINDOW
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, creationflags=flags)
                ok = r.returncode == 0
                lg.info("pip install pystray: %s\n%s", r.returncode, (r.stdout + r.stderr)[-2000:])
            except Exception as e:  # noqa: BLE001
                ok = False
                lg.error("pip install pystray: %s", e)

            def done():
                if ok:
                    import importlib
                    importlib.invalidate_caches()
                    self._start_tray()
                    if not self._no_pystray:
                        messagebox.showinfo("Бэкап", "Готово — значок появился в трее.", parent=self.root)
                        return
                messagebox.showerror("Бэкап", "Не получилось установить pystray. Выполните в командной строке:\n"
                                     + " ".join(f'"{c}"' if " " in c else c for c in cmd), parent=self.root)
            self.q.put(done)

        threading.Thread(target=run, daemon=True).start()

    def _launch_tray(self) -> None:
        """Не поднялся (бывает при автозапуске, пока панель задач ещё не готова) — снова через 15 с."""
        import logging
        lg = logging.getLogger("pcbackup")
        self._tray_attempt += 1
        img = self._tray_imgs[COLORS.get(self._last_state or "setup", COLORS["setup"])]

        def setup(ic):
            for i in range(120):                     # панель задач может появиться не сразу
                try:
                    ic.visible = True
                    lg.info("значок в трее показан (попытка %d)", self._tray_attempt)
                    return
                except Exception:  # noqa: BLE001
                    if i == 0:
                        lg.exception("значок в трее пока не показывается — повторяю")
                    time.sleep(5)

        def run():
            try:
                icon = self._tray_cls("photocloud-backup", img, self._tray_status[:120], self._tray_menu)
                self.tray = icon                     # создан в этом же потоке, где и run()
                icon.run(setup)
            except Exception:  # noqa: BLE001
                lg.exception("значок в трее не запустился (попытка %d)", self._tray_attempt)
                self.q.put(self._tray_failed)

        self._tray_thread = threading.Thread(target=run, name="tray", daemon=True)
        self._tray_thread.start()

    def _tray_failed(self) -> None:
        self.tray = None
        self.root.after(15000, self._launch_tray)

    def _tray_text(self, s: dict, state: str) -> str:
        t = TITLES.get(state, state)
        if state == "copying":
            if s["bytes"]:
                t += f" · {100 * s['have_bytes'] // s['bytes']}%"
            if s["speed"]:
                t += f" · {human(s['speed'])}/с"
        elif state in ("done", "waiting") and s["files"]:
            t += f" · {num(s['have_files'])} из {num(s['files'])}"
        return "Бэкап: " + t

    # ------------------------------------------------------------ обновление

    def tick(self, once: bool = False) -> None:
        while not self._closing:
            try:
                self.q.get_nowait()()
            except queue.Empty:
                break
        if self._closing:
            return                               # «Выход» или перезапуск — окна уже нет
        s = self.engine.snapshot()
        state = "paused" if s["paused"] else s["state"]
        self.v_state.set(s["text"] if not s["paused"] else "Пауза")
        self.v_detail.set(s["detail"] if not s["paused"] else "Копирование остановлено, интернет не используется")
        if s["bytes"]:
            part = s["cur_done"] if state == "copying" and s["current"] else 0     # большой файл — видно, что идёт
            self.bar["value"] = 1000 * min(s["bytes"], s["have_bytes"] + part) / s["bytes"]
            self.v_counts.set(f"Скопировано: {num(s['have_files'])} из {num(s['files'])} файлов · "
                              f"{human(s['have_bytes'])} из {human(s['bytes'])}")
        else:
            self.bar["value"] = 0
            self.v_counts.set("")
        if s["current"] and state == "copying":
            pct = f" — {100 * s['cur_done'] // max(1, s['cur_size'])}% из {human(s['cur_size'])}" if s["cur_size"] else ""
            self.v_current.set(f"Файл: {s['current']}{pct}")
        else:
            self.v_current.set("")
        if state == "copying" and s["speed"] > 0:
            self.v_speed.set(f"Скорость: {human(s['speed'])}/с · осталось ≈ {eta(s['left_bytes'] / s['speed'])}"
                             + (f" · ошибок: {s['errors']}" if s["errors"] else ""))
        elif s["left_files"] and state != "done":
            self.v_speed.set(f"Осталось: {num(s['left_files'])} файлов, {human(s['left_bytes'])}"
                             + (f" · ошибок: {s['errors']}" if s["errors"] else ""))
        else:
            self.v_speed.set(f"Ошибок: {s['errors']}" if s["errors"] else "")
        if state == "confirm":
            self.confirm.pack(fill="x", padx=12, pady=8)
        else:
            self.confirm.pack_forget()
        self.b_pause.configure(text="Продолжить" if s["paused"] else "Пауза")
        day = lambda ts: time.strftime("%d.%m.%Y", time.localtime(ts)) if ts else "—"     # noqa: E731
        bad = f" · повреждено и скачивается заново: {s['verify_bad']}" if s["verify_bad"] else ""
        if s["verifying"]:
            self.v_verify.set(f"Проверка копий: {num(s['verify_done'])} из {num(s['verify_total'])}{bad}")
        elif s["verify_last"]:
            self.v_verify.set(f"Проверка копий: последняя {day(s['verify_last'])}, следующая {day(s['verify_next'])}{bad}")
        else:
            self.v_verify.set("")
        top = s["log"][0] if s["log"] else None
        if top != self._log_top:
            self._log_top = top
            self.logbox.configure(state="normal")
            self.logbox.delete("1.0", "end")
            for ts, kind, text, path in s["log"]:
                self.logbox.insert("end", f"{time.strftime('%d.%m %H:%M:%S', time.localtime(ts))}  "
                                          f"{KIND.get(kind, '')}{text}{'  ' + path if path else ''}\n")
            self.logbox.configure(state="disabled")
        if self.tray:
            text = self._tray_text(s, state)
            try:
                if state != self._last_state or s["paused"] != self._last_paused:
                    self.tray.icon = self._tray_imgs[COLORS.get(state, COLORS["setup"])]
                if text != self._tray_status:
                    self._tray_status = text
                    self.tray.title = text[:120]           # подсказка при наведении (Windows: до 127 символов)
                    if sys.platform != "win32":            # в Windows меню пересобирается при каждом показе
                        self.tray.update_menu()
            except Exception:  # noqa: BLE001 — значок не обновился: окно всё равно работает
                pass
        self._last_state, self._last_paused = state, s["paused"]
        if not once:
            self.root.after(700, self.tick)

    def run(self) -> None:
        self.root.mainloop()


# ======================================================================== запуск

def _ensure_deps() -> bool:
    """Нет httpx/pystray/pillow в этом Python — предложить поставить их тем же интерпретатором."""
    global httpx, Image, ImageDraw
    missing = [pip for mod, pip in DEPS if importlib.util.find_spec(mod) is None]
    if missing:
        root = tk.Tk()
        root.withdraw()
        py = Path(sys.executable)
        py = py.with_name("python.exe") if py.name.lower() == "pythonw.exe" and py.with_name("python.exe").exists() else py
        cmd = [str(py), "-m", "pip", "install", *missing]
        need_core = any(importlib.util.find_spec(m) is None for m in ("httpx", "PIL"))
        if messagebox.askyesno("Photocloud — бэкап", "Для работы нужны библиотеки: " + ", ".join(missing) +
                               f".\n\nУстановить их сейчас в этот Python?\n{py}\n\nЭто займёт около минуты."):
            w = tk.Toplevel(root)
            w.title("Photocloud — бэкап")
            ttk.Label(w, text="Устанавливаю библиотеки…", padding=24).pack()
            w.update()
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                                   creationflags=0x08000000 if sys.platform == "win32" else 0)
                log.info("pip install %s: %s\n%s", " ".join(missing), r.returncode, (r.stdout + r.stderr)[-3000:])
                ok = r.returncode == 0
            except Exception as e:  # noqa: BLE001
                log.error("pip install: %s", e)
                ok = False
            w.destroy()
            if not ok:
                messagebox.showerror("Photocloud — бэкап", "Не получилось установить. Выполните в командной строке:\n"
                                     + " ".join(f'"{c}"' if " " in c else c for c in cmd))
            importlib.invalidate_caches()
        elif need_core:
            root.destroy()
            return False
        root.destroy()
    try:
        import httpx as _h
        from PIL import Image as _i, ImageDraw as _d
    except ImportError as e:
        log.error("нет библиотеки %s", e.name)
        return False
    httpx, Image, ImageDraw = _h, _i, _d
    return True


def main() -> None:
    d = app_dir()
    log_path = d / "backup.log"
    h = logging.handlers.RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[h], format="%(asctime)s %(levelname)s %(message)s")
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    log.info("старт %s: %s, python %s", VERSION, Path(__file__).resolve(), sys.executable)
    if "WindowsApps" in sys.executable or "PythonSoftwareFoundation" in sys.prefix:
        log.warning("Python из Microsoft Store: файлы в %%APPDATA%% он хранит в своей песочнице")

    if "--wait-pid" in sys.argv:             # перезапуск после обновления: ждём, пока старая копия выйдет
        try:
            winutil.wait_pid(int(sys.argv[sys.argv.index("--wait-pid") + 1]), 30)
        except (ValueError, IndexError):
            pass
    app = None
    inst = winutil.SingleInstance(d, lambda: app and app.q.put(app.show))
    if not inst.acquire():
        return                                   # уже запущен — показали его окно
    if not _ensure_deps():
        return
    cfg = Config()
    script = Path(__file__).resolve()
    if cfg.autostart and cfg.server:
        try:
            winutil.set_autostart(True, script)  # файл могли перенести — путь в автозапуске обновляем
        except OSError:
            pass
    engine = Engine(cfg)
    engine.start()
    log.info("запуск, папка: %s", cfg.root or "—")
    app = App(cfg, engine, script, start_hidden="--tray" in sys.argv, log_path=log_path)
    try:
        app.run()
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
