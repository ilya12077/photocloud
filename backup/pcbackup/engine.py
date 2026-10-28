"""Движок бэкапа: сверка с сервером photocloud и копирование оригиналов.

Без интерфейса — окно и значок в трее только читают состояние (Engine.snapshot())
и вызывают методы управления (pause/resume/sync_now/wake_now/confirm_delete).

Папка бэкапа:
    Архив\\…        — копия архива один в один (пути и даты изменения как на ПК)
    Версии\\…       — прежние варианты изменённых файлов, хранятся всегда
    Удалённые\\…    — файлы, которых больше нет на ПК, хранятся всегда
    .photocloud-backup\\state.db, tmp\\ — своя база и недокачанные файлы
"""
from __future__ import annotations

import collections
import datetime
import gzip
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import sys
import threading
import time
import zlib
from pathlib import Path
from urllib.parse import quote

import httpx

VERSION = "1.1.3"
log = logging.getLogger("pcbackup")

ARCHIVE, VERSIONS, DELETED, META = "Архив", "Версии", "Удалённые", ".photocloud-backup"
CHUNK = 256 * 1024
PASS_MAX = 15 * 60          # с: проход не дольше — потом свежий список (досчитались новые хеши)
IDLE_EVERY = 10             # с: всё скопировано — спрашивать сервер о новом так часто
PC_OFF_EVERY = 10           # с: ПК выключен — проверять так часто
LOCAL_EVERY = 10 * 60       # с: сверять папку бэкапа с базой (на месте ли файлы) не чаще
DISK_EVERY = 10             # с: мало места — так часто смотреть, не освободилось ли
REPORT_EVERY = 5 * 60       # с: отчёт серверу, если состояние не меняется
REPORT_COPYING = 5          # с: а во время копирования — так часто (админка видит ход в реальном времени)
DELETE_SUSPICIOUS = (100, 0.05)   # больше стольких И больше такой доли — ждём подтверждения
IS_WIN = sys.platform == "win32"


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
        self.mu = threading.Lock()

    def files(self) -> dict[str, tuple[int, int, str]]:
        with self.mu:
            return {p: (s, m, h) for p, s, m, h in self.con.execute("SELECT path, size, mtime, sha FROM files")}

    def put(self, path: str, size: int, mtime: int, sha: str) -> None:
        with self.mu:
            self.con.execute("INSERT OR REPLACE INTO files VALUES(?, ?, ?, ?, ?)", (path, size, mtime, sha, time.time()))

    def put_many(self, rows) -> None:
        with self.mu:
            self.con.execute("BEGIN")
            self.con.executemany("INSERT OR REPLACE INTO files VALUES(?, ?, ?, ?, ?)", rows)
            self.con.execute("COMMIT")

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
        self._want_sync = self._want_wake = self._confirm = False
        self._reload = True
        self.mu = threading.Lock()
        self.log = collections.deque(maxlen=300)
        self.st = dict(state="setup", text="Укажите сервер, токен и папку в настройках", detail="",
                       files=0, bytes=0, have_files=0, have_bytes=0, left_files=0, left_bytes=0,
                       waiting_hash=0, current="", cur_done=0, cur_size=0, speed=0.0, errors=0,
                       pending_delete=0, copied=0, copied_bytes=0, last_ok=0.0, server="",
                       wire_bytes=0, raw_bytes=0)
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
        self.ev.set()

    def wake_now(self) -> None:
        self._want_wake = True
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
            self._sleep(15 if waking else PC_OFF_EVERY)
            return
        self._woke = True              # ПК уже включён — будить при запуске не нужно
        if self._pass():
            self._sleep(IDLE_EVERY if not self._want_sync else 0)
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

    def _verify_local(self, local: dict) -> dict:
        """Файлы, которые пропали из Архива или изменились руками, считаем отсутствующими —
        их скачаем заново (изменённый сначала уйдёт в Версии)."""
        out, gone = {}, []
        for p, v in local.items():
            try:
                st = os.stat(lp(self._arch(p)))
            except OSError:
                gone.append(p)
                continue
            except ValueError:
                gone.append(p)
                continue
            if st.st_size != v[0]:
                gone.append(p)
                continue
            out[p] = v
        for p in gone:
            self.db.drop(p)
        if gone:
            self._note(f"в папке бэкапа пропали или изменились {len(gone)} файлов — скопирую заново", "warn")
        return out

    # ------------------------------------------------------------ операции с файлами

    def _arch(self, rel: str) -> Path:
        return self.root.joinpath(ARCHIVE, *safe_rel(rel))

    def _aside(self, src: Path, folder: str, rel: str) -> Path:
        """Убрать файл в Версии/Удалённые, не затирая то, что там уже лежит."""
        dst = self.root.joinpath(folder, *safe_rel(rel))
        if folder == VERSIONS or os.path.exists(lp(dst)):
            dst = dst.with_name(f"{dst.stem} ({stamp()}){dst.suffix}")
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
        every = REPORT_COPYING if state == "copying" else REPORT_EVERY
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
                         **({"error": error} if error else {})})
