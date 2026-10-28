"""Доступ к фотографиям: SMB-шара Windows (боевой режим) или локальная папка (разработка).

Наружу (в браузер) пути не отдаются и обратно не принимаются: клиент знает
только непрозрачные id из индекса. Поэтому path traversal невозможен
по построению; проверки здесь — второй рубеж."""
from __future__ import annotations

import errno
import logging
import os
import threading
import time
import stat as statmod
from pathlib import Path
from typing import BinaryIO, Iterator

log = logging.getLogger("photocloud.storage")

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif"}
VIDEO_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".webm", ".mts", ".m2ts", ".avi"}
# браузер умеет играть только эти; остальные (видеокамеры AVCHD, старые AVI) — эскиз + скачать
PLAYABLE_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".webm"}
MEDIA_EXT = IMAGE_EXT | VIDEO_EXT
SKIP_NAMES = {"$recycle.bin", "system volume information", "thumbs.db", "desktop.ini", "@eadir", ".thumbnails"}
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# (относительный путь через '/', размер, mtime)
Item = tuple[str, int, float]


_FATAL_ERRNO = {errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTDIR, errno.EISDIR}


# NtStatus, при которых соединение/сессия действительно умерли — тогда переподключаемся
_RECONNECT_NT = {
    0xC0000203,  # STATUS_USER_SESSION_DELETED
    0xC000035C,  # STATUS_NETWORK_SESSION_EXPIRED
    0xC00000C9,  # STATUS_NETWORK_NAME_DELETED
    0xC000020C,  # STATUS_CONNECTION_DISCONNECTED
    0xC000013B,  # STATUS_LOCAL_DISCONNECT
    0xC000013C,  # STATUS_REMOTE_DISCONNECT
    0xC0000241,  # STATUS_CONNECTION_ABORTED
    0xC0000236,  # STATUS_CONNECTION_REFUSED
}
NT_REQUEST_NOT_ACCEPTED = 0xC00000D0   # Windows: исчерпан лимит входящих SMB-подключений


def _ntstatus(e: BaseException) -> int | None:
    v = getattr(e, "ntstatus", None)
    if v is None and e.__cause__ is not None:
        v = getattr(e.__cause__, "status", None)
    return v


def _not_connection_error(e: BaseException) -> bool:
    """Ошибки, которые НЕ лечатся переподключением: нет файла, нет прав, нет шары,
    файл занят и т.п. Раньше любой такой ответ Windows вызывал полное переподключение —
    при параллельных запросах это плодило сессии до лимита Windows («REQUEST_NOT_ACCEPTED»)."""
    if isinstance(e, ValueError) or getattr(e, "errno", None) in _FATAL_ERRNO:
        return True
    nt = _ntstatus(e)
    return nt is not None and nt not in _RECONNECT_NT


_MISSING_NT = {0xC0000034, 0xC000003A, 0xC000000F, 0xC0000056, 0xC0000033}   # нет файла/пути, удаляется, плохое имя


def is_missing(e: BaseException) -> bool:
    """Файла больше нет (удалили или переименовали на ПК) — это не «ПК недоступен»."""
    if isinstance(e, FileNotFoundError) or getattr(e, "errno", None) in (errno.ENOENT, errno.ENOTDIR):
        return True
    return _ntstatus(e) in _MISSING_NT


def _skip(name: str) -> bool:
    return name.startswith(".") or name.lower() in SKIP_NAMES


def _is_media(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in MEDIA_EXT


def _check_rel(rel: str) -> list[str]:
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") or "\\" in p or "\x00" in p or ":" in p for p in parts):
        raise ValueError("bad path")
    return parts


class LocalStorage:
    """ТОЛЬКО ДЛЯ ТЕСТОВ: фото из локальной папки. В проде будет удалено."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()

    def reachable(self) -> bool:
        return self.root.is_dir()

    skipped = 0          # папок, которые не прочитались при последнем обходе

    def walk(self) -> Iterator[Item]:
        stack = [("", self.root)]
        self.skipped = 0
        while stack:
            prefix, d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError as e:
                log.warning("scandir %s: %s", prefix or "/", e)
                self.skipped += 1
                continue
            with it:
                for e in it:
                    if _skip(e.name) or e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                        continue
                    rel = f"{prefix}/{e.name}" if prefix else e.name
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    # Windows: скрытые, системные и точки повторной обработки пропускаем
                    if getattr(st, "st_file_attributes", 0) & (
                            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT):
                        continue
                    if statmod.S_ISDIR(st.st_mode):
                        stack.append((rel, e.path))
                    elif statmod.S_ISREG(st.st_mode) and _is_media(e.name):
                        yield rel, st.st_size, st.st_mtime

    def local_path(self, rel: str) -> Path:
        rp = self.root.joinpath(*_check_rel(rel)).resolve()
        if self.root not in rp.parents:
            raise PermissionError("outside root")
        return rp

    def open(self, rel: str) -> BinaryIO:
        return open(self.local_path(rel), "rb")


# Одно SMB-соединение обслуживает все потоки. Windows выдаёт ему ограниченное число
# «кредитов» на одновременные запросы; если запросов больше, smbprotocol не ждёт, а
# падает с «Request requires 1 credits but only 0 credits are available». Поэтому
# одновременных сетевых операций — не больше SMB_PARALLEL, а нехватку кредитов
# пережидаем короткой паузой (это не обрыв связи — переподключаться нельзя).
SMB_PARALLEL = 6
SMB_BACKGROUND = 4     # фоновое чтение дат/обход папок — не больше стольких слотов


class GateBusy(TimeoutError):
    """Все слоты заняты дольше GATE_WAIT. Это перегрузка, а не обрыв: переподключаться нельзя."""


class _Gate:
    """Слоты для сетевых операций с приоритетом: эскизы и просмотр (то, что ждёт человек)
    всегда проходят первыми, а фоновое чтение дат занимает не больше SMB_BACKGROUND слотов
    и уступает, пока кто-то из «живых» запросов ждёт."""

    def __init__(self, n: int, bg_max: int):
        self.n, self.bg_max = n, bg_max
        self.used = self.bg_used = self.fg_waiting = 0
        self.cv = threading.Condition()

    def acquire(self, bg: bool, timeout: float) -> bool:
        end = time.monotonic() + timeout
        with self.cv:
            if not bg:
                self.fg_waiting += 1
            try:
                while True:
                    if self.used < self.n and (not bg or (self.bg_used < self.bg_max and not self.fg_waiting)):
                        self.used += 1
                        self.bg_used += bg
                        return True
                    left = end - time.monotonic()
                    if left <= 0:
                        return False
                    self.cv.wait(left)
            finally:
                if not bg:
                    self.fg_waiting -= 1

    def release(self, bg: bool) -> None:
        with self.cv:
            self.used -= 1
            self.bg_used -= bg
            self.cv.notify_all()


_gate = _Gate(SMB_PARALLEL, SMB_BACKGROUND)


def _background() -> bool:
    # потоки индексации: обход папок («index») и чтение дат съёмки («meta…»)
    return threading.current_thread().name.startswith(("index", "meta"))


def _is_credit_error(e: BaseException) -> bool:
    return "credits" in str(e) and "available" in str(e)


_active: dict[int, float] = {}          # операция -> к какому моменту должна закончиться (для сторожа)
_active_mu = threading.Lock()
GATE_WAIT = 30                          # дольше не ждём свободного слота — отдаём ошибку, клиент повторит
HANG_AFTER = 40                         # сетевая операция дольше — считаем, что SMB завис


def _gated(fn, *a, **kw):
    bg = _background()
    for attempt in range(6):
        if not _gate.acquire(bg, GATE_WAIT * (4 if bg else 1)):
            raise GateBusy("SMB: все слоты заняты")
        key = id(threading.current_thread()) ^ int(time.monotonic() * 1e6)
        with _active_mu:
            _active[key] = time.monotonic() + HANG_AFTER
        try:
            return fn(*a, **kw)
        except Exception as e:  # noqa: BLE001
            if not _is_credit_error(e) or attempt == 5:
                raise
        finally:
            with _active_mu:
                _active.pop(key, None)
            _gate.release(bg)
        time.sleep(0.05 * (attempt + 1))


class _SMBFile:
    """Файл с шары: каждое чтение и закрытие проходит через общий «шлюз»."""

    def __init__(self, f):
        self._f = f

    def read(self, n: int = -1) -> bytes:
        return _gated(self._f.read, n)

    def seek(self, *a):
        return self._f.seek(*a)            # локальная операция, сеть не трогает

    def tell(self) -> int:
        return self._f.tell()

    def close(self) -> None:
        try:
            _gated(self._f.close)
        except Exception:  # noqa: BLE001 — закрытие после обрыва связи не должно ронять запрос
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


class SMBStorage:
    def __init__(self, s):
        import smbclient  # noqa: импорт здесь, чтобы локальный режим не требовал библиотеку
        self._smb = smbclient
        self.host, self.port = s.smb_host, s.smb_port
        self.base = f"\\\\{s.smb_host}\\{s.smb_share}"
        if s.smb_subdir:
            self.base += "\\" + s.smb_subdir.replace("/", "\\")
        self._creds = dict(username=s.smb_user, password=s.smb_password, port=s.smb_port,
                           encrypt=s.smb_encrypt, connection_timeout=5, require_signing=True)
        self._registered = False
        self._mu = threading.RLock()        # только регистрация сессии
        self._reset_mu = threading.Lock()   # сброс: короткий, без сети — не ждёт регистрацию
        self._reset_at = 0.0
        self._down_until = 0.0
        self._warned = 0.0
        threading.Thread(target=self._watchdog, name="smb-watchdog", daemon=True).start()

    def _watchdog(self) -> None:
        """Если Windows перестала отвечать посреди запроса, smbprotocol ждёт ответа вечно,
        и занятые слоты блокируют всё приложение. Сторож рвёт такое соединение — зависшие
        вызовы получают ошибку, клиенты повторяют запрос уже по новому подключению."""
        while True:
            time.sleep(2)
            with _active_mu:
                due = min(_active.values(), default=None)
            if due is not None and time.monotonic() > due:
                log.warning("SMB: компьютер не отвечает на запрос — сбрасываю соединение")
                self._reset_locked()
                with _active_mu:
                    _active.clear()

    def reset(self) -> None:
        """После сна ПК соединение мёртвое — сбрасываем кэш подключений."""
        self._reset_locked()

    def _reset_locked(self) -> None:
        """Рвём соединения без вежливого «выхода»: штатный reset_connection_cache()
        сначала закрывает файлы и сессию и ждёт ответа сервера — у выключенного ПК
        это ожидание бесконечное, и вместе с ним зависало всё приложение.
        Закрытие сокета будит все потоки, ждущие ответа, — они сразу получают ошибку."""
        with self._reset_mu:
            self._reset_now()

    def _reset_now(self) -> None:
        try:
            from smbclient import _pool
            cache = _pool._SMB_CONNECTIONS
            for name in list(cache.keys()):
                conn = cache.pop(name, None)
                if conn is not None:
                    try:
                        conn.disconnect(close=False)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass
        self._registered = False
        self._reset_at = time.time()

    def _session(self) -> None:
        if self._registered:
            return
        if time.monotonic() < self._down_until:
            # только что не смогли подключиться — не стучимся снова каждым потоком по 5 с
            raise ConnectionError("SMB: компьютер недоступен")
        # Вход на ПК: если тот выключился посреди рукопожатия, smbprotocol ждёт ответа
        # вечно — раньше это держало замок, и вставало всё приложение. Теперь ждём замок
        # ограниченно, а само рукопожатие стережёт сторож (сброс будит ждущий поток).
        if not self._mu.acquire(timeout=15):
            raise ConnectionError("SMB: подключение к компьютеру не устанавливается")
        try:
            if self._registered:
                return
            key = id(threading.current_thread()) ^ int(time.monotonic() * 1e6) ^ 1
            with _active_mu:
                _active[key] = time.monotonic() + 15
            try:
                self._smb.register_session(self.host, **self._creds)
            except ValueError as e:
                # smbprotocol сообщает «не удалось подключиться» как ValueError — для остального
                # кода это обрыв связи, а не битый файл (иначе эскиз попал бы в «не декодируется»)
                if isinstance(e.__cause__, OSError):
                    self._down_until = time.monotonic() + 5
                    raise ConnectionError(f"SMB: компьютер недоступен ({e.__cause__})") from e
                raise
            except (OSError, TimeoutError) as e:
                if not _not_connection_error(e):
                    self._down_until = time.monotonic() + 5
                raise
            finally:
                with _active_mu:
                    _active.pop(key, None)
            self._registered = True
        finally:
            self._mu.release()

    def _retry(self, fn):
        try:
            return self._retry_inner(fn)
        except ValueError as e:
            # smbclient сам переподключается внутри вызова и сообщает «не удалось
            # подключиться» как ValueError — для нас это недоступный ПК, а не битый файл
            if isinstance(e.__cause__, OSError):
                self._down_until = time.monotonic() + 5
                raise ConnectionError(f"SMB: компьютер недоступен ({e.__cause__})") from e
            raise

    def _retry_inner(self, fn):
        self._session()
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — smbprotocol кидает свои исключения
            if _ntstatus(e) == NT_REQUEST_NOT_ACCEPTED:
                now = time.time()
                if now - self._warned > 60:
                    self._warned = now
                    log.warning("SMB: компьютер не принимает новые подключения (REQUEST_NOT_ACCEPTED). "
                                "Windows 10/11 допускает ~20 входящих SMB-сессий — закрой лишние "
                                "подключения к шаре или перезагрузи ПК")
                raise
            if isinstance(e, GateBusy) or _not_connection_error(e) or _is_credit_error(e):
                raise
            # переподключаемся не чаще раза в 10 с и одним потоком: остальные просто повторяют
            if time.time() - self._reset_at > 10:
                log.info("SMB: переподключение (%s)", type(e).__name__)
                self._reset_locked()
            self._session()
            return fn()

    skipped = 0          # папок, которые не прочитались при последнем обходе

    def walk(self) -> Iterator[Item]:
        # собираем список целиком внутри _retry, чтобы переподключение было атомарным
        def run() -> list[Item]:
            out: list[Item] = []
            stack = [("", self.base)]
            self.skipped = 0
            while stack:
                prefix, d = stack.pop()
                try:
                    entries = _gated(lambda: list(self._smb.scandir(d, **self._creds)))
                except OSError as e:
                    # корень шары недоступен (нет шары, нет прав, лимит подключений) — это ошибка
                    # индексации целиком; недоступная подпапка — просто пропускаем её
                    if not prefix or not _not_connection_error(e) or _ntstatus(e) == NT_REQUEST_NOT_ACCEPTED:
                        raise
                    log.warning("scandir %s: %s", prefix, type(e).__name__)
                    self.skipped += 1
                    continue
                for e in entries:
                    if _skip(e.name):
                        continue
                    info = e.smb_info
                    attrs = info.file_attributes
                    # точки повторной обработки (junction/symlink) пропускаем:
                    # они могут вести за пределы шары на стороне Windows
                    if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SYSTEM):
                        continue
                    rel = f"{prefix}/{e.name}" if prefix else e.name
                    if e.is_dir():
                        stack.append((rel, f"{d}\\{e.name}"))
                    elif _is_media(e.name) and not attrs & FILE_ATTRIBUTE_HIDDEN:
                        mtime = info.last_write_time.timestamp()
                        out.append((rel, int(info.end_of_file), mtime))
            return out

        yield from self._retry(run)

    def open(self, rel: str) -> BinaryIO:
        path = self.base + "\\" + "\\".join(_check_rel(rel))
        return _SMBFile(self._retry(
            lambda: _gated(self._smb.open_file, path, mode="rb", share_access="rw", **self._creds)))


def make_storage(s):
    if s.storage == "local":
        return LocalStorage(s.local_root)
    return SMBStorage(s)
