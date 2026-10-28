"""Индекс медиатеки в памяти.

Фаза 1 — обход папок (только имя/размер/mtime), индекс сразу доступен с датами
из кэша или по mtime. Фаза 2 — в фоне читаем дату съёмки (EXIF / mp4 mvhd) у тех
файлов, которых нет в кэше, и публикуем новую версию. Кэш дат — таблица SQLite
в DATA_DIR, ключ (путь, размер, mtime), так что повторно файлы не читаются."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import threading
import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import meta
from .storage import PLAYABLE_EXT, VIDEO_EXT

log = logging.getLogger("photocloud.library")

F_VIDEO = 1
F_TAKEN = 2   # дата из EXIF/метаданных
F_NAME = 4    # дата из имени файла
F_NOPLAY = 8  # видео, которое браузер не воспроизведёт
F_LIVE = 16   # «живое фото»: у снимка есть короткий ролик-пара
F_FOLDER = 32 # известен только год — из названия папки

LIVE_IMG = {".jpg", ".jpeg", ".heic", ".heif"}
LIVE_VID = {".mp4", ".mov"}
LIVE_MAX = 40 * 1024 * 1024     # ролик живого фото — пара секунд, обычно 2–10 МБ


def _under(rel: str, folders) -> bool:
    # сравнение по целым частям пути: «фотки» не захватывает «фотки2»
    return any(rel == f or rel.startswith(f + "/") for f in folders)


def folder_ok(rel: str, access) -> bool:
    """Путь файла (или папки) rel доступен? access=None — всё; иначе (allow, deny):
    allow — разрешённые папки (None — все), deny — скрытые папки внутри них."""
    if access is None:
        return True
    allow, deny = access
    if allow is not None and not _under(rel, allow):
        return False
    return not _under(rel, deny)


class View:
    """Список файлов для конкретного набора папок (админ — все)."""
    __slots__ = ("payload", "gz", "version", "count")

    def __init__(self, payload: bytes, gz: bytes, version: str, count: int):
        self.payload, self.gz, self.version, self.count = payload, gz, version, count


def _encode(photos: list, folder_list: list[str], fmap: dict[int, int] | None = None) -> View:
    # колоночный формат: так gzip жмёт заметно лучше, чем массив строк
    dates = [int(p.date) for p in photos]
    cols = {
        "id": "".join(p.id for p in photos),
        "f": [p.folder if fmap is None else fmap[p.folder] for p in photos],
        "n": [p.name for p in photos],
        # даты по убыванию -> храним разницу с предыдущей (маленькие числа)
        "d": [dates[0]] + [dates[i - 1] - dates[i] for i in range(1, len(dates))] if dates else [],
        "m": [int(p.mtime) - d for p, d in zip(photos, dates)],     # чаще всего 0
        "s": [(p.size + 1023) // 1024 for p in photos],              # КБ
        "x": [p.flags() for p in photos],
        "live": {p.id: p.live for p in photos if p.live},
    }
    body = json.dumps({"folders": folder_list, **cols}, ensure_ascii=False, separators=(",", ":"))
    version = hashlib.blake2b(body.encode("utf-8", "replace"), digest_size=8).hexdigest()
    payload = ('{"v":"%s",' % version + body[1:]).encode("utf-8", "replace")
    return View(payload, gzip.compress(payload, compresslevel=9), version, len(photos))


def photo_id(rel: str, salt: int = 0) -> str:
    """8 символов [A-Za-z0-9_-] (48 бит) — короче список для медленных клиентов.
    Стабилен между пересборками, поэтому кэш эскизов в браузере не теряется."""
    data = rel.encode("utf-8", "surrogatepass") + (b"\0%d" % salt if salt else b"")
    d = hashlib.blake2b(data, digest_size=6, person=b"photocloud").digest()
    return base64.urlsafe_b64encode(d).decode()


@dataclass(slots=True)
class Photo:
    id: str
    rel: str
    folder: int
    name: str
    size: int
    mtime: float
    ext: str
    taken: float = 0.0     # из метаданных; 0 = неизвестно
    live: str = ""         # у фото: id ролика-пары; у ролика: id фото, к которому он относится
    named: float = 0.0     # из имени файла; 0 = нет
    year: int = 0          # из названия папки; 0 = нет
    year_ts: float = 0.0   # 1 января этого года, полдень (в часовом поясе архива)

    @property
    def date(self) -> float:
        # приоритет: метаданные -> имя файла -> год папки -> дата изменения
        if self.taken or self.named:
            return self.taken or self.named
        if self.year and time.localtime(self.mtime).tm_year != self.year:
            # дата изменения из другого года (файл копировали) — ставим 1 января года из папки
            return self.year_ts
        return self.mtime

    def folder_only(self) -> bool:
        return not (self.taken or self.named) and bool(self.year) and \
            time.localtime(self.mtime).tm_year != self.year

    def flags(self) -> int:
        f = 0
        if self.video:
            f |= F_VIDEO | (0 if self.ext in PLAYABLE_EXT else F_NOPLAY)
        if self.live and not self.video:
            f |= F_LIVE
        if self.taken:
            f |= F_TAKEN
        elif self.named:
            f |= F_NAME
        elif self.folder_only():
            f |= F_FOLDER
        return f

    @property
    def video(self) -> bool:
        return self.ext in VIDEO_EXT

    def cache_key(self) -> str:
        return f"{self.rel}\0{self.size}\0{int(self.mtime)}"


class MetaCache:
    """Даты съёмки: в памяти — словарь для быстрых проверок, на диске — таблица SQLite.
    Пишутся только новые записи (пачками), а не весь кэш целиком."""

    def __init__(self, db):
        self.db = db
        self.d: dict[str, float] = db.dates_load()
        self._pending: list[tuple[str, float]] = []
        self._mu = threading.Lock()
        log.info("кэш дат: %d записей", len(self.d))

    def get(self, key: str):
        return self.d.get(key)

    def put(self, key: str, ts: float) -> None:
        with self._mu:
            self.d[key] = ts
            self._pending.append((key, ts))

    def save(self, keep: set[str] | None = None) -> None:
        with self._mu:
            batch, self._pending = self._pending, []
            if keep is not None:
                self.d = {k: v for k, v in self.d.items() if k in keep}
        try:
            self.db.dates_put(batch)
            if keep is not None:
                gone = self.db.dates_prune(keep)
                if gone:
                    log.info("кэш дат: убрано %d записей об отсутствующих файлах", gone)
        except Exception as e:  # noqa: BLE001
            log.warning("не удалось сохранить кэш дат: %s", e)
            with self._mu:
                self._pending = batch + self._pending


class Library:
    def __init__(self, tz, meta_threads: int = 4, db=None):
        self.tz = tz
        self.meta_threads = meta_threads
        self.cache = MetaCache(db)
        self.state = "empty"          # empty | building | ready | error
        self.error = ""
        self.built_at = 0.0
        self.attempted_at = 0.0
        self.progress = 0
        self.meta_total = 0           # сколько файлов надо дочитать
        self.meta_done = 0
        # фаза 3: подробности (камера, размеры, GPS) для панели «Подробнее» -> в базу
        self.info_reader = None       # p -> dict; задаёт main (читает файл с ПК)
        self.info_total = self.info_done = 0
        self.info_state = ""          # "" | running | stopped | done
        self._info_stop = threading.Event()
        # фаза 4: SHA-256 содержимого для клиентов бэкапа -> в базу (только если они есть)
        self.hash_reader = None       # p -> hex; задаёт main
        self.hash_wanted = lambda: False
        self.hash_total = self.hash_done = 0
        self.hash_bytes_total = self.hash_bytes_done = 0
        self.hash_state = ""          # "" | running | stopped | done
        self._hash_stop = threading.Event()
        self._hlock = threading.Lock()
        self._hthread: threading.Thread | None = None
        self.skipped = 0              # папок, не прочитанных при последнем обходе (индекс неполный)
        self.version = ""
        self.by_id: dict[str, Photo] = {}
        self.payload = b"{}"
        self.payload_gz = gzip.compress(b"{}")
        self._feed: list = []
        self._folders: list[str] = [""]
        self._views: dict = {None: View(b"{}", gzip.compress(b"{}"), "", 0)}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def get(self, pid: str) -> Photo | None:
        return self.by_id.get(pid)

    def busy(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def stale(self, ttl: int) -> bool:
        if self.busy():
            return False
        if self.state == "empty":
            return True
        age = time.time() - self.attempted_at
        return age > (30 if self.state == "error" else ttl)

    def start_build(self, storage, on_error=None) -> bool:
        with self._lock:
            if self.busy():
                return False
            self._thread = threading.Thread(target=self._build, args=(storage, on_error),
                                            name="index", daemon=True)
            self._thread.start()
            return True

    # ------------------------------------------------------------ публикация

    @staticmethod
    def pair_live(photos: list[Photo]) -> int:
        """Живые фото: снимок и ролик в одной папке с одинаковым именем
        (IMG_1234.HEIC + IMG_1234.MOV у iPhone, IMG_2026…jpg + IMG_2026…MP4 у Android/Takeout).
        Ролик прячется из ленты и показывается внутри фото."""
        groups: dict = {}
        for p in photos:
            p.live = ""
            stem = p.name.rsplit(".", 1)[0].lower()
            groups.setdefault((p.folder, stem), []).append(p)
        n = 0
        for g in groups.values():
            if len(g) != 2:
                continue
            img = next((p for p in g if p.ext in LIVE_IMG), None)
            vid = next((p for p in g if p.ext in LIVE_VID), None)
            if img and vid and vid.size <= LIVE_MAX:
                img.live, vid.live = vid.id, img.id
                n += 1
        return n

    def _publish(self, photos: list[Photo], folder_list: list[str]) -> None:
        self.pair_live(photos)
        everything = photos
        # ролики живых фото в ленту не попадают, но остаются доступны по id
        photos = [p for p in photos if not (p.video and p.live)]
        photos = sorted(photos, key=lambda p: (int(p.date), p.name), reverse=True)
        full = _encode(photos, folder_list)
        # атомарная подмена: читатели видят либо старую, либо новую версию целиком
        self.by_id = {p.id: p for p in everything}
        self._feed, self._folders = photos, folder_list
        self._views = {None: full}
        self.payload, self.payload_gz, self.version = full.payload, full.gz, full.version

    def view(self, folders) -> View:
        """Список только из разрешённых папок (folders=None — всё). Папки-предки разрешённых
        попадают в дерево только именами — чтобы до них можно было дойти; соседние — нет."""
        views, feed, flist = self._views, self._feed, self._folders     # один снимок версии
        if not self.version:
            return views[None]                  # список ещё не собран — пусто для всех
        key = None if folders is None else (None if folders[0] is None else tuple(sorted(folders[0])),
                                            tuple(sorted(folders[1])))
        v = views.get(key)
        if v is not None:
            return v
        need = {""}
        for f in (key[0] or ()):
            parts = f.split("/")
            need.update("/".join(parts[:i]) for i in range(1, len(parts)))
        keep = [i for i, fp in enumerate(flist) if fp in need or folder_ok(fp, key)]
        fmap = {old: new for new, old in enumerate(keep)}
        v = _encode([p for p in feed if folder_ok(p.rel, key)], [flist[i] for i in keep], fmap)
        if len(views) > 64:
            views.clear()
        views[key] = v
        return v

    # ------------------------------------------------------------ сборка

    def _build(self, storage, on_error) -> None:
        prev_state = self.state
        self.state, self.progress = "building", 0
        self.meta_total = self.meta_done = 0
        t0 = self.attempted_at = time.time()
        try:
            folders: dict[str, int] = {"": 0}
            folder_list = [""]
            photos: list[Photo] = []
            seen: set[str] = set()
            for rel, size, mtime in storage.walk():
                folder, _, name = rel.rpartition("/")
                if folder not in folders:
                    parts = folder.split("/")
                    for i in range(1, len(parts) + 1):
                        f = "/".join(parts[:i])
                        if f not in folders:
                            folders[f] = len(folder_list)
                            folder_list.append(f)
                pid, salt = photo_id(rel), 0
                while pid in seen:   # коллизия 48-битного хэша: редкость, но файлы не путаем
                    salt += 1
                    pid = photo_id(rel, salt)
                seen.add(pid)
                p = Photo(pid, rel, folders[folder], name, size, mtime, os.path.splitext(name)[1].lower())
                p.named = meta.name_date(name, self.tz) or 0.0
                p.year = meta.folder_year(rel) or 0
                if p.year:
                    p.year_ts = datetime.datetime(p.year, 1, 1, 12, tzinfo=self.tz).timestamp()
                c = self.cache.get(p.cache_key())
                if c:
                    p.taken = c
                photos.append(p)
                self.progress = len(photos)
            self._publish(photos, folder_list)
            self.skipped = getattr(storage, "skipped", 0)
            self.built_at, self.state, self.error = time.time(), "ready", ""
            log.info("индекс: %d файлов, %d папок за %.1fс, живых фото: %d", len(photos), len(folder_list),
                     time.time() - t0, sum(1 for p in photos if p.live and not p.video))
        except Exception as e:  # noqa: BLE001
            log.exception("ошибка индексации")
            self.error = type(e).__name__
            self.state = "ready" if prev_state == "ready" and self.by_id else "error"
            if on_error:
                on_error(self.error)
            return

        # ---- фаза 2: даты съёмки
        todo = [p for p in photos if p.cache_key() not in self.cache.d and meta.needs_scan(p.ext)]
        if not todo:
            self.cache.save(keep={p.cache_key() for p in photos})
            self._after(storage, photos)
            return
        self.meta_total, self.meta_done = len(todo), 0
        t1 = time.time()
        failures = 0

        def one(p: Photo):
            with storage.open(p.rel) as f:
                return p, meta.taken_at(f, p.ext, p.size, self.tz)

        with ThreadPoolExecutor(self.meta_threads, thread_name_prefix="meta") as ex:
            futs = [ex.submit(one, p) for p in todo]
            for i, fut in enumerate(as_completed(futs), 1):
                try:
                    p, ts = fut.result()
                except Exception as e:  # noqa: BLE001 — не прочитали: не кэшируем, попробуем в следующий раз
                    failures += 1
                    if failures > 50 and failures > i // 2:
                        log.warning("даты съёмки: слишком много ошибок (%s), прерываю", type(e).__name__)
                        for f2 in futs:
                            f2.cancel()
                        break
                    continue
                self.cache.put(p.cache_key(), ts or 0.0)
                if ts:
                    p.taken = ts
                self.meta_done = i
                if i % 500 == 0:
                    self.cache.save()
        self.meta_done = self.meta_total
        self.cache.save(keep={p.cache_key() for p in photos})
        self._publish(photos, folder_list)
        log.info("даты съёмки: %d файлов за %.1fс, найдено у %d", len(todo), time.time() - t1,
                 sum(1 for p in todo if p.taken))
        self._after(storage, photos)

    def _after(self, storage, photos: list[Photo]) -> None:
        self._collect_info(storage, photos)
        self.start_hashes(storage)

    # ------------------------------------------------------------ фаза 3: подробности в базу

    def stop_info(self) -> None:
        """Админ остановил текущий сбор. Следующее сканирование папок (по интервалу
        или вручную) продолжит с того места — собранное уже лежит в базе."""
        self._info_stop.set()

    def _collect_info(self, storage, photos: list[Photo]) -> None:
        """Камера, размеры и координаты всех фото, которых ещё нет в базе — чтобы панель
        «Подробнее» открывалась сразу. Фоновые потоки («meta…») уступают эскизам и просмотру."""
        db, reader = self.cache.db, self.info_reader
        if reader is None or db is None:
            return
        keep = {p.cache_key() for p in photos}
        try:
            gone = db.info_prune(keep)
            if gone:
                log.info("подробности: убрано %d записей об отсутствующих файлах", gone)
            have = db.info_keys()
        except Exception as e:  # noqa: BLE001
            log.warning("подробности: база недоступна (%s)", e)
            return
        todo = [p for p in photos if not p.video and p.cache_key() not in have]
        if not todo:
            self.info_state = "done"
            return
        self._info_stop.clear()
        self.info_total, self.info_done, self.info_state = len(todo), 0, "running"
        t0, failures, batch = time.time(), 0, []

        def one(p: Photo):
            if self._info_stop.is_set():
                return None
            return p.cache_key(), json.dumps(reader(p), separators=(",", ":"))

        with ThreadPoolExecutor(self.meta_threads, thread_name_prefix="meta-info") as ex:
            futs = [ex.submit(one, p) for p in todo]
            for i, fut in enumerate(as_completed(futs), 1):
                if self._info_stop.is_set():
                    for f2 in futs:
                        f2.cancel()
                    break
                try:
                    r = fut.result()
                except Exception as e:  # noqa: BLE001 — не прочитали: попробуем в следующий раз
                    failures += 1
                    if failures > 50 and failures > i // 2:
                        log.warning("подробности: слишком много ошибок (%s), прерываю", type(e).__name__)
                        for f2 in futs:
                            f2.cancel()
                        break
                    continue
                if r:
                    batch.append(r)
                self.info_done = i
                if len(batch) >= 200:
                    db.info_put_many(batch)
                    batch = []
        db.info_put_many(batch)
        stopped = self._info_stop.is_set()
        self.info_state = "stopped" if stopped else "done"
        log.info("подробности: %d из %d файлов за %.1fс%s", self.info_done, self.info_total,
                 time.time() - t0, " — остановлено" if stopped else "")

    # ------------------------------------------------------------ фаза 4: хеши для бэкапа

    def start_hashes(self, storage) -> bool:
        """Хеши считаются в своём потоке: первый проход по архиву — это часы, и всё это
        время сканирование папок и даты должны работать как обычно. Если пока считали,
        список файлов обновился — сразу ещё круг по новым."""
        with self._hlock:
            if (self._hthread and self._hthread.is_alive()) or not self.by_id or not self.hash_wanted():
                return False

            def run():
                while True:
                    ver = self.version
                    self._collect_hashes(storage, list(self.by_id.values()))
                    if self.version == ver or self.hash_state in ("stopped", "error") or not self.hash_wanted():
                        return

            self._hthread = threading.Thread(target=run, name="meta-hashes", daemon=True)
            self._hthread.start()
            return True

    def stop_hashes(self) -> None:
        self._hash_stop.set()

    def _collect_hashes(self, storage, photos: list[Photo]) -> None:
        """SHA-256 всех файлов, которых ещё нет в базе. Читает файлы целиком, поэтому
        только когда есть клиенты бэкапа, в два потока и в фоновой очереди SMB."""
        db, reader = self.cache.db, self.hash_reader
        if reader is None or db is None or not self.hash_wanted():
            return
        try:
            gone = db.hashes_prune({p.cache_key() for p in photos})
            if gone:
                log.info("хеши: убрано %d записей об отсутствующих файлах", gone)
            have = set(db.hashes_load())
        except Exception as e:  # noqa: BLE001
            log.warning("хеши: база недоступна (%s)", e)
            return
        # сначала новые: их бэкап ждёт в первую очередь
        todo = sorted((p for p in photos if p.cache_key() not in have), key=lambda p: p.date, reverse=True)
        if not todo:
            self.hash_state = "done"
            return
        self._hash_stop.clear()
        self.hash_total, self.hash_done, self.hash_state = len(todo), 0, "running"
        self.hash_bytes_total, self.hash_bytes_done = sum(p.size for p in todo), 0
        t0, failures, batch, aborted = time.time(), 0, [], False

        def one(p: Photo):
            if self._hash_stop.is_set():
                return None
            return p, reader(p, self._hash_stop)

        with ThreadPoolExecutor(2, thread_name_prefix="meta-hash") as ex:
            futs = [ex.submit(one, p) for p in todo]
            for i, fut in enumerate(as_completed(futs), 1):
                if self._hash_stop.is_set():
                    for f2 in futs:
                        f2.cancel()
                    break
                try:
                    r = fut.result()
                except Exception as e:  # noqa: BLE001 — не прочитали: попробуем в следующий раз
                    failures += 1
                    if failures > 20 and failures > i // 2:
                        log.warning("хеши: слишком много ошибок (%s), прерываю", type(e).__name__)
                        aborted = True
                        for f2 in futs:
                            f2.cancel()
                        break
                    continue
                if r and r[1]:
                    p, sha = r
                    batch.append((p.cache_key(), sha))
                    self.hash_bytes_done += p.size
                self.hash_done = i
                if len(batch) >= 100:
                    db.hashes_put_many(batch)
                    batch = []
        db.hashes_put_many(batch)
        stopped = self._hash_stop.is_set()
        self.hash_state = "stopped" if stopped else "error" if aborted else "done"
        log.info("хеши: %d из %d файлов (%.1f ГБ) за %.0fс%s", self.hash_done, self.hash_total,
                 self.hash_bytes_done / 2**30, time.time() - t0, " — остановлено" if stopped else "")
