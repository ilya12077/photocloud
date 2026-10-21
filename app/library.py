"""Индекс медиатеки в памяти.

Фаза 1 — обход папок (только имя/размер/mtime), индекс сразу доступен с датами
из кэша или по mtime. Фаза 2 — в фоне читаем дату съёмки (EXIF / mp4 mvhd) у тех
файлов, которых нет в кэше, и публикуем новую версию. Кэш дат — маленький JSON
в DATA_DIR, ключ (путь, размер, mtime), так что повторно файлы не читаются."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from . import meta
from .storage import PLAYABLE_EXT, VIDEO_EXT

log = logging.getLogger("photocloud.library")

F_VIDEO = 1
F_TAKEN = 2   # дата из EXIF/метаданных
F_NAME = 4    # дата из имени файла
F_NOPLAY = 8  # видео, которое браузер не воспроизведёт
F_LIVE = 16   # «живое фото»: у снимка есть короткий ролик-пара

LIVE_IMG = {".jpg", ".jpeg", ".heic", ".heif"}
LIVE_VID = {".mp4", ".mov"}
LIVE_MAX = 40 * 1024 * 1024     # ролик живого фото — пара секунд, обычно 2–10 МБ


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

    @property
    def date(self) -> float:
        # приоритет: метаданные -> имя файла -> дата изменения
        return self.taken or self.named or self.mtime

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
        return f

    @property
    def video(self) -> bool:
        return self.ext in VIDEO_EXT

    def cache_key(self) -> str:
        return f"{self.rel}\0{self.size}\0{int(self.mtime)}"


class MetaCache:
    """Даты съёмки: в памяти — словарь для быстрых проверок, на диске — таблица SQLite.
    Пишутся только новые записи (пачками), а не весь кэш целиком."""

    def __init__(self, db, legacy_json: Path):
        self.db = db
        db.migrate_dates_json(legacy_json)
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
    def __init__(self, data_dir: Path, tz, meta_threads: int = 8, db=None):
        self.tz = tz
        self.meta_threads = meta_threads
        self.cache = MetaCache(db, data_dir / "dates-cache.json")
        self.state = "empty"          # empty | building | ready | error
        self.error = ""
        self.built_at = 0.0
        self.attempted_at = 0.0
        self.progress = 0
        self.meta_total = 0           # сколько файлов надо дочитать
        self.meta_done = 0
        self.version = ""
        self.by_id: dict[str, Photo] = {}
        self.payload = b"{}"
        self.payload_gz = gzip.compress(b"{}")
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
        # колоночный формат: так gzip жмёт заметно лучше, чем массив строк
        dates = [int(p.date) for p in photos]
        cols = {
            "id": "".join(p.id for p in photos),
            "f": [p.folder for p in photos],
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
        gz = gzip.compress(payload, compresslevel=6)
        # атомарная подмена: читатели видят либо старую, либо новую версию целиком
        self.by_id = {p.id: p for p in everything}
        self.payload, self.payload_gz, self.version = payload, gz, version

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
                c = self.cache.get(p.cache_key())
                if c:
                    p.taken = c
                photos.append(p)
                self.progress = len(photos)
            self._publish(photos, folder_list)
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
