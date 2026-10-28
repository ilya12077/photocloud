"""Настройки клиента: %APPDATA%\\photocloud-backup\\config.json.
Токен хранится зашифрованным средствами Windows (DPAPI): расшифровать его может
только эта учётная запись на этом компьютере."""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
import threading
from pathlib import Path

IS_WIN = sys.platform == "win32"
log = logging.getLogger("pcbackup.config")


def app_dir() -> Path:
    base = os.environ.get("APPDATA") if IS_WIN else os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    d = Path(base or Path.home()) / "photocloud-backup"
    d.mkdir(parents=True, exist_ok=True)
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
        self.update_branch = ""           # пусто — ветка git-клона (.git/HEAD) или master
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
