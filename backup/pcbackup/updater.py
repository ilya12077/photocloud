"""Обновление клиента с GitHub (репозиторий публичный).

Версия — файл backup/VERSION в выбранной ветке. Обновление: архив ветки с GitHub,
из него берутся только файлы папки backup/ и раскладываются поверх этой папки
(сначала всё распаковывается во временную папку, потом файлы подменяются).
Если поменялся requirements.txt — доустанавливаются зависимости тем же Python.
Затем программа перезапускается."""
from __future__ import annotations

import io
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import httpx

REPO = "ilya12077/photocloud"
HERE = Path(__file__).resolve().parent.parent          # папка backup/
log = logging.getLogger("pcbackup.update")
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def local_version() -> str:
    try:
        return (HERE / "VERSION").read_text(encoding="utf-8").strip() or "0"
    except OSError:
        return "0"


def parse(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def default_branch() -> str:
    """Обновления — из основной ветки репозитория (в настройках можно указать другую)."""
    return "master"


def _client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(60, connect=15), follow_redirects=True,
                        headers={"user-agent": f"photocloud-backup/{local_version()}"})


def head_sha(branch: str) -> str | None:
    """Последний коммит ветки. Через API GitHub — без пятиминутного кэша raw.githubusercontent.com,
    из-за которого клиент после пуша ещё какое-то время видел старую версию."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch):
        return None
    try:
        with _client() as c:
            r = c.get(f"https://api.github.com/repos/{REPO}/commits/{branch}",
                      headers={"accept": "application/vnd.github.sha"})
    except httpx.HTTPError:
        return None
    sha = r.text.strip() if r.status_code == 200 else ""
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def _ref(branch: str) -> str:
    """Коммит, если API ответил (файлы коммита неизменны — кэш не мешает); иначе имя ветки."""
    return head_sha(branch) or branch


def remote_version(branch: str, ref: str | None = None) -> str | None:
    """Версия клиента в ветке на GitHub; None — в этой ветке клиента нет (или GitHub недоступен)."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch):
        return None
    ref = ref or _ref(branch)
    url = f"https://raw.githubusercontent.com/{REPO}/{ref}/backup/VERSION"
    if ref == branch:
        url += f"?t={int(time.time())}"                   # без API: хотя бы мимо кэша
    with _client() as c:
        r = c.get(url, headers={"cache-control": "no-cache"})
    if r.status_code != 200:
        return None
    v = r.text.strip()
    return v if re.fullmatch(r"[0-9][0-9A-Za-z.\-+]{0,30}", v) else None


def newer(remote: str | None) -> bool:
    return bool(remote) and parse(remote) > parse(local_version())


def apply(branch: str) -> str:
    """Скачать последний коммит ветки и разложить backup/ поверх этой папки. Возвращает новую версию."""
    ref = _ref(branch)
    expect = remote_version(branch, ref)
    url = (f"https://codeload.github.com/{REPO}/zip/{ref}" if ref != branch
           else f"https://codeload.github.com/{REPO}/zip/refs/heads/{branch}")
    with _client() as c:
        r = c.get(url)
        r.raise_for_status()
        data = r.content
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    if not names:
        raise ValueError("пустой архив")
    top = names[0].split("/", 1)[0] + "/backup/"
    tmp = HERE / ".update"
    shutil.rmtree(tmp, ignore_errors=True)
    files: list[str] = []
    for n in names:
        if not n.startswith(top) or n.endswith("/"):
            continue
        rel = n[len(top):]
        parts = rel.split("/")
        if any(p in ("", ".", "..") or ":" in p or "\\" in p for p in parts) or rel.startswith("backup.log"):
            continue
        dst = tmp.joinpath(*parts)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(zf.read(n))
        files.append(rel)
    if "photocloud_backup.pyw" not in files or "VERSION" not in files:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("в архиве нет клиента бэкапа")
    got = (tmp / "VERSION").read_text(encoding="utf-8").strip()
    if expect and got != expect:                       # архив из кэша старее, чем версия — не ставим
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"GitHub отдал версию {got} вместо {expect} — попробуйте через пару минут")
    old_req = (HERE / "requirements.txt").read_bytes() if (HERE / "requirements.txt").exists() else b""
    for rel in files:
        dst = HERE.joinpath(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp.joinpath(*rel.split("/")), dst)
    shutil.rmtree(tmp, ignore_errors=True)
    new = local_version()
    log.info("обновлено до %s из ветки %s: %d файлов", new, branch, len(files))
    if (HERE / "requirements.txt").read_bytes() != old_req:
        py = Path(sys.executable)
        py = py.with_name("python.exe") if py.name.lower() == "pythonw.exe" else py   # pip — без окна, но с выводом
        res = subprocess.run([str(py), "-m", "pip", "install", "-r", str(HERE / "requirements.txt")],
                             capture_output=True, text=True, timeout=900, creationflags=_NO_WINDOW)
        log.info("pip install: %s\n%s", res.returncode, (res.stdout + res.stderr)[-2000:])
    return new


def restart(hidden: bool) -> None:
    """Запустить новую копию программы; она дождётся, пока эта завершится."""
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    if sys.platform == "win32" and w.exists():
        exe = w
    args = [str(exe), str(HERE / "photocloud_backup.pyw"), "--wait-pid", str(os.getpid())]
    if hidden:
        args.append("--tray")
    flags = (0x00000008 | 0x00000200) if sys.platform == "win32" else 0   # DETACHED_PROCESS | NEW_PROCESS_GROUP
    subprocess.Popen(args, close_fds=True, creationflags=flags)
