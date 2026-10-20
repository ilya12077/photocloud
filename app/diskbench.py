"""Диагностика: куда уходит время при открытии файлов.

    python -m app.diskbench "D:\\фото"

Берёт случайные файлы из папки и меряет по отдельности: stat, открытие/закрытие,
чтение первых 256 КБ, Path.resolve(). Каждый файл — два раза: первый проход
«холодный», второй — когда файл уже в кэше Windows. Если и во втором проходе
открытие ~15+ мс, тормозит не диск, а программа, которая проверяет каждый
открываемый файл (антивирус и т.п.)."""
from __future__ import annotations

import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

EXT = {".jpg", ".jpeg", ".png", ".heic", ".mp4", ".mov", ".gif", ".webp"}


def ms(fn) -> float:
    t = time.perf_counter()
    fn()
    return (time.perf_counter() - t) * 1000


def collect(root: Path, limit: int = 5000) -> list[Path]:
    out = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in EXT:
                out.append(Path(dp) / fn)
                if len(out) >= limit:
                    return out
    return out


def row(name: str, vals: list[float]) -> str:
    vals = sorted(vals)
    p90 = vals[min(len(vals) - 1, int(len(vals) * 0.9))]
    return f"  {name:26} медиана {statistics.median(vals):7.2f} мс   p90 {p90:7.2f} мс"


def antivirus() -> str:
    if sys.platform != "win32":
        return "—"
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName;"
             "'Defender realtime: ' + (Get-MpComputerStatus).RealTimeProtectionEnabled"],
            capture_output=True, text=True, timeout=20)
        return " / ".join(x.strip() for x in r.stdout.splitlines() if x.strip()) or "не определить"
    except Exception as e:  # noqa: BLE001
        return f"не определить ({type(e).__name__})"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit('использование: python -m app.diskbench "путь к папке с фото"')
    root = Path(sys.argv[1])
    files = collect(root)
    if not files:
        sys.exit("файлов не найдено")
    sample = random.sample(files, min(200, len(files)))
    print(f"Папка: {root}  ·  взято файлов: {len(sample)}")
    print(f"Антивирус: {antivirus()}\n")
    for title in ("Проход 1 (холодный)", "Проход 2 (файлы уже в кэше)"):
        st, oc, rd, rs = [], [], [], []
        for p in sample:
            st.append(ms(lambda: os.stat(p)))
            oc.append(ms(lambda: open(p, "rb").close()))

            def read():
                with open(p, "rb") as f:
                    f.read(256 * 1024)
            rd.append(ms(read))
            rs.append(ms(lambda: p.resolve()))
        print(title)
        print(row("stat", st))
        print(row("открыть + закрыть", oc))
        print(row("открыть + прочитать 256 КБ", rd))
        print(row("Path.resolve()", rs))
        print()
    print("Как читать: если «открыть» во 2-м проходе тоже 10+ мс — время съедает проверка файлов\n"
          "(антивирус, защита папок), а не диск. На NVMe без проверки это доли миллисекунды.")


if __name__ == "__main__":
    main()
