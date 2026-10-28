"""Photocloud — бэкап: копирует оригиналы фото и видео с сервера photocloud на этот компьютер.

Запуск: двойной щелчок по этому файлу (откроется через pythonw, без консоли).
Дальше живёт значком в трее; автозапуск при входе в Windows включается в настройках.
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pcbackup import winutil  # noqa: E402
from pcbackup.config import Config, app_dir  # noqa: E402


def main() -> None:
    d = app_dir()
    h = logging.handlers.RotatingFileHandler(d / "backup.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[h], format="%(asctime)s %(levelname)s %(message)s")
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    log = logging.getLogger("pcbackup")

    app = None
    inst = winutil.SingleInstance(d, lambda: app and app.q.put(app.show))
    if not inst.acquire():
        return                                   # уже запущен — показали его окно
    try:
        from pcbackup.engine import Engine
        from pcbackup.ui import App
    except ImportError as e:                     # нет зависимостей — подскажем, что поставить
        import tkinter.messagebox as mb
        mb.showerror("Photocloud — бэкап", f"Не хватает библиотеки: {e.name}\n\n"
                     f"Выполните в командной строке:\npy -m pip install -r \"{HERE / 'requirements.txt'}\"")
        return
    cfg = Config()
    if cfg.autostart and cfg.server:
        try:
            winutil.set_autostart(True, Path(__file__).resolve())   # путь к скрипту мог поменяться
        except OSError:
            pass
    engine = Engine(cfg)
    engine.start()
    log.info("запуск, папка: %s", cfg.root or "—")
    app = App(cfg, engine, Path(__file__).resolve(), start_hidden="--tray" in sys.argv)
    try:
        app.run()
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
