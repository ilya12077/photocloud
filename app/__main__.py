"""Запуск: python -m app  (настройки — из .env рядом с проектом)."""
import os
import shutil
import sys

from . import config


def main() -> None:
    env = config.PROJECT_ROOT / ".env"
    if not env.exists() and os.environ.get("PHOTOCLOUD_DOCKER") != "1":
        shutil.copy(config.PROJECT_ROOT / ".env.example", env)
        print(f"Создан {env}\nЗаполни его (как минимум LOCAL_ROOT) и запусти снова.")
        sys.exit(1)
    try:
        s = config.load()
    except config.ConfigError as e:
        print(f"Ошибка настройки: {e}", file=sys.stderr)
        sys.exit(2)
    import uvicorn
    host = "localhost" if s.bind in ("127.0.0.1", "0.0.0.0") else s.bind
    print(f"Photocloud: http://{host}:{s.port}", flush=True)
    uvicorn.run("app.main:app", host=s.bind, port=s.port, proxy_headers=False,
                server_header=False, date_header=False, access_log=False, log_level="info")


if __name__ == "__main__":
    main()
