"""Запуск: python -m app  (настройки — из .env рядом с проектом).
Из консоли контейнера: python -m app 2fa-reset <логин> — отключить двухфакторный вход
(потерян телефон); работающий сервер подхватит изменение сам."""
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
    if len(sys.argv) > 1:
        sys.exit(command(s, sys.argv[1:]))
    import uvicorn
    host = "localhost" if s.bind in ("127.0.0.1", "0.0.0.0") else s.bind
    print(f"Photocloud: http://{host}:{s.port}", flush=True)
    uvicorn.run("app.main:app", host=s.bind, port=s.port, proxy_headers=False,
                server_header=False, date_header=False, access_log=False, log_level="info")


def command(s, args: list[str]) -> int:
    from .auth import UserError, UserStore
    if args[0] == "2fa-reset" and len(args) == 2:
        users = UserStore(s.data_dir / "users.json")
        if not users.totp_on(args[1]):
            print(f"У «{args[1]}» двухфакторный вход не включён (или нет такого пользователя)")
            return 1
        try:
            users.totp_disable(args[1])
        except UserError as e:
            print(e, file=sys.stderr)
            return 1
        from .logs import Audit
        Audit(s.data_dir / "audit.log")("2fa_reset", "консоль", "", args[1])
        print(f"Двухфакторный вход у «{args[1]}» отключён — вход по паролю (или Google)")
        return 0
    print("Команды:\n  python -m app 2fa-reset <логин>   отключить двухфакторный вход", file=sys.stderr)
    return 2


if __name__ == "__main__":
    main()
