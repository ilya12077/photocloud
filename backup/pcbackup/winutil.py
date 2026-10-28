"""Windows: автозапуск, один экземпляр, открыть папку."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

IS_WIN = sys.platform == "win32"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "PhotocloudBackup"


def _pythonw() -> str:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if w.exists() else exe)


def set_autostart(on: bool, script: Path) -> None:
    """Запуск при входе в Windows — запись в реестре текущего пользователя (без прав админа)."""
    if not IS_WIN:
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{_pythonw()}" "{script}" --tray')
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except FileNotFoundError:
                pass


def wait_pid(pid: int, timeout: float) -> None:
    """Дождаться завершения процесса pid (не дольше timeout секунд)."""
    import time
    if IS_WIN:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)        # SYNCHRONIZE
        if h:
            ctypes.windll.kernel32.WaitForSingleObject(h, int(timeout * 1000))
            ctypes.windll.kernel32.CloseHandle(h)
        return
    t = time.time()
    while time.time() - t < timeout:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.2)


def open_folder(p: str) -> None:
    if IS_WIN:
        os.startfile(p)  # noqa: S606
    else:
        subprocess.Popen(["xdg-open", p])


class SingleInstance:
    """Второй запуск не создаёт второй клиент, а показывает окно первого.
    Первый экземпляр слушает 127.0.0.1 на случайном порту, номер — в файле рядом с настройками."""

    def __init__(self, folder: Path, on_show):
        self.port_file = folder / "instance.port"
        self.on_show = on_show
        self.sock: socket.socket | None = None
        self._mutex = None

    def acquire(self) -> bool:
        if IS_WIN:
            import ctypes
            self._mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\PhotocloudBackup")
            if ctypes.windll.kernel32.GetLastError() == 183:       # ERROR_ALREADY_EXISTS
                self._poke()
                return False
        elif self._poke():
            return False
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(2)
        self.sock = s
        self.port_file.write_text(str(s.getsockname()[1]))
        threading.Thread(target=self._serve, name="instance", daemon=True).start()
        return True

    def _poke(self) -> bool:
        try:
            port = int(self.port_file.read_text())
            with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                c.sendall(b"show")
            return True
        except (OSError, ValueError):
            return False

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                c.settimeout(2)
                try:
                    if c.recv(16) == b"show":
                        self.on_show()
                except OSError:
                    pass
