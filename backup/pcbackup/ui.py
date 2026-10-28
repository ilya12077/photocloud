"""Окно (tkinter) и значок в трее (pystray). Движок работает в своём потоке;
сюда — только чтение его состояния раз в 0,7 с и кнопки."""
from __future__ import annotations

import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import httpx
from PIL import Image, ImageDraw

from . import winutil
from .engine import VERSION, Api, AuthError, PcOff, human

COLORS = {"copying": "#2f80ed", "done": "#27ae60", "paused": "#9aa0a6", "pc_off": "#f2994a", "waiting": "#2f80ed",
          "error": "#eb5757", "confirm": "#eb5757", "disk_full": "#eb5757", "setup": "#9aa0a6", "scan": "#2f80ed"}
TITLES = {"copying": "копирует", "done": "всё скопировано", "paused": "пауза", "pc_off": "компьютер выключен",
          "waiting": "ждёт хеши с сервера", "error": "ошибка", "disk_full": "мало места на диске", "confirm": "ждёт подтверждения", "setup": "не настроен",
          "scan": "проверяет папку бэкапа"}
KIND = {"info": "", "warn": "⚠ ", "error": "✖ ", "move": "↪ ", "copy": "", "update": "✎ ", "delete": "🗑 "}


def num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def eta(sec: float) -> str:
    sec = int(sec)
    if sec < 90:
        return "меньше 2 мин"
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return " ".join(x for x in (f"{d} д" if d else "", f"{h} ч" if h else "", f"{m} мин" if not d else "") if x)


def tray_image(color: str) -> Image.Image:
    im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((2, 2, 62, 62), 14, fill=color)
    d.ellipse((17, 19, 47, 49), outline="white", width=6)        # объектив, как у значка сайта
    d.rectangle((40, 10, 52, 18), fill="white")
    return im


class App:
    def __init__(self, cfg, engine, script: Path, start_hidden: bool):
        self.cfg, self.engine, self.script = cfg, engine, script
        self.q: queue.Queue = queue.Queue()
        self._last_state, self._last_paused, self._log_top = None, None, None
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:  # noqa: BLE001
                pass
        self.root = tk.Tk()
        self.root.report_callback_exception = self._tk_error     # под pythonw консоли нет — пишем в журнал
        self.root.title("Photocloud — бэкап")
        self.root.geometry("700x620")
        self.root.minsize(600, 540)
        self.root.protocol("WM_DELETE_WINDOW", self.hide)
        try:
            self._icon_img = tk.PhotoImage(data=self._png(tray_image(COLORS["done"])))
            self.root.iconphoto(True, self._icon_img)
        except tk.TclError:
            pass
        self._build()
        self.tray = None
        self._start_tray()
        configured = bool(cfg.server and cfg.token and cfg.root)
        if not configured:
            self.nb.select(self.tab_set)
        if getattr(cfg, "load_error", ""):
            self.root.after(500, lambda: messagebox.showwarning(
                "Бэкап", f"Настройки не прочитались: {cfg.load_error}\nФайл: {cfg.path}", parent=self.root))
        if start_hidden and configured and cfg.hide_on_autostart and self.tray is not None:
            self.root.withdraw()
        self.root.after(300, self.tick)

    def _tk_error(self, exc, val, tb) -> None:
        import logging
        logging.getLogger("pcbackup").error("ошибка в окне", exc_info=(exc, val, tb))
        messagebox.showerror("Бэкап", f"Ошибка: {exc.__name__}: {val}", parent=self.root)

    @staticmethod
    def _png(im: Image.Image) -> bytes:
        import base64
        import io
        b = io.BytesIO()
        im.resize((32, 32)).save(b, "PNG")
        return base64.b64encode(b.getvalue())

    # ------------------------------------------------------------ окно

    def _build(self) -> None:
        pad = {"padx": 12, "pady": 4}
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        # --- состояние
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="Состояние")
        self.v_state = tk.StringVar()
        self.v_detail = tk.StringVar()
        self.v_counts = tk.StringVar()
        self.v_current = tk.StringVar()
        self.v_speed = tk.StringVar()
        ttk.Label(t, textvariable=self.v_state, font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=12, pady=(12, 0))
        ttk.Label(t, textvariable=self.v_detail, foreground="#666", wraplength=640).pack(anchor="w", **pad)
        self.bar = ttk.Progressbar(t, maximum=1000)
        self.bar.pack(fill="x", padx=12, pady=(8, 4))
        ttk.Label(t, textvariable=self.v_counts).pack(anchor="w", **pad)
        ttk.Label(t, textvariable=self.v_current, foreground="#666", wraplength=640).pack(anchor="w", **pad)
        ttk.Label(t, textvariable=self.v_speed).pack(anchor="w", **pad)

        self.confirm = ttk.Frame(t)
        ttk.Label(self.confirm, text="Файлы уберутся в папку «Удалённые» внутри бэкапа — ничего не стирается.",
                  wraplength=420).pack(side="left", padx=(0, 8))
        ttk.Button(self.confirm, text="Подтвердить", command=self.engine.confirm_delete).pack(side="left")

        row = ttk.Frame(t)
        row.pack(fill="x", padx=12, pady=(12, 4), side="bottom")
        self.b_pause = ttk.Button(row, text="Пауза", command=self.toggle_pause, width=14)
        self.b_pause.pack(side="left")
        ttk.Button(row, text="Проверить сейчас", command=self.engine.sync_now).pack(side="left", padx=6)
        ttk.Button(row, text="Разбудить ПК", command=self.engine.wake_now).pack(side="left")
        ttk.Button(row, text="Открыть папку", command=self.open_root).pack(side="right")

        lim = ttk.Frame(t)
        lim.pack(fill="x", padx=12, pady=4, side="bottom")
        ttk.Label(lim, text="Лимит скорости, Мбит/с (0 — без ограничения):").pack(side="left")
        self.v_limit = tk.StringVar(value=self._fmt_limit(self.cfg.limit_mbps))
        sp = ttk.Spinbox(lim, from_=0, to=1000, increment=1, width=7, textvariable=self.v_limit,
                         command=self.apply_limit)
        sp.pack(side="left", padx=6)
        sp.bind("<Return>", lambda _e: self.apply_limit())
        sp.bind("<FocusOut>", lambda _e: self.apply_limit())

        # --- журнал
        lg = ttk.Frame(self.nb)
        self.nb.add(lg, text="Журнал")
        self.logbox = tk.Text(lg, wrap="none", height=10, state="disabled", font=("Consolas", 9))
        ys = ttk.Scrollbar(lg, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=ys.set)
        ys.pack(side="right", fill="y")
        self.logbox.pack(fill="both", expand=True)

        # --- настройки
        s = ttk.Frame(self.nb)
        self.tab_set = s
        self.nb.add(s, text="Настройки")
        s.columnconfigure(1, weight=1)
        self.v_server = tk.StringVar(value=self.cfg.server)
        self.v_token = tk.StringVar()
        self.v_root = tk.StringVar(value=self.cfg.root)
        self.v_auto = tk.BooleanVar(value=self.cfg.autostart)
        self.v_hide = tk.BooleanVar(value=self.cfg.hide_on_autostart)
        self.v_wake = tk.BooleanVar(value=self.cfg.wake_on_start)
        self.v_free = tk.StringVar(value=self._fmt_limit(self.cfg.min_free_gb))
        self.v_test = tk.StringVar()
        r = 0
        ttk.Label(s, text="Адрес сайта:").grid(row=r, column=0, sticky="w", padx=12, pady=(14, 4))
        ttk.Entry(s, textvariable=self.v_server).grid(row=r, column=1, columnspan=2, sticky="ew", padx=12, pady=(14, 4))
        r += 1
        ttk.Label(s, text="Токен:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        ttk.Entry(s, textvariable=self.v_token, show="•").grid(row=r, column=1, columnspan=2, sticky="ew", padx=12, pady=4)
        r += 1
        self.l_token = ttk.Label(s, foreground="#666", wraplength=420)
        self.l_token.grid(row=r, column=1, columnspan=2, sticky="w", padx=12)
        r += 1
        ttk.Label(s, text="Папка бэкапа:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        ttk.Entry(s, textvariable=self.v_root).grid(row=r, column=1, sticky="ew", padx=(12, 4), pady=4)
        ttk.Button(s, text="Выбрать…", command=self.pick_root).grid(row=r, column=2, padx=(0, 12), pady=4)
        r += 1
        ttk.Label(s, text="Оставлять свободным:").grid(row=r, column=0, sticky="w", padx=12, pady=4)
        fr = ttk.Frame(s)
        fr.grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=4)
        ttk.Spinbox(fr, from_=0, to=10000, increment=1, width=7, textvariable=self.v_free).pack(side="left")
        ttk.Label(fr, text="ГБ на диске (иначе новые файлы не качаются)", foreground="#666").pack(
            side="left", padx=6)
        r += 1
        ttk.Checkbutton(s, text="Запускать при входе в Windows", variable=self.v_auto,
                        command=self._sync_hide).grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=(10, 2))
        r += 1
        self.c_hide = ttk.Checkbutton(s, text="Не показывать окно при автозапуске (только значок в трее)",
                                      variable=self.v_hide)
        self.c_hide.grid(row=r, column=1, columnspan=2, sticky="w", padx=(32, 12), pady=2)
        self._sync_hide()
        r += 1
        ttk.Checkbutton(s, text="Будить домашний компьютер при запуске", variable=self.v_wake).grid(
            row=r, column=1, columnspan=2, sticky="w", padx=12, pady=2)
        r += 1
        b = ttk.Frame(s)
        b.grid(row=r, column=1, columnspan=2, sticky="w", padx=12, pady=12)
        ttk.Button(b, text="Сохранить", command=self.save_settings).pack(side="left")
        ttk.Button(b, text="Проверить связь", command=self.test_conn).pack(side="left", padx=6)
        r += 1
        ttk.Label(s, textvariable=self.v_test, wraplength=440).grid(row=r, column=1, columnspan=2, sticky="w", padx=12)
        r += 1
        ttk.Label(s, text="Закрытие окна оставляет программу в трее (значок у часов; в Windows 11 он может "
                          "быть спрятан под стрелкой ^ — его можно перетащить на панель). Выход — правой кнопкой "
                          "по значку → «Выход».", foreground="#666", wraplength=640).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 0))
        r += 1
        ttk.Label(s, text=f"Настройки: {self.cfg.path}", foreground="#999", wraplength=640).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 0))
        r += 1
        ttk.Label(s, text=f"photocloud-backup {VERSION}", foreground="#999").grid(
            row=r, column=0, columnspan=3, sticky="sw", padx=12, pady=12)
        s.rowconfigure(r, weight=1)
        self._token_hint()

    def _sync_hide(self) -> None:
        self.c_hide.state(["!disabled"] if self.v_auto.get() else ["disabled"])

    def _token_hint(self) -> None:
        self.l_token.configure(text="Токен сохранён (зашифрован). Оставьте поле пустым, чтобы не менять."
                               if self.cfg.token else "Токен выдаёт администратор: Админка → Бэкап → Новый клиент.")

    @staticmethod
    def _fmt_limit(v) -> str:
        v = float(v or 0)
        return str(int(v)) if v == int(v) else str(v)

    def apply_limit(self) -> None:
        try:
            v = float(self.v_limit.get().replace(",", "."))
        except ValueError:
            v = -1
        if not 0 <= v <= 10000:
            self.v_limit.set(self._fmt_limit(self.cfg.limit_mbps))
            return
        if v != self.cfg.limit_mbps:
            self.cfg.limit_mbps = v
            self.cfg.save()

    def pick_root(self) -> None:
        d = filedialog.askdirectory(title="Папка для бэкапа", initialdir=self.v_root.get() or str(Path.home()))
        if d:
            self.v_root.set(str(Path(d)))

    def _server(self) -> str | None:
        srv = self.v_server.get().strip().rstrip("/")
        if srv and "://" not in srv:
            srv = "https://" + srv
        local = srv.startswith(("http://localhost", "http://127.0.0.1"))
        if not (srv.startswith("https://") or local):
            messagebox.showerror("Бэкап", "Адрес сайта должен начинаться с https://", parent=self.root)
            return None
        return srv

    def save_settings(self) -> None:
        srv = self._server()
        if srv is None:
            return
        root = self.v_root.get().strip()
        if not root:
            messagebox.showerror("Бэкап", "Выберите папку для бэкапа", parent=self.root)
            return
        try:
            Path(root).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Бэкап", f"Не создать папку: {e}", parent=self.root)
            return
        try:
            free_gb = float(self.v_free.get().replace(",", "."))
            if not 0 <= free_gb <= 100000:
                raise ValueError
        except ValueError:
            messagebox.showerror("Бэкап", "Свободное место: число ГБ, 0 — без ограничения", parent=self.root)
            return
        tok = self.v_token.get().strip()
        if not tok and not self.cfg.token:
            messagebox.showerror("Бэкап", "Вставьте токен", parent=self.root)
            return
        moved = self.cfg.root and Path(root) != Path(self.cfg.root)
        if moved and not messagebox.askyesno(
                "Бэкап", "Сменить папку бэкапа? Старая папка останется как есть; "
                         "в новую файлы будут скопированы заново (если там уже лежит бэкап — он будет проверен).",
                parent=self.root):
            return
        self.cfg.server, self.cfg.root = srv, root
        if tok:
            self.cfg.token = tok
        self.cfg.autostart, self.cfg.wake_on_start = self.v_auto.get(), self.v_wake.get()
        self.cfg.hide_on_autostart = self.v_hide.get()
        self.cfg.min_free_gb = free_gb
        try:
            self.cfg.save()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Бэкап", f"Не удалось сохранить настройки в {self.cfg.path}:\n{type(e).__name__}: {e}",
                                 parent=self.root)
            return
        try:
            winutil.set_autostart(self.cfg.autostart, self.script)
        except OSError as e:
            messagebox.showwarning("Бэкап", f"Автозапуск не настроен: {e}", parent=self.root)
        self.v_token.set("")
        self._token_hint()
        self.v_server.set(srv)
        self.engine.reconfigure()
        self.v_test.set("Сохранено.")
        self.test_conn()

    def test_conn(self) -> None:
        srv = self._server()
        if srv is None:
            return
        tok = self.v_token.get().strip() or self.cfg.token
        self.v_test.set("Проверяю…")

        def run():
            api = Api(srv, tok)
            try:
                st = api.status()
                pc = {"up": "включён", "down": "выключен", "waking": "просыпается"}.get(st.get("pc"), st.get("pc"))
                msg = f"✔ Связь есть: «{st.get('name')}», сервер {st.get('server')}, компьютер {pc}."
            except AuthError as e:
                msg = f"✖ {e}"
            except PcOff:
                msg = "✔ Сервер отвечает, компьютер выключен."
            except httpx.HTTPError as e:
                msg = f"✖ Нет связи с сервером: {type(e).__name__}"
            finally:
                api.close()
            self.q.put(lambda: self.v_test.set(msg))

        threading.Thread(target=run, daemon=True).start()

    def open_root(self) -> None:
        if self.cfg.root:
            winutil.open_folder(self.cfg.root)

    def toggle_pause(self) -> None:
        if self.cfg.paused:
            self.engine.resume()
        else:
            self.engine.pause()
        self.tick(once=True)

    def show(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide(self) -> None:
        if self.tray is None:              # значка в трее нет — сворачиваем, чтобы копирование не остановилось
            self.root.iconify()
        else:
            self.root.withdraw()

    def quit(self) -> None:
        self.engine.shutdown()
        if self.tray:
            self.tray.stop()
        self.engine.join(5)
        self.root.destroy()

    # ------------------------------------------------------------ трей

    def _start_tray(self) -> None:
        try:
            import pystray
        except ImportError:
            import logging
            logging.getLogger("pcbackup").error("нет библиотеки pystray — значка в трее не будет")
            return
        call = lambda fn: (lambda *_a: self.q.put(fn))        # noqa: E731 — из потока трея в поток окна
        self._tray_status = "Photocloud — бэкап"
        menu = pystray.Menu(
            pystray.MenuItem(lambda _i: self._tray_status, None, enabled=False),      # состояние
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Открыть окно", call(self.show), default=True),        # и по щелчку по значку
            pystray.MenuItem(lambda _i: "Продолжить копирование" if self.cfg.paused else "Пауза",
                             call(self.toggle_pause)),
            pystray.MenuItem("Проверить сейчас", call(self.engine.sync_now)),
            pystray.MenuItem("Разбудить домашний ПК", call(self.engine.wake_now)),
            pystray.MenuItem("Открыть папку бэкапа", call(self.open_root)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", call(self.quit)),
        )
        self._tray_imgs = {c: tray_image(c) for c in set(COLORS.values())}
        self.tray = pystray.Icon("photocloud-backup", self._tray_imgs[COLORS["setup"]], "Photocloud — бэкап", menu)

        def run():
            try:
                self.tray.run()
            except Exception:  # noqa: BLE001
                import logging
                logging.getLogger("pcbackup").exception("значок в трее не запустился")
                self.q.put(self._tray_failed)

        threading.Thread(target=run, name="tray", daemon=True).start()

    def _tray_failed(self) -> None:
        self.tray = None
        self.show()

    def _tray_text(self, s: dict, state: str) -> str:
        t = TITLES.get(state, state)
        if state == "copying":
            if s["bytes"]:
                t += f" · {100 * s['have_bytes'] // s['bytes']}%"
            if s["speed"]:
                t += f" · {human(s['speed'])}/с"
        elif state in ("done", "waiting") and s["files"]:
            t += f" · {num(s['have_files'])} из {num(s['files'])}"
        return "Бэкап: " + t

    # ------------------------------------------------------------ обновление

    def tick(self, once: bool = False) -> None:
        while True:
            try:
                self.q.get_nowait()()
            except queue.Empty:
                break
        s = self.engine.snapshot()
        state = "paused" if s["paused"] else s["state"]
        self.v_state.set(s["text"] if not s["paused"] else "Пауза")
        self.v_detail.set(s["detail"] if not s["paused"] else "Копирование остановлено, интернет не используется")
        if s["bytes"]:
            part = s["cur_done"] if state == "copying" and s["current"] else 0     # большой файл — видно, что идёт
            self.bar["value"] = 1000 * min(s["bytes"], s["have_bytes"] + part) / s["bytes"]
            self.v_counts.set(f"Скопировано: {num(s['have_files'])} из {num(s['files'])} файлов · "
                              f"{human(s['have_bytes'])} из {human(s['bytes'])}")
        else:
            self.bar["value"] = 0
            self.v_counts.set("")
        if s["current"] and state == "copying":
            pct = f" — {100 * s['cur_done'] // max(1, s['cur_size'])}% из {human(s['cur_size'])}" if s["cur_size"] else ""
            self.v_current.set(f"Файл: {s['current']}{pct}")
        else:
            self.v_current.set("")
        if state == "copying" and s["speed"] > 0:
            self.v_speed.set(f"Скорость: {human(s['speed'])}/с · осталось ≈ {eta(s['left_bytes'] / s['speed'])}"
                             + (f" · ошибок: {s['errors']}" if s["errors"] else ""))
        elif s["left_files"] and state != "done":
            self.v_speed.set(f"Осталось: {num(s['left_files'])} файлов, {human(s['left_bytes'])}"
                             + (f" · ошибок: {s['errors']}" if s["errors"] else ""))
        else:
            self.v_speed.set(f"Ошибок: {s['errors']}" if s["errors"] else "")
        if state == "confirm":
            self.confirm.pack(fill="x", padx=12, pady=8)
        else:
            self.confirm.pack_forget()
        self.b_pause.configure(text="Продолжить" if s["paused"] else "Пауза")
        top = s["log"][0] if s["log"] else None
        if top != self._log_top:
            self._log_top = top
            self.logbox.configure(state="normal")
            self.logbox.delete("1.0", "end")
            for ts, kind, text, path in s["log"]:
                self.logbox.insert("end", f"{time.strftime('%d.%m %H:%M:%S', time.localtime(ts))}  "
                                          f"{KIND.get(kind, '')}{text}{'  ' + path if path else ''}\n")
            self.logbox.configure(state="disabled")
        if self.tray:
            text = self._tray_text(s, state)
            try:
                if state != self._last_state or s["paused"] != self._last_paused:
                    self.tray.icon = self._tray_imgs[COLORS.get(state, COLORS["setup"])]
                if text != self._tray_status:
                    self._tray_status = text
                    self.tray.title = text[:120]           # подсказка при наведении (Windows: до 127 символов)
                    self.tray.update_menu()
                elif s["paused"] != self._last_paused:
                    self.tray.update_menu()
            except Exception:  # noqa: BLE001 — значок не обновился: окно всё равно работает
                pass
        self._last_state, self._last_paused = state, s["paused"]
        if not once:
            self.root.after(700, self.tick)

    def run(self) -> None:
        self.root.mainloop()
