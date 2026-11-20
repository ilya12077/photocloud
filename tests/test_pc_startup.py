"""Exercise the real App constructor and marks loader together."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import hashlib

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows desktop agent is tested on the required Windows runner")
    def test_paired_agent_loads_marks(self):
        import httpx
        import tkinter as tk
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "USERPROFILE": directory}))
            import sys
            stack.enter_context(patch.object(sys, "excepthook"))
            module = runpy.run_path(str(ROOT / "pc/photocloud_pc.pyw"))
            cfg = module["Config"]()
            cfg.root, cfg.server, cfg.client_id = directory, "https://archive.test", "agent"
            app_class = module["App"]
            if not os.environ.get("DISPLAY") and os.name != "nt":
                stack.enter_context(patch.object(tk, "Tk"))
                stack.enter_context(patch.object(app_class, "_build"))
            app = app_class(cfg)
            stack.callback(app.root.destroy)
            stack.callback(app.check_pool.shutdown)
            stack.callback(app.thumb_pool.shutdown)
            for name in list(os.environ):
                if name.lower().endswith("_proxy"):
                    stack.enter_context(patch.dict(os.environ, {name: ""}))
            api = module["Api"](cfg, None)
            api.c.close()
            def marks(request):
                self.assertEqual(request.url.path, "/api/pc/marks")
                self.assertTrue(request.headers["x-pc-mac"])
                return httpx.Response(200, json={"items": []})
            api.c = httpx.Client(base_url=cfg.server, transport=httpx.MockTransport(marks))
            stack.callback(api.close)
            import time
            api.sid, api.skey, api.exp = "session", b"key", time.time() + 900
            app.api = api
            app.bg = Mock()  # startup check is tested independently without a UI thread
            app._load()
            callback = app.q.get_nowait()
            if not os.environ.get("DISPLAY") and os.name != "nt":
                app._show = Mock()
            callback()
            self.assertEqual(app.items, [])
            app.bg.assert_called_once_with(app._check_startup_restores)


class RestoreFilesystemTests(unittest.TestCase):
    def test_verified_replace_retry_and_tamper(self):
        import hashlib
        import sys
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'USERPROFILE': directory, 'XDG_CONFIG_HOME': directory}), patch.object(sys, 'excepthook'):
            module = runpy.run_path(str(ROOT / 'pc/photocloud_pc.pyw'))
            root = Path(directory) / 'archive'
            (root / 'Restored').mkdir(parents=True)
            dst = root / 'photo.jpg'
            dst.write_bytes(b'bad')
            os.utime(dst, (1700000000, 1700000000))
            src = root / 'Restored/photo.jpg'
            src.write_bytes(b'bad')
            item = dict(path='photo.jpg', restored='photo.jpg', size=3, mtime=1700000000,
                        sha_good=hashlib.sha256(b'new').hexdigest(), sha_bad=hashlib.sha256(b'bad').hexdigest())
            with self.assertRaises(ValueError):
                module['apply_restored'](root, item)
            self.assertEqual(dst.read_bytes(), b'bad')
            src.write_bytes(b'new')
            with patch.object(module['os'], 'replace', side_effect=PermissionError('file locked')):
                with self.assertRaises(PermissionError):
                    module['apply_restored'](root, item)
            self.assertEqual(dst.read_bytes(), b'bad')
            self.assertFalse(list(root.glob('.photocloud-restore-*')))
            self.assertTrue(module['apply_restored'](root, item))
            self.assertEqual(dst.read_bytes(), b'new')
            self.assertEqual(int(dst.stat().st_mtime), 1700000000)
            self.assertFalse(module['apply_restored'](root, item))
            self.assertFalse(list(root.glob('.photocloud-restore-*')))
            self.assertTrue(any(p.read_bytes() == b'bad' for p in (module['app_dir']() / 'replaced-originals').glob('*.bak')))


class StartupRestorePromptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        with patch.object(sys, "excepthook"):
            cls.module = runpy.run_path(str(ROOT / "pc/photocloud_pc.pyw"))

    def test_only_server_reported_sha_matching_copies_are_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            (archive / "Restored").mkdir()
            (archive / "Restored" / "good.jpg").write_bytes(b"good")
            (archive / "Restored" / "tampered.jpg").write_bytes(b"evil")
            (archive / "Restored" / "unannounced.jpg").write_bytes(b"good")
            reported = [
                dict(path="good.jpg", restored="good.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
                dict(path="tampered.jpg", restored="tampered.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
                dict(path="missing.jpg", restored="missing.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
            ]
            api = Mock()
            api.call.return_value = SimpleNamespace(status_code=200, json=lambda: {"items": reported})
            app = SimpleNamespace(api=api, cfg=SimpleNamespace(root=str(archive)),
                                  ui=Mock(), _offer_startup_restores=Mock())
            self.module["App"]._check_startup_restores(app)
            api.call.assert_called_once_with("GET", "/api/pc/restored")
            app.ui.assert_called_once()
            app.ui.call_args.args[0]()
            app._offer_startup_restores.assert_called_once_with(api, str(archive), ("good.jpg",))

    def test_local_file_without_server_notice_does_not_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            (archive / "Restored").mkdir()
            (archive / "Restored" / "unannounced.jpg").write_bytes(b"good")
            api = Mock()
            api.call.return_value = SimpleNamespace(status_code=200, json=lambda: {"items": []})
            app = SimpleNamespace(api=api, cfg=SimpleNamespace(root=str(archive)),
                                  ui=Mock(), _offer_startup_restores=Mock())
            self.module["App"]._check_startup_restores(app)
            app.ui.assert_not_called()

    def test_confirmation_is_required(self):
        api = Mock()
        app = SimpleNamespace(api=api, cfg=SimpleNamespace(root="archive"),
                              busy=False, apply_restores=Mock())
        with patch.object(self.module["messagebox"], "askyesno", return_value=False):
            self.module["App"]._offer_startup_restores(app, api, "archive", ("good.jpg",))
        app.apply_restores.assert_not_called()
        with patch.object(self.module["messagebox"], "askyesno", return_value=True):
            self.module["App"]._offer_startup_restores(app, api, "archive", ("good.jpg",))
        app.apply_restores.assert_called_once_with(only_paths={"good.jpg"})
