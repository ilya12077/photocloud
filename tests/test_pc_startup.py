"""Exercise the real App constructor and marks loader together."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch, Mock

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
            app._load()
            callback = app.q.get_nowait()
            if not os.environ.get("DISPLAY") and os.name != "nt":
                app._show = Mock()
            callback()
            self.assertEqual(app.items, [])


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
