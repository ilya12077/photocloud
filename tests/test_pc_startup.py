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
