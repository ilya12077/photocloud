"""Regression tests for offline thumbnail fallback and interrupted SMB indexing.

Pure stdlib: extract the production functions with AST to avoid loading the
full production config, authentication and SMB stack on a CI runner.
"""
import ast
import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def production_function(path, name, owner=None, globals_=None):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
    body = tree.body
    if owner:
        body = next(n for n in body if isinstance(n, ast.ClassDef) and n.name == owner).body
    node = next(n for n in body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    code = compile(ast.Module(body=[ast.ImportFrom(module="__future__",
                           names=[ast.alias(name="annotations")], level=0), node], type_ignores=[]),
                   path, "exec")
    scope = dict(globals_ or {})
    exec(code, scope)
    return scope[name]


class NetworkNameDeleted(OSError):
    ntstatus = 0xC00000C9


class FakeResponse:
    def __init__(self, content, media_type, headers):
        self.body = content
        self.media_type = media_type
        self.headers = headers


class OfflineTests(unittest.TestCase):
    def thumbnail(self, kind, small=None, medium=None, video=False, memory=None):
        async def on_thread(fn, *args):
            return fn(*args)

        source = {"s": small, "t": medium}
        photo = SimpleNamespace(id="12345678", size=200, mtime=123.0, video=video,
                                cache_key=lambda: "file-key")
        cache = memory or {}
        db = SimpleNamespace(vthumb_get=lambda key, fmt: small)
        ns = {
            "Response": FakeResponse,
            "S": SimpleNamespace(image_format="webp"),
            "thumb_cache": SimpleNamespace(get=cache.get),
            "pthumbs": SimpleNamespace(get=lambda key, size: source.get(size)),
            "db": db,
            "_pkind": lambda k: k,
            "run_in_threadpool": on_thread,
            "log": logging.getLogger("test.offline"),
        }
        fn = production_function("app/main.py", "_offline_thumbnail", globals_=ns)
        return asyncio.run(fn(photo, kind))

    def test_medium_uses_saved_small_when_pc_off(self):
        r = self.thumbnail("t", small=b"small")
        self.assertEqual(r.body, b"small")
        self.assertEqual(r.headers["x-photocloud-fallback"], "s")
        self.assertEqual(r.headers["cache-control"], "private, no-store")

    def test_large_prefers_saved_medium(self):
        r = self.thumbnail("m", small=b"small", medium=b"medium")
        self.assertEqual(r.body, b"medium")
        self.assertEqual(r.headers["x-photocloud-fallback"], "t")

    def test_large_uses_memory_cache_too(self):
        r = self.thumbnail("m", memory={("t", "12345678", 123.0, 200): b"ram"})
        self.assertEqual(r.body, b"ram")

    def test_video_uses_small_cached_frame(self):
        r = self.thumbnail("m", small=b"video", video=True)
        self.assertEqual(r.body, b"video")

    def test_no_cached_thumbnail_is_unavailable(self):
        self.assertIsNone(self.thumbnail("m"))

    def test_full_preview_is_not_blurred_by_thumb_fallback(self):
        self.assertIsNone(self.thumbnail("p", small=b"small"))

    def test_network_name_deleted_is_transient(self):
        from app.storage import is_connection_error
        self.assertTrue(is_connection_error(NetworkNameDeleted("PC sleeping")))
        self.assertFalse(is_connection_error(ValueError("invalid data")))

    def test_interrupted_index_keeps_last_snapshot_without_alert(self):
        from app.storage import is_connection_error
        def scan(entries):
            list(entries)
            raise AssertionError("not reached")

        class Lost:
            def walk(self):
                yield ("file.jpg", 100, 1)
                raise NetworkNameDeleted("share disconnected")

        old = object()
        lib = SimpleNamespace(state="ready", progress=0, meta_total=0, meta_done=0,
                              attempted_at=0, retry_at=0, error="", by_id={"old": old},
                              _scan=scan, _publish=lambda *args: self.fail("published partial index"))
        alerts = []
        fn = production_function("app/library.py", "_build", owner="Library",
                                 globals_={"__package__": "app", "time": time,
                                           "log": logging.getLogger("test.offline")})
        fn(lib, Lost(), alerts.append)
        self.assertEqual(lib.state, "ready")
        self.assertIs(lib.by_id["old"], old)
        self.assertEqual(alerts, [])
        self.assertGreater(lib.retry_at, time.time())
        stale = production_function("app/library.py", "stale", owner="Library",
                                   globals_={"time": time})
        lib.busy = lambda: False
        self.assertFalse(stale(lib, 600))
        lib.retry_at = time.time() - 1
        self.assertTrue(stale(lib, 600))


if __name__ == "__main__":
    unittest.main()
