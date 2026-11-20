"""Безопасные ограниченные повторы отправки в корзину Windows."""
import tempfile
import unittest
from pathlib import Path
from test_offline import production_function


class RecycleFallbackTests(unittest.TestCase):
    def test_isolate_one_bad_file_without_blame_for_group(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            files = [root / name for name in ("a.jpg", "bad.jpg", "c.jpg", "d.jpg")]
            for p in files:
                p.write_bytes(b"x")
            calls = {p: 0 for p in files}
            def recycle(paths):
                for p in paths:
                    calls[p] += 1
                if len(paths) > 1 and root / "bad.jpg" in paths:
                    return "код 124"
                for p in paths:
                    if p.name != "bad.jpg":
                        p.unlink()
                return "код 124" if root / "bad.jpg" in paths else ""
            fn = production_function("pc/photocloud_pc.pyw", "recycle_with_fallback")
            done, failed = fn(
                [({"path": p.name}, p) for p in files], recycle,
                lambda it: ("ok", root / it["path"], ""), lambda: False)
            self.assertEqual({item["path"] for item in done}, {"a.jpg", "c.jpg", "d.jpg"})
            self.assertEqual(failed, [("bad.jpg", "код 124")])
            self.assertLessEqual(calls[root / "bad.jpg"], 3)
            self.assertEqual({p.name for p in root.iterdir()}, {"bad.jpg"})

    def test_strict_maximum_of_three_attempts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = [root / f"{i}.jpg" for i in range(6)]
            for p in paths:
                p.write_bytes(b"x")
            calls = {p: 0 for p in paths}
            def recycle(batch):
                for p in batch:
                    calls[p] += 1
                return "код 124"
            fn = production_function("pc/photocloud_pc.pyw", "recycle_with_fallback")
            done, failed = fn(
                [({"path": p.name}, p) for p in paths], recycle,
                lambda it: ("ok", root / it["path"], ""), lambda: False)
            self.assertFalse(done)
            self.assertEqual(len(failed), len(paths))
            self.assertEqual(set(calls.values()), {3})

    def test_windows_cancel_disables_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.jpg"
            path.write_bytes(b"x")
            calls = []
            fn = production_function("pc/photocloud_pc.pyw", "recycle_with_fallback")
            gone, failed = fn([({"path": path.name}, path)], lambda ps: calls.append(ps) or "отменено",
                              lambda _: ("ok", path, ""), lambda: False)
            self.assertFalse(gone)
            self.assertEqual(len(calls), 1)
            self.assertEqual(failed, [(path.name, "отменено")])

    def test_revalidate_prevents_deleting_modified_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "changed.jpg"
            path.write_bytes(b"x")
            calls = []
            fn = production_function("pc/photocloud_pc.pyw", "recycle_with_fallback")
            gone, failed = fn([({"path": path.name}, path)], lambda ps: calls.append(ps) or "код 124",
                              lambda _: ("changed", path, "хеш другой"), lambda: False)
            self.assertFalse(gone)
            self.assertEqual(len(calls), 1)
            self.assertEqual(failed, [(path.name, "хеш другой")])
