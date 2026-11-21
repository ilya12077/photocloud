"""Удаление не должно читать и хешировать содержимое файлов."""
import ast
from pathlib import Path
import tempfile
import unittest
from test_offline import production_function


class MetadataOnlyDeletionTests(unittest.TestCase):
    def test_matches_size_and_mtime_without_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "photo.jpg"
            path.write_bytes(b"not original")
            item = {"path": "photo.jpg", "size": path.stat().st_size,
                    "mtime": int(path.stat().st_mtime), "sha": "not-real-sha"}
            check_file = production_function("pc/photocloud_pc.pyw", "check_file")
            state, found, _ = check_file(root, item)
            self.assertEqual(state, "ok")
            self.assertEqual(found, path)

    def test_modified_size_and_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "photo.jpg"
            path.write_bytes(b"file")
            fn = production_function("pc/photocloud_pc.pyw", "check_file")
            self.assertEqual(fn(root, {"path": "photo.jpg",
                                       "size": 100, "mtime": int(path.stat().st_mtime)})[0], "changed")
            self.assertEqual(fn(root, {"path": "../photo.jpg", "size": 4, "mtime": 0})[0], "bad")

    def test_check_file_has_no_file_reads(self):
        source = (Path(__file__).resolve().parents[1] / "pc/photocloud_pc.pyw").read_text(encoding="utf-8")
        fn = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "check_file")
        body = ast.get_source_segment(source, fn)
        self.assertNotIn("sha256", body)
        self.assertNotIn(".read(", body)


if __name__ == "__main__":
    unittest.main()
