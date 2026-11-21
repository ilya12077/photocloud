"""Загрузка медиа: ограничения, очередь через Restored, импорт без перезаписи."""
import ast
import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.db import DB
from app.uploads import UploadQueue, destination_folder, media_name, import_path, UPLOAD_PREFIX
from test_offline import production_function

ROOT = Path(__file__).resolve().parents[1]


class UploadQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = DB(self.root / "uploads.db")
        self.queue = UploadQueue(self.db, self.root / "incoming")

    def test_supported_media_and_safe_folders(self):
        for name in ("a.JPG", "video.MP4", "scan.heic", "movie.avi", "movie.mts"):
            self.assertEqual(media_name(name), name)
        for name in ("test.exe", "../foo.jpg", "CON.mp4", "bad:name.mov", "a.txt", "x/abc.jpg"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                media_name(name)
        self.assertEqual(destination_folder("Google Фото/2026/Осень"), "Google Фото/2026/Осень")
        self.assertEqual(import_path("Google Фото/2026", "x.mp4"), "Google Фото/2026/x.mp4")
        for folder in ("../bad", "Restored", ".photocloud/uploads", "A//B", "C:\\Windows"):
            with self.subTest(folder=folder), self.assertRaises(ValueError):
                destination_folder(folder)

    def test_upload_chunks_survive_then_go_to_restored(self):
        content = b"abc" * 10000
        start = self.queue.start("admin", "2026.jpg", "Google Фото/2026/Новый альбом",
                                 len(content), 1700000000)
        ident = start["id"]
        self.assertEqual(self.queue.chunk(ident, "admin", 0, content[:10000]), 10000)
        with self.assertRaises(ValueError):
            self.queue.chunk(ident, "admin", 0, b"changed")
        with self.assertRaises(ValueError):
            self.queue.finish(ident, "admin")
        self.queue.chunk(ident, "admin", 10000, content[10000:])
        row = self.queue.finish(ident, "admin")
        self.assertEqual(row["state"], "queued")
        self.assertEqual(row["sha"], hashlib.sha256(content).hexdigest())
        self.assertEqual(row["folder"], "Google Фото/2026/Новый альбом")
        self.assertEqual(len(self.queue.list(("ready",))), 0)

        class Restore:
            enabled = True
            def write(self, rel, src, mtime, sha):
                assert rel == f"{UPLOAD_PREFIX}/{ident}/2026.jpg"
                assert src.read_bytes() == content
                assert sha == hashlib.sha256(content).hexdigest()
                return rel

        self.assertEqual(self.queue.stage_one(Restore())["state"], "ready")
        self.assertEqual(self.queue.list(("ready",))[0]["id"], ident)
        self.assertTrue(self.queue.completed(ident, "Google Фото/2026/Новый альбом/2026.jpg"))
        self.assertEqual(self.queue.get(ident)["state"], "done")
        self.assertFalse(self.queue.path(ident).exists())

    def test_other_files_upload_while_large_video_is_copied_to_restored(self):
        import threading
        first = self.queue.start("alice", "large.mp4", "", 4, 1700000000)
        self.queue.chunk(first["id"], "alice", 0, b"data")
        self.queue.finish(first["id"], "alice")
        copying = threading.Event()
        release = threading.Event()
        next_uploaded = threading.Event()

        class SlowRestore:
            enabled = True
            def write(self, rel, src, mtime, sha):
                copying.set()
                release.wait(4)
                return rel

        worker = threading.Thread(target=lambda: self.queue.stage_one(SlowRestore()),
                                  daemon=True)
        worker.start()
        self.assertTrue(copying.wait(2), "SMB transfer did not start")
        self.assertEqual(self.queue.get(first["id"])["state"], "staging")

        def next_file():
            other = self.queue.start("alice", "next.jpg", "", 4, 1700000000)
            self.queue.chunk(other["id"], "alice", 0, b"next")
            self.queue.finish(other["id"], "alice")
            next_uploaded.set()
        second = threading.Thread(target=next_file, daemon=True)
        second.start()
        try:
            self.assertTrue(next_uploaded.wait(1.5), "slow SMB transfer blocked new uploads")
        finally:
            release.set()
            worker.join(5)
            second.join(5)
        self.assertEqual(self.queue.get(first["id"])["state"], "ready")

    def test_staging_is_requeued_after_server_restart(self):
        item = self.queue.start("alice", "photo.jpg", "", 4, 1700000000)
        self.queue.chunk(item["id"], "alice", 0, b"file")
        self.queue.finish(item["id"], "alice")
        self.db.run("UPDATE uploads SET state='staging' WHERE id=?", (item["id"],))
        restarted = UploadQueue(self.db, self.root / "incoming")
        self.assertEqual(restarted.get(item["id"])["state"], "queued")

    def test_non_admin_cannot_overwrite_part_of_another_upload(self):
        item = self.queue.start("alice", "test.mp4", "", 4, 1700000000)
        with self.assertRaises(ValueError):
            self.queue.chunk(item["id"], "bob", 0, b"AAAA")
        self.assertEqual(self.queue.path(item["id"]).stat().st_size, 0)
        self.assertFalse(self.queue.cancel(item["id"], "bob"))
        self.assertTrue(self.queue.cancel(item["id"], "alice"))

    def test_oversized_chunk_rejected(self):
        item = self.queue.start("alice", "test.mp4", "", 4*1024*1024 + 1, 1700000000)
        with self.assertRaises(ValueError):
            self.queue.chunk(item["id"], "alice", 0, b"x"*(4*1024*1024+1))
        self.assertEqual(self.queue.path(item["id"]).stat().st_size, 0)

    def test_server_routes_require_admin(self):
        source = (ROOT / "app/main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for name in ("upload_folders", "upload_list", "upload_start", "upload_chunk",
                     "upload_finish", "upload_cancel", "upload_media", "upload_thumb"):
            fn = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
            self.assertIn("require_admin", ast.get_source_segment(source, fn).splitlines()[0] +
                          "\n" + "\n".join(ast.get_source_segment(source, fn).splitlines()[:4]))


class PCUploadImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.safe_rel = production_function("pc/photocloud_pc.pyw", "safe_rel")
        self.restore_path = production_function("pc/photocloud_pc.pyw", "restore_path",
                                                 globals_={"safe_rel": self.safe_rel, "os": os, "re": re})
        self.restore_digest = production_function("pc/photocloud_pc.pyw", "restore_digest",
                                                   globals_={"hashlib": hashlib})
        self.move = production_function("pc/photocloud_pc.pyw", "import_uploaded",
                                        globals_={"safe_rel":self.safe_rel,
                                                  "restore_path":self.restore_path,
                                                  "restore_digest":self.restore_digest,
                                                  "os":os, "re":re, "hashlib":hashlib, "Path":Path})

    def item(self, payload=b"real photo bytes", name="first.jpg"):
        import uuid
        ident = uuid.uuid4().hex
        staged = f"PhotoCloud-Uploads/{ident}/{name}"
        src = self.root / "Restored" / "PhotoCloud-Uploads" / ident / name
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(payload)
        return {"id":ident, "name":name, "staged":staged,
                "sha":hashlib.sha256(payload).hexdigest(), "size":len(payload),
                "mtime":1700000000, "folder":"Google Фото/2026"}

    def test_import_creates_new_folder_without_touching_restored_before_ack(self):
        item = self.item()
        dst = self.move(self.root, item, "Google Фото/2026/Новая папка")
        self.assertEqual(dst, "Google Фото/2026/Новая папка/first.jpg")
        self.assertEqual((self.root / Path(dst)).read_bytes(), b"real photo bytes")
        self.assertTrue((self.root / "Restored" / Path(item["staged"])).exists())
        self.assertEqual(self.move(self.root, item, "Google Фото/2026/Новая папка"), dst)

    def test_collision_does_not_replace_another_file(self):
        existing = self.root / "Album" / "first.jpg"
        existing.parent.mkdir()
        existing.write_bytes(b"important original")
        item = self.item(payload=b"new photo")
        dst = self.move(self.root, item, "Album")
        self.assertEqual(dst, "Album/first (2).jpg")
        self.assertEqual(existing.read_bytes(), b"important original")
        self.assertEqual((self.root / "Album/first (2).jpg").read_bytes(), b"new photo")

    def test_wrong_sha_prevents_copy(self):
        item = self.item()
        item["sha"] = "0" * 64
        with self.assertRaises(ValueError):
            self.move(self.root, item, "Photos")
        self.assertFalse((self.root / "Photos/first.jpg").exists())

    def test_path_traversal_prevents_copy(self):
        item = self.item()
        with self.assertRaises(ValueError):
            self.move(self.root, item, "../outside")


if __name__ == "__main__":
    unittest.main()
