"""Проверки прямой записи на ПК без сохранения медиа на сервере."""
import ast
import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.uploads import UploadQueue, destination_folder, media_name, import_path, UPLOAD_PREFIX, duplicate_status
from app.storage import LocalStorage
from test_offline import production_function

ROOT = Path(__file__).resolve().parents[1]


class DirectUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pc = self.root / "pc"  # имитирует файл. систему именно ПК
        self.pc.mkdir()
        self.server = self.root / "server"
        self.server.mkdir()
        self.writer = SimpleNamespace(local=True, enabled=True, storage=SimpleNamespace(root=self.pc))
        self.queue = UploadQueue(self.writer)

    def upload(self, name="photo.jpg", content=b"photo-bytes", folder="Google Фото/2026"):
        started = self.queue.start("admin", name, folder, len(content), 1700000000)
        ident = started["id"]
        split = max(1,len(content)//2)
        self.assertEqual(self.queue.chunk(ident, "admin", 0, content[:split]), split)
        self.assertEqual(self.queue.chunk(ident, "admin", split, content[split:]), len(content))
        return ident, self.queue.finish(ident, "admin")

    def test_upload_preview_survives_database_reopen_and_index_pruning(self):
        from app.db import DB
        from app.library import Photo
        db = DB(self.server / "preview.db")
        ident, sha, data = "a" * 32, "b" * 64, b"thumbnail"
        db.run("INSERT INTO upload_previews VALUES(?,?,?,?)", (ident, sha, "webp:400:60", data))
        db.run("INSERT INTO upload_imports VALUES(?,?,?,?,?,?)",
               (ident, sha, "album/new.jpg", 123, 1700000000, 1700000001))
        db.vthumbs_prune(set())
        db.con.close()
        db = DB(self.server / "preview.db")
        try:
            self.assertEqual(db.run("SELECT data FROM upload_previews WHERE id=?", (ident,)), [(data,)])
            self.assertEqual(db.run("SELECT destination FROM upload_imports WHERE id=?", (ident,)),
                             [("album/new.jpg",)])
            p = Photo("abc", "album/new.jpg", 0, "new.jpg", 123, 1700000000, ".jpg")
            self.assertEqual(p.cache_key(), "album/new.jpg\0" + "123\0" + "1700000000")
        finally:
            db.con.close()

    def test_uploaded_video_is_seekable_at_end(self):
        content = b"start" + b"x" * (5 * 1024 * 1024) + b"moov-at-end"
        ident, item = self.upload("clip.mp4", content)
        received, source = self.queue.open_received(ident)
        with source:
            self.assertEqual(source.seek(-11, 2), len(content) - 11)
            self.assertEqual(source.read(), b"moov-at-end")
        self.assertEqual(received["sha"], hashlib.sha256(content).hexdigest())
        self.assertEqual(list(self.server.iterdir()), [])

    def test_supported_and_unsafe_paths(self):
        for name in ("a.JPG", "video.MP4", "scan.heic", "movie.avi", "movie.mts"):
            self.assertEqual(media_name(name), name)
        for name in ("test.exe","../foo.jpg","CON.mp4","bad:name.mov","x/abc.jpg"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                media_name(name)
        self.assertEqual(import_path("Google Фото/2026", "a.jpg"), "Google Фото/2026/a.jpg")
        for folder in ("../bad","Restored",".photocloud/uploads","A//B","C:\\Windows"):
            with self.subTest(folder=folder), self.assertRaises(ValueError):
                destination_folder(folder)

    def test_blocks_go_straight_to_pc_and_not_to_server_disk(self):
        content = b"abcdef" * 1000
        started = self.queue.start("admin","large.mp4","Альбом",len(content),1700000000)
        ident = started["id"]
        pc_part = self.pc / "Restored" / UPLOAD_PREFIX / ident / "large.mp4.photocloud-part"
        self.assertTrue(pc_part.exists())
        self.assertEqual(list(self.server.iterdir()), [])
        self.queue.chunk(ident,"admin",0,content[:1000])
        self.assertEqual(pc_part.read_bytes(),content[:1000])
        self.queue.chunk(ident,"admin",1000,content[1000:])
        done = self.queue.finish(ident,"admin")
        self.assertEqual(done["state"],"ready")
        self.assertEqual(done["sha"],hashlib.sha256(content).hexdigest())
        self.assertFalse(pc_part.exists())
        self.assertEqual((pc_part.parent / "large.mp4").read_bytes(),content)
        self.assertTrue((pc_part.parent / "manifest.json").exists())
        self.assertEqual(list(self.server.iterdir()), [])
        self.assertEqual(b"".join(self.queue.iter_media(ident)),content)

    def test_restart_reads_only_manifest_on_pc(self):
        ident, item = self.upload("photo.jpg", b"photo content")
        restarted = UploadQueue(self.writer)
        self.assertEqual(len(restarted.list()), 1)
        self.assertEqual(restarted.get(ident)["staged"], item["staged"])
        self.assertTrue(restarted.completed(ident, "Альбом/photo.jpg"))
        self.assertEqual(restarted.list(), [])
        self.assertFalse((self.pc / "Restored" / UPLOAD_PREFIX / ident / "manifest.json").exists())

    def test_discard_received_upload_removes_only_restored_copy(self):
        ident, item = self.upload("web.jpg", b"uploaded photo", "Album")
        original = self.pc / "Album" / "web.jpg"
        original.parent.mkdir()
        original.write_bytes(b"KEEP ORIGINAL")
        folder = self.pc / "Restored" / UPLOAD_PREFIX / ident
        self.assertTrue((folder / "manifest.json").exists())
        self.assertTrue(self.queue.discard(ident, item["sha"]))
        self.assertFalse((folder / "web.jpg").exists())
        self.assertFalse((folder / "manifest.json").exists())
        self.assertEqual(original.read_bytes(), b"KEEP ORIGINAL")
        self.assertEqual(self.queue.list(), [])

    def test_discard_refuses_wrong_sha(self):
        ident, item = self.upload("web.jpg", b"uploaded photo")
        with self.assertRaises(ValueError):
            self.queue.discard(ident, "0" * 64)
        self.assertIsNotNone(self.queue.get(ident))
        self.assertTrue((self.pc / "Restored" / UPLOAD_PREFIX / ident / "web.jpg").exists())

    def test_discard_refuses_modified_size_or_symlink(self):
        ident, item = self.upload("photo.jpg", b"original content")
        path = self.pc / "Restored" / UPLOAD_PREFIX / ident / "photo.jpg"
        path.write_bytes(b"changed length")
        with self.assertRaises(ValueError):
            self.queue.discard(ident, item["sha"])
        self.assertTrue(path.exists())
        path.unlink()
        external = self.pc / "gallery_original.jpg"
        external.write_bytes(b"outside")
        try:
            path.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not allowed on this machine")
        with self.assertRaises(ValueError):
            self.queue.discard(ident, item["sha"])
        self.assertEqual(external.read_bytes(), b"outside")

    def test_pc_discard_endpoint_rejects_unsigned_users(self):
        source = (ROOT / "app/main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "pc_upload_discard")
        self.assertIn("Depends(require_pc)", ast.get_source_segment(source, fn))
        self.assertIn("upload_queue.discard", ast.get_source_segment(source, fn))

    def test_offline_writer_rejects_upload_before_bytes(self):
        self.writer.enabled = False
        with self.assertRaises(ConnectionError):
            self.queue.start("admin","new.mp4","",100,1700000000)
        self.assertEqual(self.queue.active,{})
        self.assertEqual(list(self.server.iterdir()),[])

    def test_wrong_offsets_and_other_users_rejected(self):
        task = self.queue.start("admin", "a.jpg", "", 5, 1700000000)
        ident = task["id"]
        with self.assertRaises(ValueError):
            self.queue.chunk(ident,"other",0,b"hello")
        with self.assertRaises(ValueError):
            self.queue.chunk(ident,"admin",4,b"e")
        self.queue.chunk(ident,"admin",0,b"hello")
        with self.assertRaises(ValueError):
            self.queue.chunk(ident,"admin",0,b"x")
        self.assertEqual(self.queue.finish(ident,"admin")["state"],"ready")

    def test_cancel_removes_partial_upload_on_pc(self):
        started = self.queue.start("admin","cancel.mp4","",10,1700000000)
        ident = started["id"]
        self.queue.chunk(ident,"admin",0,b"abc")
        self.assertFalse(self.queue.cancel(ident,"intruder"))
        self.assertTrue(self.queue.cancel(ident,"admin"))
        base = self.pc / "Restored" / UPLOAD_PREFIX / ident
        self.assertFalse((base / "cancel.mp4.photocloud-part").exists())
        self.assertFalse((base / "manifest.json").exists())


    def test_duplicate_classification_compares_same_name_by_size(self):
        self.assertEqual(duplicate_status(2048, None), "new")
        self.assertEqual(duplicate_status(2048, 4096), "duplicate")
        self.assertEqual(duplicate_status(4096, 4096), "duplicate")
        self.assertEqual(duplicate_status(8192, 4096), "larger")

    def test_duplicate_metadata_check_does_not_read_media(self):
        folder = self.pc / "Album"
        folder.mkdir()
        file = folder / "photo.jpg"
        file.write_bytes(b"a" * 100)
        storage = LocalStorage(str(self.pc))
        self.assertEqual(storage.file_size("Album/photo.jpg"), 100)
        self.assertIsNone(storage.file_size("Album/missing.jpg"))
        with self.assertRaises(ValueError):
            storage.file_size("../secrets.jpg")

    def test_already_received_and_active_uploads_count_as_duplicates(self):
        self.upload("Same.JPG", b"a" * 10, "Album")
        active = self.queue.start("admin", "same.jpg", "ALBUM", 30, 1700000000)
        pending = self.queue.pending_sizes()
        self.assertEqual(pending[("album", "same.jpg")], 30)
        self.queue.cancel(active["id"], "admin")
        self.assertEqual(self.queue.pending_sizes()[("album", "same.jpg")], 10)

    def test_duplicate_preflight_is_admin_only_and_rechecked_at_start(self):
        src = (ROOT / "app/main.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        check_fn = next(x for x in tree.body if isinstance(x, ast.AsyncFunctionDef)
                        and x.name == "upload_check")
        start_fn = next(x for x in tree.body if isinstance(x, ast.AsyncFunctionDef)
                        and x.name == "upload_start")
        check_source = ast.get_source_segment(src, check_fn)
        start_source = ast.get_source_segment(src, start_fn)
        self.assertIn("Depends(require_admin)", check_source)
        self.assertIn("PC.is_up()", check_source)
        self.assertIn("storage.file_size(", src)
        self.assertIn("pending_sizes()", src)
        self.assertIn('decision["status"] == "duplicate"', start_source)
        self.assertIn('decision["status"] == "larger"', start_source)
        self.assertIn("allow_larger", start_source)

    def test_completed_upload_shows_result_not_stuck_at_100_percent(self):
        js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
        self.assertIn('id="up-result"', html)
        self.assertIn('id="up-result-title"', html)
        self.assertIn("function upShowResult(", js)
        self.assertIn("$('up-progress-wrap').hidden = true", js)
        self.assertIn("'Загрузка завершена'", js)
        self.assertIn("upShowResult(UP.done, skips.length, errors, ctrl.signal.aborted)", js)
        self.assertIn("Проверка SHA-256 на ПК", js)
        self.assertIn("upResetResult();", js)

    def test_latest_indexed_photo_sets_default_destination(self):
        from app.library import Library
        fake = SimpleNamespace(_feed=[
            SimpleNamespace(video=True, rel="Videos/newest.mp4"),
            SimpleNamespace(video=False, rel="Album/2026/newest.jpg"),
            SimpleNamespace(video=False, rel="Album/2025/old.jpg"),
        ])
        self.assertEqual(Library.latest_photo_folder(fake), "Album/2026")
        self.assertEqual(Library.latest_photo_folder(SimpleNamespace(_feed=[])), "")
        source = (ROOT / "app/main.py").read_text(encoding="utf-8")
        self.assertIn('"default_folder": library.latest_photo_folder()', source)
        js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        self.assertIn("data.default_folder", js)
        self.assertIn("UP.folderEdited", js)

    def test_progress_shows_sent_remaining_speed_and_eta_for_entire_batch(self):
        js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
        self.assertIn('id="up-progress-stats"', html)
        for fragment in ("function upProgressTracker(", "Передано ", " · осталось ",
                         " · скорость ", " · время до конца ", "tracker.skip(f.size)",
                         "tracker.complete(f.size)", "tracker.render(uploadedBytes",
                         "onVerify()"):
            self.assertIn(fragment, js)

    def test_excessive_server_ui_descriptions_are_removed(self):
        html = (ROOT / "app/static/admin.html").read_text(encoding="utf-8")
        main_html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
        js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        self.assertNotIn("Только администратор. Передача возможна только при включённом ПК.", main_html)
        self.assertNotIn("Файлы уже сохранены в Restored на ПК. Для переноса", js)
        self.assertNotIn("Уже записан в Restored · ожидает переноса клиентом ПК", js)
        self.assertNotIn("Клиент бэкапа на другом компьютере копирует оригиналы", html)
        self.assertNotIn("Хеши файлов</b> считаются сами", html)
        self.assertNotIn("Программа <b>photocloud_pc.pyw</b>", html)

    def test_server_endpoints_require_admin_and_online_pc(self):
        src = (ROOT / "app/main.py").read_text(encoding="utf-8")
        t = ast.parse(src)
        for name in ("upload_folders","upload_list","upload_check","upload_start","upload_chunk",
                     "upload_finish","upload_cancel","upload_media","upload_thumb"):
            f = next(n for n in t.body if isinstance(n,ast.AsyncFunctionDef) and n.name==name)
            text = ast.get_source_segment(src,f)
            self.assertIn("require_admin",text.splitlines()[0]+"\n"+"\n".join(text.splitlines()[:5]))
        for name in ("upload_start","upload_chunk","upload_finish"):
            f = next(n for n in t.body if isinstance(n,ast.AsyncFunctionDef) and n.name==name)
            self.assertIn("PC.is_up()",ast.get_source_segment(src,f))
        self.assertNotIn("incoming-uploads",src)
        self.assertNotIn("_upload_stage_loop",src)


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
