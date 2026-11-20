"""Скрытие файлов должно переживать подтверждённое удаление в корзину."""
import tempfile
import unittest
from pathlib import Path
from app.db import DB


class HiddenAfterRecycleTests(unittest.TestCase):
    def test_hidden_settings_survive_confirmed_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            db = DB(Path(directory) / "photocloud.db")
            db.run("CREATE TABLE IF NOT EXISTS backup_deleted(path TEXT PRIMARY KEY, at REAL NOT NULL)")
            db.hidden_put("alice", ["family/photo.jpg"])
            db.hidden_put("bob", ["family/photo.jpg"])
            db.marks_put([("family/photo.jpg", "family/photo.jpg\x0010\x001234", "goodhash")], "alice")
            at = db.marks_rows()[0][-1]
            item = {"path": "family/photo.jpg", "size": 10, "mtime": 1234, "sha": "goodhash", "at": at}
            self.assertEqual(db.finish_deletions([item]), ["family/photo.jpg"])
            self.assertEqual(db.finish_deletions([item]), [])
            self.assertEqual(db.marks_rows(), [])
            self.assertEqual(db.run("SELECT path FROM backup_deleted"), [("family/photo.jpg",)])
            self.assertIn("family/photo.jpg", db.hidden_load()["alice"])
            self.assertIn("family/photo.jpg", db.hidden_load()["bob"])
            db.con.close()
