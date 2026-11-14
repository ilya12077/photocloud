from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from app.db import DB
from test_offline import production_function


class ReconciliationTests(unittest.TestCase):
    def test_partial_and_unhashed_moves(self):
        plan = production_function("backup/photocloud_backup.pyw", "_plan", "Engine")
        local = {"old": (7, 1, "hash")}
        target = ["new", 7, 2, 1, "hash", 0]
        moves, copies, _, deletes, _ = plan(SimpleNamespace(), {"new": target}, local, False)
        self.assertEqual((moves, copies, deletes), ([], [("old", "new")], ["old"]))
        target[4] = None
        self.assertEqual(plan(SimpleNamespace(), {"new": target}, local)[3], [])
        target[4] = "hash"
        self.assertEqual(plan(SimpleNamespace(), {"new": target}, local)[0], [("old", "new")])

    def test_report_is_atomic_and_replay_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            db = DB(Path(folder) / "server.db")
            db.run("CREATE TABLE backup_deleted(path TEXT PRIMARY KEY, at REAL)")
            db.marks_put([("a", "a\x007\x001", "hash")], "admin")
            item = dict(path="a", size=7, mtime=1, sha="hash", at=db.marks_rows()[0][-1])
            db.run("CREATE TRIGGER fail BEFORE DELETE ON delete_marks BEGIN SELECT RAISE(ABORT,'test'); END")
            import sqlite3
            with self.assertRaises(sqlite3.IntegrityError):
                db.finish_deletions([item])
            self.assertEqual(db.run("SELECT * FROM backup_deleted"), [])
            db.run("DROP TRIGGER fail")
            self.assertEqual(db.finish_deletions([item]), ["a"])
            self.assertEqual(db.finish_deletions([item]), [])
            db.marks_put([("a", "a\x007\x001", "hash")], "admin")
            self.assertEqual(db.finish_deletions([item]), [])
            db.con.close()

    def test_restart_retries_missing_file_after_lost_response(self):
        import json
        import sqlite3
        from contextlib import closing
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cfg = SimpleNamespace(server="test", root=folder, client_id="pc")
            journal = production_function("pc/photocloud_pc.pyw", "_journal", "App",
                dict(json=json, sqlite3=sqlite3, closing=closing, app_dir=lambda: root))
            item = dict(path="a.jpg", size=7, sha="hash", at=1, mtime=2)
            journal(SimpleNamespace(cfg=cfg), [item])
            restarted = Mock()
            restarted.cfg = cfg
            restarted._pending.side_effect = lambda: journal(restarted)
            restarted._journal.side_effect = lambda *a, **k: journal(restarted, *a, **k)
            restarted.api.call.return_value.status_code = 200
            restarted.api.call.return_value.json.side_effect = lambda: {"items": [item.copy()]}
            load = production_function("pc/photocloud_pc.pyw", "_load", "App",
                dict(Path=Path, check_file=lambda *_: ("missing", None, "")))
            restarted._report.side_effect = [ConnectionError(), 1]
            with self.assertRaises(ConnectionError):
                load(restarted)
            self.assertEqual(journal(restarted), [item])
            load(restarted)
            self.assertEqual(journal(restarted), [])
