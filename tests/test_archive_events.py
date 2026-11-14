import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import re
import time
import unittest

from app.db import DB
from test_offline import production_function


class ArchiveEventTests(unittest.TestCase):
    def test_lost_ack_replay_after_restart(self):
        async def run(fn, *args):
            return fn(*args)
        with TemporaryDirectory() as folder:
            path = Path(folder) / "server.db"
            event = ["a"*32, 123.5, "moved", "old.jpg", "new.jpg"]
            for _ in range(2):
                db = DB(path)
                db.run("CREATE TABLE IF NOT EXISTS archive_events(id TEXT PRIMARY KEY,at REAL,kind TEXT,src TEXT,dst TEXT,received REAL)")
                save = production_function("app/main.py", "pc_changes", globals_=dict(
                    app=SimpleNamespace(post=lambda _:lambda f:f), Depends=lambda _:None,
                    require_pc=None, _pc_json=lambda _:{"events":[event]}, re=re, time=time,
                    db=db, run_in_threadpool=run, no_store=lambda x:x, JSONResponse=dict))
                self.assertEqual(asyncio.run(save(None)), {"ok":True})
                self.assertEqual(db.run("SELECT kind,src,dst FROM archive_events"), [tuple(event[2:])])
                db.con.close()
