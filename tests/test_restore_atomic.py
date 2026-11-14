import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock
import unittest
import uuid

from test_offline import production_function


class RestoreAtomicTests(unittest.IsolatedAsyncioTestCase):
    async def test_interrupted_and_repeated_chunk(self):
        async def threaded(fn, *args):
            await asyncio.sleep(0)
            return fn(*args)
        class Request:
            def __init__(self, disconnect=False):
                self.disconnect = disconnect
            async def stream(self):
                yield b"123"
                await asyncio.sleep(0)
                if self.disconnect:
                    raise ConnectionError()
        import hashlib
        with TemporaryDirectory() as folder:
            part = Path(folder) / "incoming"
            scope = dict(RESTORE_TMP=part.parent, RESTORE_CHUNK=12,
                         _restore_item=lambda *_: {"size": 12}, _part_path=lambda _: part,
                         run_in_threadpool=threaded, no_store=lambda x: x,
                         JSONResponse=lambda body, status=200: (status, body),
                         Depends=lambda _: None, require_backup=None, hashlib=hashlib,
                         app=SimpleNamespace(put=lambda _:lambda fn:fn),
                         _restore_locks=[asyncio.Lock()], _writing=set())
            scope["_accept_restore_chunk"] = production_function("app/main.py", "_accept_restore_chunk", globals_=scope)
            put = production_function("app/main.py", "backup_restore_put", globals_=scope)
            with self.assertRaises(ConnectionError):
                await put(Request(True), "a", 0, None)
            self.assertFalse(part.exists())
            results = await asyncio.gather(*(put(Request(), "a", 0, None) for _ in range(2)))
            self.assertEqual(sorted(code for code, _ in results), [200, 409])
            self.assertEqual(part.read_bytes(), b"123")

    def test_smb_collision_preserves_destination(self):
        with TemporaryDirectory() as folder:
            src = Path(folder) / "source"
            src.write_bytes(b"photo")
            smb = Mock()
            smb.stat.side_effect = FileNotFoundError()
            smb.open_file.side_effect = FileExistsError()
            obj = SimpleNamespace(_smb=smb, _kw={}, host="pc", root="restored",
                                  _final_names=lambda _: [["photo.jpg"]], _mkdirs=lambda *_:None)
            write = production_function("app/storage.py", "_write_smb", "RestoreWriter",
                                        dict(uuid=uuid, is_missing=lambda e:isinstance(e, FileNotFoundError)))
            with self.assertRaises(FileExistsError):
                write(obj, "photo.jpg", src, 0, "hash")
            smb.remove.assert_not_called()
