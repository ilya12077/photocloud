"""Проверки пометок удаления из основной галереи без запуска всего сервера."""
import asyncio
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from test_offline import production_function


class GalleryDeleteTests(TestCase):
    def _view(self, hidden=0, starred=0, marks=None):
        photo = "photo.jpg"
        library = SimpleNamespace(built_at=100, view=Mock())
        mine = SimpleNamespace(hidden={"adm": {}}, groups={}, starred={"adm": {photo}},
                               gen={"adm": 0})
        fn = production_function("app/main.py", "_view_for", globals_={
            "mine": mine, "_deleted_times": {},
            "_marks": {p: ("adm", 1) for p in (marks if marks is not None else (photo,))},
            "library": library, "user_folders": lambda _: None,
            "_hidden_all": lambda: {photo},
        })
        fn(SimpleNamespace(user="adm", role="admin"), hidden, starred)
        return library.view.call_args.kwargs

    def test_marked_photo_hidden_in_all_galleries(self):
        photo = "photo.jpg"
        self.assertIn(photo, self._view()["hide"])
        self.assertIn(photo, self._view(starred=1)["hide"])
        self.assertNotIn(photo, self._view(hidden=1)["only"])

    def test_cache_key_changes_when_mark_created(self):
        self.assertNotEqual(self._view(marks=())["key"], self._view(marks=("photo.jpg",))["key"])

    def test_admin_marks_unhidden_photo(self):
        photo = SimpleNamespace(rel="photo.jpg", cache_key=lambda: "key")
        recorded = []
        db = SimpleNamespace(hash_get=lambda _: "sha",
                             marks_put=lambda rows, user: recorded.extend(rows),
                             marks_load=lambda: {"photo.jpg": ("adm", 1)})
        async def targets(*_args):
            return [photo], {"on": True}
        async def pool(fn, *args):
            return fn(*args)
        fn = production_function("app/main.py", "marks_set", globals_={
            "app": SimpleNamespace(post=lambda *a, **kw: lambda fn: fn),
            "Depends": lambda _: None, "require_csrf": None, "require_admin": None,
            "_targets": targets, "_bad": lambda msg: {"error": msg},
            "db": db, "_marks": {}, "run_in_threadpool": pool,
            "audit": Mock(), "ip_of": lambda _: "",
            "_n": lambda photos: len(photos), "_sample": lambda _: "photo.jpg",
            "no_store": lambda x: x, "JSONResponse": dict,
        })
        result = asyncio.run(fn(None, SimpleNamespace(user="adm")))
        self.assertEqual(result["count"], 1)
        self.assertEqual(recorded, [("photo.jpg", "key", "sha")])
