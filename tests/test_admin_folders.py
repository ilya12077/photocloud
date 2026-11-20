"""Проверка списка папок для настроек прав: все вложенные уровни."""
import asyncio
from types import SimpleNamespace
import unittest

from test_offline import production_function


class AdminFoldersTests(unittest.TestCase):
    def test_nested_google_photo_album_is_returned(self):
        folders = [
            "", "Google Фото", "Google Фото/Фото 2026 г_",
            "Google Фото/Фото 2026 г_/Нужный альбом",
            "Google Фото/Фото 2026 г_/Нужный альбом/Подборка",
            "фотки", "фотки/2026"
        ]
        fn = production_function("app/main.py", "admin_folders", globals_={
            "app": SimpleNamespace(get=lambda path: lambda func: func),
            "Depends": lambda dependency: None,
            "require_admin": object(),
            "library": SimpleNamespace(_folders=folders),
            "no_store": lambda result: result,
            "JSONResponse": lambda d: d,
        })
        res = asyncio.run(fn())
        self.assertNotIn("", res["folders"])
        self.assertEqual(len(res["folders"]), len(folders) - 1)
        self.assertIn("Google Фото/Фото 2026 г_/Нужный альбом", res["folders"])
        self.assertIn("Google Фото/Фото 2026 г_/Нужный альбом/Подборка", res["folders"])

    def test_empty_index_returns_empty_list(self):
        fn = production_function("app/main.py", "admin_folders", globals_={
            "app": SimpleNamespace(get=lambda path: lambda func: func),
            "Depends": lambda dependency: None,
            "require_admin": object(),
            "library": SimpleNamespace(_folders=[""]),
            "no_store": lambda result: result,
            "JSONResponse": lambda d: d,
        })
        self.assertEqual(asyncio.run(fn()), {"folders": []})


if __name__ == "__main__":
    unittest.main()
