"""Массовая загрузка оригиналов: ZIP без временных файлов и одноразовые ссылки."""
import io
import unittest
import zipfile
from types import SimpleNamespace

from app.downloads import DownloadTickets, iter_zip_originals


class DownloadTicketsTests(unittest.TestCase):
    def test_one_time_ticket_only_for_same_user_and_session(self):
        tickets = DownloadTickets(ttl=180)
        token = tickets.issue("alice", "session-1", ["abc12345"] * 51, now=100)
        self.assertEqual(len(token), 32)
        self.assertIsNone(tickets.take("bob", "session-1", token, now=101))
        self.assertIsNone(tickets.take("alice", "session-2", token, now=101))
        self.assertEqual(tickets.take("alice", "session-1", token, now=101), tuple(["abc12345"] * 51))
        self.assertIsNone(tickets.take("alice", "session-1", token, now=102))

    def test_ticket_expires(self):
        tickets = DownloadTickets(ttl=180)
        token = tickets.issue("alice", "session", ["abc12345"], now=100)
        self.assertIsNone(tickets.take("alice", "session", token, now=280))


class ZipDownloadsTests(unittest.TestCase):
    def test_streaming_zip_contains_all_selected_originals_and_folders(self):
        mapping = {
            "Google Фото/2026/Фото.jpg": b"\xff\xd8" + b"JPG" * 5000,
            "Google Фото/2026/Семья/Видео.mp4": b"\0\0\0ftyp" + b"VIDEO" * 20000,
        }
        entries = [SimpleNamespace(rel=name, mtime=1700000000) for name in mapping]
        opens = []
        class Reader(io.BytesIO):
            pass
        def opener(path):
            opens.append(path)
            return Reader(mapping[path])
        # Каждый yield ограничен размером читаемого куска (кроме заголовков ZIP).
        chunks = list(iter_zip_originals(entries, opener, chunk_size=8192))
        self.assertGreater(len(chunks), 5)
        self.assertEqual(opens, list(mapping))
        with zipfile.ZipFile(io.BytesIO(b"".join(chunks))) as archive:
            self.assertEqual(set(archive.namelist()), set(mapping))
            for path, content in mapping.items():
                self.assertEqual(archive.read(path), content)
                self.assertEqual(archive.getinfo(path).compress_type, zipfile.ZIP_STORED)

    def test_unavailable_file_reported_without_breaking_zip(self):
        entries = [SimpleNamespace(rel="present.jpg", mtime=1700000000),
                   SimpleNamespace(rel="missing.jpg", mtime=1700000000)]
        def opener(path):
            if path == "missing.jpg":
                raise FileNotFoundError("нет файла")
            return io.BytesIO(b"original")
        result = b"".join(iter_zip_originals(entries, opener))
        with zipfile.ZipFile(io.BytesIO(result)) as archive:
            self.assertEqual(archive.read("present.jpg"), b"original")
            self.assertNotIn("missing.jpg", archive.namelist())
            self.assertIn("missing.jpg", archive.read("ОШИБКИ_СКАЧИВАНИЯ.txt").decode())

    def test_invalid_archive_path_cannot_traverse(self):
        photos = [SimpleNamespace(rel="../private.txt", mtime=1700000000)]
        result = b"".join(iter_zip_originals(photos, lambda _: io.BytesIO(b"secret")))
        with zipfile.ZipFile(io.BytesIO(result)) as archive:
            self.assertNotIn("../private.txt", archive.namelist())
            self.assertIn("ОШИБКИ_СКАЧИВАНИЯ.txt", archive.namelist())


if __name__ == "__main__":
    unittest.main()
