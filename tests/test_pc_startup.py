"""Exercise the real App constructor and marks loader together."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import hashlib

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows desktop agent is tested on the required Windows runner")
    def test_paired_agent_loads_marks(self):
        import httpx
        import tkinter as tk
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "USERPROFILE": directory}))
            import sys
            stack.enter_context(patch.object(sys, "excepthook"))
            module = runpy.run_path(str(ROOT / "pc/photocloud_pc.pyw"))
            cfg = module["Config"]()
            cfg.root, cfg.server, cfg.client_id = directory, "https://archive.test", "agent"
            app_class = module["App"]
            if not os.environ.get("DISPLAY") and os.name != "nt":
                stack.enter_context(patch.object(tk, "Tk"))
                stack.enter_context(patch.object(app_class, "_build"))
            app = app_class(cfg)
            stack.callback(app.root.destroy)
            stack.callback(app.check_pool.shutdown)
            stack.callback(app.thumb_pool.shutdown)
            for name in list(os.environ):
                if name.lower().endswith("_proxy"):
                    stack.enter_context(patch.dict(os.environ, {name: ""}))
            api = module["Api"](cfg, None)
            api.c.close()
            def marks(request):
                self.assertEqual(request.url.path, "/api/pc/marks")
                self.assertTrue(request.headers["x-pc-mac"])
                return httpx.Response(200, json={"items": []})
            api.c = httpx.Client(base_url=cfg.server, transport=httpx.MockTransport(marks))
            stack.callback(api.close)
            import time
            api.sid, api.skey, api.exp = "session", b"key", time.time() + 900
            app.api = api
            app.bg = Mock()  # startup check is tested independently without a UI thread
            app._load()
            callback = app.q.get_nowait()
            if not os.environ.get("DISPLAY") and os.name != "nt":
                app._show = Mock()
            callback()
            self.assertEqual(app.items, [])
            app.bg.assert_called_once_with(app._check_startup_restores)


class RestoreFilesystemTests(unittest.TestCase):
    def test_verified_replace_retry_and_tamper(self):
        import hashlib
        import sys
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'USERPROFILE': directory, 'XDG_CONFIG_HOME': directory}), patch.object(sys, 'excepthook'):
            module = runpy.run_path(str(ROOT / 'pc/photocloud_pc.pyw'))
            root = Path(directory) / 'archive'
            (root / 'Restored').mkdir(parents=True)
            dst = root / 'photo.jpg'
            dst.write_bytes(b'bad')
            os.utime(dst, (1700000000, 1700000000))
            src = root / 'Restored/photo.jpg'
            src.write_bytes(b'bad')
            item = dict(path='photo.jpg', restored='photo.jpg', size=3, mtime=1700000000,
                        sha_good=hashlib.sha256(b'new').hexdigest(), sha_bad=hashlib.sha256(b'bad').hexdigest())
            with self.assertRaises(ValueError):
                module['apply_restored'](root, item)
            self.assertEqual(dst.read_bytes(), b'bad')
            src.write_bytes(b'new')
            with patch.object(module['os'], 'replace', side_effect=PermissionError('file locked')):
                with self.assertRaises(PermissionError):
                    module['apply_restored'](root, item)
            self.assertEqual(dst.read_bytes(), b'bad')
            self.assertFalse(list(root.glob('.photocloud-restore-*')))
            self.assertTrue(module['apply_restored'](root, item))
            self.assertEqual(dst.read_bytes(), b'new')
            self.assertEqual(int(dst.stat().st_mtime), 1700000000)
            self.assertFalse(module['apply_restored'](root, item))
            self.assertFalse(list(root.glob('.photocloud-restore-*')))
            self.assertTrue(any(p.read_bytes() == b'bad' for p in (module['app_dir']() / 'replaced-originals').glob('*.bak')))


class StartupRestorePromptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        with patch.object(sys, "excepthook"):
            cls.module = runpy.run_path(str(ROOT / "pc/photocloud_pc.pyw"))

    def test_only_server_reported_sha_matching_copies_are_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            (archive / "Restored").mkdir()
            (archive / "Restored" / "good.jpg").write_bytes(b"good")
            (archive / "Restored" / "tampered.jpg").write_bytes(b"evil")
            (archive / "Restored" / "unannounced.jpg").write_bytes(b"good")
            reported = [
                dict(path="good.jpg", restored="good.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
                dict(path="tampered.jpg", restored="tampered.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
                dict(path="missing.jpg", restored="missing.jpg", size=4,
                     sha_good=hashlib.sha256(b"good").hexdigest()),
            ]
            api = Mock()
            api.call.return_value = SimpleNamespace(status_code=200, json=lambda: {"items": reported})
            app = SimpleNamespace(api=api, cfg=SimpleNamespace(root=str(archive)),
                                  ui=Mock(), _offer_startup_restores=Mock())
            self.module["App"]._check_startup_restores(app)
            api.call.assert_called_once_with("GET", "/api/pc/restored")
            app.ui.assert_called_once()
            app.ui.call_args.args[0]()
            app._offer_startup_restores.assert_called_once_with(api, str(archive), ("good.jpg",))

    def test_local_file_without_server_notice_does_not_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            (archive / "Restored").mkdir()
            (archive / "Restored" / "unannounced.jpg").write_bytes(b"good")
            api = Mock()
            api.call.return_value = SimpleNamespace(status_code=200, json=lambda: {"items": []})
            app = SimpleNamespace(api=api, cfg=SimpleNamespace(root=str(archive)),
                                  ui=Mock(), _offer_startup_restores=Mock())
            self.module["App"]._check_startup_restores(app)
            app.ui.assert_not_called()

    def test_confirmation_is_required(self):
        api = Mock()
        app = SimpleNamespace(api=api, cfg=SimpleNamespace(root="archive"),
                              busy=False, apply_restores=Mock())
        with patch.object(self.module["messagebox"], "askyesno", return_value=False):
            self.module["App"]._offer_startup_restores(app, api, "archive", ("good.jpg",))
        app.apply_restores.assert_not_called()
        with patch.object(self.module["messagebox"], "askyesno", return_value=True):
            self.module["App"]._offer_startup_restores(app, api, "archive", ("good.jpg",))
        app.apply_restores.assert_called_once_with(only_paths={"good.jpg"})


class UploadedFilesStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        with patch.object(sys, "excepthook"):
            cls.module = runpy.run_path(str(ROOT / "pc/photocloud_pc.pyw"))

    def test_client_opens_upload_gallery_with_preview_and_delete_action(self):
        source = (ROOT / "pc/photocloud_pc.pyw").read_text(encoding="utf-8")
        for token in ('text="Плитки с превью"', 'command=self._up_delete',
                      'def _up_card(', 'def _up_thumb(', 'def _up_tile_click(',
                      'self.up_tree.selection_add', 'self.thumb_pool.submit(self._up_thumb'):
            self.assertIn(token, source)

    def test_startup_upload_notification_is_once_only(self):
        api = self.module["App"]
        mock_root = Mock()
        object_under_test = SimpleNamespace(
            _up_refreshing=True, up_tree=Mock(),
            root=mock_root, upload_tab=Mock(), nb=Mock(), up_canvas=Mock(),
            upload_items=[], upload_by_id={}, _uploads_known=None,
            _up_active_id=None,
            up_gen=1, _up_layout=Mock(), _up_selection_changed=Mock(),
            up_status=Mock())
        object_under_test.up_tree.selection.return_value = ()
        object_under_test.up_tree.get_children.return_value = ()
        object_under_test.up_canvas.yview.return_value = (0.0, 1.0)
        loaded = [{"id": "0" * 32, "name": "test.jpg", "folder": "Photos",
                   "size": 100, "user": "admin"}]
        with patch.object(self.module["messagebox"], "showinfo") as shown:
            api._up_show(object_under_test, loaded, [], "")
            mock_root.after.assert_called_once()
            callback = mock_root.after.call_args.args[1]
            callback()
            shown.assert_called_once()
            self.assertIn("Загруженные", shown.call_args.args[1])
            mock_root.after.reset_mock()
            api._up_show(object_under_test, loaded, [], "")
            mock_root.after.assert_not_called()

    def test_delete_requires_confirmation_before_api_call(self):
        cls = self.module["App"]
        item = {"id": "a" * 32, "name": "photo.jpg", "sha": "b" * 64, "size": 100}
        app = SimpleNamespace(up_tree=Mock(), upload_by_id={item["id"]: item},
                              busy=False, api=Mock(), bg=Mock())
        app.up_tree.selection.return_value = (item["id"],)
        with patch.object(self.module["messagebox"], "askyesno", return_value=False):
            cls._up_delete(app)
        app.api.call.assert_not_called()
        app.bg.assert_not_called()

    def test_last_clicked_tile_becomes_active_without_losing_other_selection(self):
        app_class = self.module["App"]
        first, second = "a" * 32, "b" * 32
        selected = [first]
        tree = Mock()
        tree.selection.side_effect = lambda: tuple(selected)
        tree.selection_add.side_effect = selected.append
        app = SimpleNamespace(
            _up_hit=Mock(return_value=1),
            upload_items=[{"id": first}, {"id": second}],
            up_tree=tree, _up_last_tile=0, _up_active_id=first,
            _up_selection_changed=Mock(),
        )
        app_class._up_tile_click(app, SimpleNamespace(state=0))
        self.assertEqual(selected, [first, second])
        self.assertEqual(app._up_active_id, second)
        app._up_selection_changed.assert_called_once()

    def test_preview_uses_last_clicked_not_first_selected(self):
        app_class = self.module["App"]
        first, second = "a" * 32, "b" * 32
        items = {
            first: {"id": first, "name": "top.jpg", "user": "admin", "folder": "Album"},
            second: {"id": second, "name": "last.jpg", "user": "admin", "folder": "Album"},
        }
        tree = Mock()
        tree.selection.return_value = (first, second)
        mock_views = Mock()
        mock_views.select.return_value = "gallery"
        app = SimpleNamespace(
            up_tree=tree, up_groups={}, upload_by_id=items,
            _up_active_id=second, up_views=mock_views, up_table="table",
            up_drawn={}, up_canvas=Mock(), b_up_move=Mock(), b_up_delete=Mock(),
            busy=False, up_details=Mock(), up_preview=Mock(), _up_preview_img=None,
            up_thumbs={},
        )
        with patch.object(self.module["threading"], "Thread") as new_thread:
            app_class._up_selection_changed(app)
            new_thread.return_value.start.assert_called_once()
        text = app.up_details.configure.call_args.kwargs["text"]
        self.assertIn("last.jpg", text)
        self.assertNotIn("top.jpg", text)
        self.assertIn("Выделено: 2", text)

    def test_tree_focus_selects_last_pressed_when_using_list_view(self):
        app_class = self.module["App"]
        first, second = "a" * 32, "b" * 32
        items = {k: {"id": k, "name": k + ".jpg", "user": "admin", "folder": "Album"}
                 for k in (first, second)}
        tree = Mock()
        tree.selection.return_value = (first, second)
        tree.focus.return_value = second
        mock_views = Mock()
        mock_views.select.return_value = "table"
        app = SimpleNamespace(
            up_tree=tree, up_groups={}, upload_by_id=items,
            _up_active_id=first, up_views=mock_views, up_table="table",
            up_drawn={}, up_canvas=Mock(), b_up_move=Mock(), b_up_delete=Mock(),
            busy=False, up_details=Mock(), up_preview=Mock(), _up_preview_img=None,
            up_thumbs={},
        )
        with patch.object(self.module["threading"], "Thread"):
            app_class._up_selection_changed(app, SimpleNamespace(widget=tree))
        self.assertEqual(app._up_active_id, second)

    def test_upload_destination_is_fixed_by_website_and_grouped(self):
        source = (ROOT / "pc/photocloud_pc.pyw").read_text(encoding="utf-8")
        self.assertNotIn("self.up_folder_box", source)
        self.assertNotIn("self.up_folder.get()", source)
        self.assertNotIn("def _up_new_folder(", source)
        self.assertIn('item, item["folder"]', source)
        self.assertIn("self.up_groups", source)
        self.assertIn("self.up_headers", source)

