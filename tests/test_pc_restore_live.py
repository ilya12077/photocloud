"""Actual TCP server, real session signatures, SQLite and filesystem (no HTTP mocks)."""
import hashlib
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'TCP suite uses the Linux file key; Windows filesystem tested separately')
class LiveRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import httpx
        from app.db import DB
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        base = Path(cls.tmp.name)
        cls.media = base / 'media'
        cls.media.mkdir()
        (cls.media / 'Restored').mkdir()
        cls.env_before = dict(os.environ)
        cls.addClassCleanup(lambda: (os.environ.clear(), os.environ.update(cls.env_before)))
        for name in list(os.environ):
            if name.lower().endswith('_proxy'):
                del os.environ[name]
        os.environ['XDG_CONFIG_HOME'] = str(base / 'config')
        cls.pc = runpy.run_path(str(ROOT / 'pc/photocloud_pc.pyw'))
        cls.cfg = cls.pc['Config']()
        cls.cfg.root = str(cls.media)
        cls.cfg.client_id = 'restore-live-agent'
        cls.cfg.key_type = 'software'
        cls.key = cls.pc['open_key']('software', True)
        cls.db = DB(base / 'data' / 'photocloud.db')
        cls.db.pc_pair(cls.cfg.client_id, cls.pc['b64e'](cls.key.public_raw()), 'live test', 'software', '127.0.0.1')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cls.cfg.server = f'http://127.0.0.1:{port}'
        env = dict(os.environ, STORAGE='local', LOCAL_ROOT=str(cls.media), DATA_DIR=str(base / 'data'),
                   REQUIRE_PROXY='false', COOKIE_SECURE='false')
        cls.log = (base / 'server.log').open('w+')
        cls.addClassCleanup(cls.log.close)
        cls.proc = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port)], cwd=ROOT, env=env, stdout=cls.log, stderr=subprocess.STDOUT)
        def stop():
            cls.proc.terminate()
            try:
                cls.proc.wait(15)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()
        cls.addClassCleanup(stop)
        cls.http = httpx.Client(base_url=cls.cfg.server, trust_env=False)
        cls.addClassCleanup(cls.http.close)
        for _ in range(150):
            try:
                if cls.http.get('/admin').status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            if cls.proc.poll() is not None:
                cls.log.seek(0)
                raise RuntimeError(cls.log.read())
            time.sleep(.1)
        else:
            raise RuntimeError('local server did not start')
        cls.api = cls.pc['Api'](cls.cfg, cls.key)
        cls.addClassCleanup(cls.api.close)

    def item(self, name):
        dst = self.media / name
        dst.write_bytes(b'BAD PHOTO')
        os.utime(dst, (1700000000, 1700000000))
        (self.media / 'Restored' / name).write_bytes(b'GOODPHOTO')
        d = dict(path=name, key=f'{name}\0{9}\0{1700000000}', size=9, mtime=1700000000,
                 sha_good=hashlib.sha256(b'GOODPHOTO').hexdigest(), sha_bad=hashlib.sha256(b'BAD PHOTO').hexdigest(),
                 found=time.time(), updated=time.time(), state='restored', restored=name, note='')
        self.db.damaged_put(d)
        r = self.api.call('GET', '/api/pc/restored')
        self.assertEqual(r.status_code, 200, r.text)
        return next(i for i in r.json()['items'] if i['path'] == name)

    def body(self, item):
        return {k:item[k] for k in ('path', 'revision')}

    def test_replacement_lost_ack_retry_and_database(self):
        it = self.item('happy.jpg')
        check = self.api.call('POST', '/api/pc/restored/check', self.body(it))
        self.assertEqual(check.status_code, 200)
        self.assertTrue(self.pc['apply_restored'](self.media, check.json()))
        # No report: simulate process exit/network loss after replace; new invocation must not write again.
        inode = (self.media / 'happy.jpg').stat().st_ino
        self.assertFalse(self.pc['apply_restored'](self.media, it))
        self.assertEqual((self.media / 'happy.jpg').stat().st_ino, inode)
        done = self.api.call('POST', '/api/pc/restored/complete', self.body(it))
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(self.db.damaged_get('happy.jpg')['state'], 'fixed')
        self.assertEqual(self.api.call('POST', '/api/pc/restored/complete', self.body(it)).status_code, 200)
        self.assertTrue(any(p.read_bytes() == b'BAD PHOTO' for p in (self.pc['app_dir']() / 'replaced-originals').glob('*.bak')))

    def test_wrong_copy_and_changed_original(self):
        it = self.item('tampered.jpg')
        (self.media / 'Restored/tampered.jpg').write_bytes(b'EVILPHOTO')
        with self.assertRaises(ValueError):
            self.pc['apply_restored'](self.media, it)
        self.assertEqual((self.media / 'tampered.jpg').read_bytes(), b'BAD PHOTO')
        (self.media / 'tampered.jpg').write_bytes(b'NEW PHOTO')
        os.utime(self.media / 'tampered.jpg', (it['mtime'], it['mtime']))
        with self.assertRaises(ValueError):
            self.pc['apply_restored'](self.media, it)
        self.assertEqual(self.api.call('POST', '/api/pc/restored/complete', self.body(it)).status_code, 409)
        self.assertEqual(self.db.damaged_get(it['path'])['state'], 'restored')

    def test_truncated_and_oversized_copy(self):
        it = self.item('length.jpg')
        for content in (b'x', b'GOODPHOTOextra'):
            (self.media / 'Restored/length.jpg').write_bytes(content)
            with self.assertRaises(ValueError):
                self.pc['apply_restored'](self.media, it)
            self.assertEqual((self.media / 'length.jpg').read_bytes(), b'BAD PHOTO')
            self.assertFalse(list(self.media.glob('.photocloud-restore-*')))

    def test_auth_revision_and_unannounced_file(self):
        # В админке после сокращения пояснений остаётся управление
        # повреждёнными файлами, а кнопка восстановления — в клиенте ПК.
        admin_html = self.http.get('/admin').text
        self.assertIn('id="dmg"', admin_html)
        self.assertIn('id="dmg-check"', admin_html)
        agent_code = (Path(__file__).resolve().parents[1] / 'pc/photocloud_pc.pyw').read_text(encoding='utf-8')
        self.assertIn('Применить восстановленные копии', agent_code)
        it = self.item('stale.jpg')
        self.assertEqual(self.http.get('/api/pc/restored').status_code, 401)
        self.assertEqual(self.http.post('/api/pc/restored/complete', json=self.body(it)).status_code, 401)
        d = self.db.damaged_get(it['path'])
        d['updated'] += 1
        self.db.damaged_put(d)
        self.assertEqual(self.api.call('POST', '/api/pc/restored/check', self.body(it)).status_code, 409)
        self.assertEqual(self.api.call('POST', '/api/pc/restored/complete', self.body(it)).status_code, 409)
        (self.media / 'Restored/unannounced.jpg').write_bytes(b'GOODPHOTO')
        self.assertNotIn('unannounced.jpg', [i['path'] for i in self.api.call('GET', '/api/pc/restored').json()['items']])
        self.assertEqual(self.api.call('POST', '/api/pc/restored/check', {'path':'../outside', 'revision':'x'}).status_code, 409)

    def test_paths_links_and_missing_bad_hash(self):
        it = self.item('paths.jpg')
        for path in ('../outside', '/outside', 'x:stream', 'Restored/paths.jpg', '.photocloud/x', 'CON.jpg', 'a./x', 'x\\y'):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                self.pc['apply_restored'](self.media, dict(it, path=path))
        with self.assertRaises(ValueError):
            self.pc['apply_restored'](self.media, dict(it, sha_bad=''))
        (self.media / 'link').symlink_to(self.media / 'Restored', target_is_directory=True)
        with self.assertRaises(ValueError):
            self.pc['apply_restored'](self.media, dict(it, path='link/paths.jpg'))
        source = self.media / 'Restored/paths.jpg'
        source.unlink()
        source.symlink_to(self.media / 'paths.jpg')
        with self.assertRaises(ValueError):
            self.pc['apply_restored'](self.media, it)
        self.assertFalse(list(self.media.glob('.photocloud-restore-*')))
