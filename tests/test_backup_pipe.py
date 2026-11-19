"""Real Windows named pipes and separate processes, without mocking Win32."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVER = r'''
import runpy, sys, time
from pathlib import Path
m = runpy.run_path(sys.argv[1])
folder = Path(sys.argv[2])
def show():
    with (folder / 'shown').open('a') as f:
        f.write('show\n')
i = m['SingleInstance'](folder, show)
try:
    acquired = i.acquire()
    (folder / ('ready' if acquired else 'secondary')).write_text('ok')
    if acquired:
        (folder / 'pipe-name').write_text(i._win.name)
        while not (folder / 'stop').exists():
            time.sleep(.02)
finally:
    i.close()
'''
RAW = r'''
import runpy, sys, time
m = runpy.run_path(sys.argv[1])
i = m['WindowsInstance'](lambda: None)
c, w, k = i.c, i.w, i.k
h = k.CreateFileW(i.name, 0x40000000, 0, None, 3, 0x00100000, None)
if h == c.c_void_p(-1).value:
    raise c.WinError(c.get_last_error())
try:
    if sys.argv[2] == 'idle':
        time.sleep(3)
    else:
        data = sys.argv[2].encode()
        n = w.DWORD()
        if not k.WriteFile(h, data, len(data), c.byref(n), None):
            raise c.WinError(c.get_last_error())
finally:
    k.CloseHandle(h)
'''


@unittest.skipUnless(os.name == 'nt', 'requires real Windows named pipes')
class NamedPipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.script = str(ROOT / 'backup/photocloud_backup.pyw')
        self.log = (self.folder / 'process.log').open('w+')
        self.addCleanup(self.log.close)
        self.processes = []
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        for p in self.processes:
            if p.poll() is None:
                p.kill()
            p.wait(10)

    def start(self):
        p = subprocess.Popen([sys.executable, '-c', SERVER, self.script, str(self.folder)],
                             stdout=self.log, stderr=self.log)
        self.processes.append(p)
        return p

    def wait_for(self, fn):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if fn():
                return
            time.sleep(.05)
        self.log.flush()
        self.log.seek(0)
        self.fail('timed out: ' + self.log.read())

    def shown(self):
        p = self.folder / 'shown'
        return len(p.read_text().splitlines()) if p.exists() else 0

    def test_second_launch_repeated_and_crash_restart(self):
        (self.folder / 'instance.port').write_text('12345')
        first = self.start()
        self.wait_for(lambda: (self.folder / 'ready').exists())
        self.assertFalse((self.folder / 'instance.port').exists())
        for expected in range(1, 4):
            second = self.start()
            self.assertEqual(second.wait(10), 0)
            self.wait_for(lambda: self.shown() == expected)
            self.assertIsNone(first.poll())
        first.kill()
        first.wait(10)
        (self.folder / 'ready').unlink()
        replacement = self.start()
        self.wait_for(lambda: (self.folder / 'ready').exists())
        self.assertEqual(self.start().wait(10), 0)
        self.wait_for(lambda: self.shown() == 4)
        (self.folder / 'stop').touch()
        self.assertEqual(replacement.wait(10), 0)
        self.assertFalse((self.folder / 'instance.port').exists())

    def test_malformed_and_idle_clients_do_not_block(self):
        first = self.start()
        self.wait_for(lambda: (self.folder / 'ready').exists())
        for command in ('delete', 'showXXXXXXXXXXXXXX', 'idle'):
            r = subprocess.run([sys.executable, '-c', RAW, self.script, command],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.shown(), 0)
        self.assertEqual(self.start().wait(10), 0)
        self.wait_for(lambda: self.shown() == 1)
        (self.folder / 'stop').touch()
        self.assertEqual(first.wait(10), 0)

    def test_simultaneous_launches(self):
        children = [self.start() for _ in range(4)]
        self.wait_for(lambda: (self.folder / 'ready').exists())
        self.wait_for(lambda: sum(p.poll() is None for p in children) == 1)
        self.wait_for(lambda: self.shown() == 3)
        self.assertTrue(all(p.poll() in (None, 0) for p in children))
        (self.folder / 'stop').touch()
        for p in children:
            self.assertEqual(p.wait(10), 0)
