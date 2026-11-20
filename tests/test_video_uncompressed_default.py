"""Регрессионные проверки стандартного режима видео в веб-просмотрщике."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VideoUncompressedDefaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        cls.html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")

    def test_checkbox_named_uncompressed_and_initially_checked(self):
        match = re.search(r'<label[^>]+id="v-origwrap"[^>]*>(.*?)</label>', self.html, re.S)
        self.assertIsNotNone(match)
        label = match.group(1)
        self.assertRegex(label, r'id="v-origchk"[^>]*\bchecked\b')
        self.assertIn("без сжатия", label)

    def test_playback_defaults_to_original_until_explicitly_switched_off(self):
        self.assertIn("const orig = !canTranscode || store('pc.vraw') !== '0';", self.js)
        self.assertIn("store('pc.vraw', e.target.checked ? '1' : '0');", self.js)
        self.assertNotIn("store('pc.vorig')", self.js)

    def test_unchecked_video_uses_compressed_hls(self):
        self.assertIn("if (orig) { v.src = origUrl(ph, false); return; }", self.js)
        self.assertRegex(self.js, r"/eco/index\.m3u8")


if __name__ == "__main__":
    unittest.main()
