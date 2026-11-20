"""Проверки реальных разрешений видео, HLS-профилей и меню качества."""
from pathlib import Path
import re
import unittest
from app import transcode

ROOT = Path(__file__).resolve().parents[1]


class QualityProfilesTests(unittest.TestCase):
    def test_full_hd_has_no_4k(self):
        self.assertEqual(transcode.quality_profiles(1080), ("p144", "p240", "p720", "p1080"))
        self.assertNotIn("/p2160/", transcode.master_playlist("abcdefgh", 123, 1080))

    def test_hd_has_no_1080_or_4k(self):
        self.assertEqual(transcode.quality_profiles(720), ("p144", "p240", "p720"))

    def test_4k_enabled_only_for_4k(self):
        self.assertIn("p2160", transcode.quality_profiles(2160))
        self.assertIn("/p2160/index.m3u8", transcode.master_playlist("abcdefgh", 123, 2160))

    def test_unknown_resolution_fallback_only_low_profile(self):
        self.assertEqual(transcode.quality_profiles(0), ("p144",))
        self.assertNotIn("/p2160/", transcode.master_playlist("abcdefgh", 123, 0))

    def test_master_playlist_has_four_levels_for_1080p(self):
        body = transcode.master_playlist("abcdefgh", 123, 1080)
        self.assertTrue(body.startswith("#EXTM3U\n"))
        self.assertEqual(body.count("#EXT-X-STREAM-INF"), 4)
        self.assertIn("BANDWIDTH=", body)
        self.assertIn("CODECS=", body)


class QualityMenuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        cls.html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")

    def test_gear_replaces_checkbox(self):
        self.assertIn('id="v-quality-toggle"', self.html)
        self.assertIn('id="v-quality-menu"', self.html)
        self.assertNotIn('id="v-origchk"', self.html)
        for label in ("Авто", "Оригинал", "144p", "240p", "720p", "1080p", "4K"):
            self.assertIn(label, self.html)

    def test_auto_starts_original_and_switches_after_stall(self):
        self.assertIn("V.autoAdaptive ? 'auto' : 'orig'", self.js)
        self.assertIn("addEventListener('waiting', onVideoStall)", self.js)
        self.assertIn("switchToAdaptive()", self.js)
        self.assertIn("2500", self.js)

    def test_unavailable_resolution_hidden_in_menu(self):
        self.assertIn("button.hidden = !allowed.includes(button.dataset.quality)", self.js)
        self.assertIn('data-quality="p2160" aria-checked="false" hidden', self.html)


if __name__ == "__main__":
    unittest.main()
