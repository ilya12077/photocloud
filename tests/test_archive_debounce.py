"""Mass deletions should not cause an index scan on every file-event batch."""
import unittest
from app.activity import ArchiveScanDebounce


class ArchiveScanDebounceTests(unittest.TestCase):
    def test_wait_for_quiet_period(self):
        gate = ArchiveScanDebounce(20, 180)
        self.assertFalse(gate.waiting(now=100))
        gate.note(now=100)
        self.assertTrue(gate.waiting(now=119))
        self.assertFalse(gate.waiting(now=120))

    def test_continuous_activity_has_maximum_delay(self):
        gate = ArchiveScanDebounce(20, 180)
        gate.note(now=100)
        gate.note(now=200)
        self.assertTrue(gate.waiting(now=210))
        gate.note(now=279)
        self.assertFalse(gate.waiting(now=280))

    def test_reset_after_scan_allows_new_batch(self):
        gate = ArchiveScanDebounce(20, 180)
        gate.note(now=100)
        gate.reset()
        self.assertFalse(gate.waiting(now=101))
        gate.note(now=102)
        self.assertTrue(gate.waiting(now=103))


if __name__ == "__main__":
    unittest.main()
