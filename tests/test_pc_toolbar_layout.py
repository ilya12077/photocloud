"""Адаптивная геометрия панели действий клиента ПК без перекрытия кнопок."""
import unittest

from test_offline import production_function


class ActionToolbarLayoutTests(unittest.TestCase):
    def setUp(self):
        self.plan = production_function("pc/photocloud_pc.pyw", "plan_action_groups")
        # Размеры имитируют группы Windows Tk на стандартном масштабе.
        self.sizes = [(130, 54), (185, 54), (365, 54), (145, 54), (390, 62)]

    def check_not_clipped(self, window):
        positions, total_height = self.plan(self.sizes, window)
        self.assertEqual(len(positions), len(self.sizes))
        for x, y, width, height in positions:
            self.assertGreaterEqual(x, 12)
            self.assertLessEqual(x + width, window - 12)
            self.assertLessEqual(y + height, total_height)
        for i, a in enumerate(positions):
            for b in positions[i + 1:]:
                overlap = a[0] < b[0] + b[2] and b[0] < a[0] + a[2] and a[1] < b[1] + b[3] and b[1] < a[1] + a[3]
                self.assertFalse(overlap, f"overlap: {a} and {b}")
        return positions

    def test_at_minimum_width_every_group_is_visible(self):
        self.check_not_clipped(820)

    def test_at_medium_width_every_group_is_visible(self):
        self.check_not_clipped(1100)

    def test_on_wide_window_all_groups_form_one_row(self):
        positions = self.check_not_clipped(1500)
        self.assertEqual({y for _x, y, _w, _h in positions}, {0})

    def test_narrower_width_increases_rows_without_shared_grid_columns(self):
        narrow = self.check_not_clipped(820)
        wide = self.check_not_clipped(1500)
        self.assertGreater(len({y for _x, y, _w, _h in narrow}), 1)
        self.assertEqual(len({y for _x, y, _w, _h in wide}), 1)


if __name__ == "__main__":
    unittest.main()
