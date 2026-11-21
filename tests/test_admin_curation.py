"""Права на изменения избранного и групп: только администратор."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AdminCurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((ROOT / "app/main.py").read_text(encoding="utf-8"))
        cls.frontend = (ROOT / "app/static/app.js").read_text(encoding="utf-8")

    def test_curation_routes_require_admin_dependency(self):
        for name in ("group_photos", "ungroup_photos", "star_photos"):
            fn = next(n for n in self.tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
            # Проверяем именно FastAPI Depends(require_admin), не только визуальное меню.
            dep = fn.args.defaults[-1]
            self.assertIsInstance(dep, ast.Call)
            self.assertIsInstance(dep.func, ast.Name)
            self.assertEqual(dep.func.id, "Depends")
            self.assertEqual(len(dep.args), 1)
            self.assertEqual(getattr(dep.args[0], "id", ""), "require_admin",
                             f"{name} must block non-admin requests")

    def test_hidden_actions_for_regular_users(self):
        self.assertIn("const canCurate = me.role === 'admin';", self.frontend)
        self.assertIn("$('sel-group').hidden = HID || !canCurate;", self.frontend)
        self.assertIn("$('sel-star').hidden = HID || STARRED || !canCurate;", self.frontend)
        self.assertIn("$('sel-unstar').hidden = !STARRED || !canCurate;", self.frontend)
        self.assertIn("$('v-star').hidden = HID || !canCurate;", self.frontend)
        self.assertIn("st.me.role !== 'admin'", self.frontend)

    def test_read_only_star_list_stays_available(self):
        fn = next(n for n in self.tree.body if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "starred_ids")
        self.assertEqual(fn.args.defaults[-1].args[0].id, "require_user")


if __name__ == "__main__":
    unittest.main()
