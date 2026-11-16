"""Regression tests: manual reindex must not report success when no scan starts."""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "app" / "main.py"


class HTTPError(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def call_reindex(pc_up, scan_started):
    """Execute the production endpoint with its external dependencies mocked."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "reindex")
    fn.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    starts = []

    async def is_up():
        return pc_up

    def start_build(*args):
        starts.append(args)
        return scan_started

    scope = {
        "PC": SimpleNamespace(is_up=is_up),
        "library": SimpleNamespace(start_build=start_build),
        "storage": object(),
        "_index_error": lambda _: None,
        "HTTPException": HTTPError,
        "JSONResponse": lambda data: data,
        "no_store": lambda response: response,
        "Depends": lambda dependency: None,
        "require_admin": object(),
        "Session": object,
    }
    exec(compile(module, str(SOURCE), "exec"), scope)
    try:
        return asyncio.run(scope["reindex"]()), len(starts), None
    except HTTPError as exc:
        return None, len(starts), exc


class ReindexTests(unittest.TestCase):
    def test_success_only_when_scan_started(self):
        body, calls, error = call_reindex(True, True)
        self.assertEqual(body, {"ok": True})
        self.assertEqual(calls, 1)
        self.assertIsNone(error)

    def test_busy_returns_conflict_not_success(self):
        body, calls, error = call_reindex(True, False)
        self.assertIsNone(body)
        self.assertEqual(calls, 1)
        self.assertEqual(error.status_code, 409)
        self.assertEqual(error.detail, "Сканирование уже выполняется")

    def test_offline_pc_does_not_attempt_scan(self):
        body, calls, error = call_reindex(False, True)
        self.assertIsNone(body)
        self.assertEqual(calls, 0)
        self.assertEqual(error.status_code, 409)
        self.assertEqual(error.detail, "pc down")


if __name__ == "__main__":
    unittest.main()
