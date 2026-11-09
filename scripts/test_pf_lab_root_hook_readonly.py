import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

_spec = importlib.util.spec_from_file_location(
    "root_hook_readonly_operator", Path(__file__).with_name("pf-lab-root-hook-readonly.py"))
op = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(op)

RESULT = {"result": "readback_matched", "scope": "root_filter_read_layout", "rules": 1,
          "build": "25G83", "root_rules_sha256": "a" * 64}


class RootHookReadonlyOperator(unittest.TestCase):
    def test_missing_digest_or_wrong_action_refuses_before_root(self):
        with mock.patch.object(op, "AUDITED_BINARY_SHA256", None), self.assertRaises(op.Refused):
            op.expected_digest()
        runner = mock.Mock()
        for action in ("stage", "recover", "status"):
            with self.subTest(action=action), self.assertRaises(op.Refused):
                op.execute(runner, action, "a" * 64)
        self.assertEqual(runner.mock_calls, [])

    def test_result_requires_a_nonempty_independent_comparison(self):
        self.assertEqual(op.parse_result(json.dumps(RESULT).encode()), RESULT)
        for change in ({"rules": 0}, {"rules": True}, {"rules": 257}, {"build": "25G84"},
                       {"ticket": 10}, {"root_rules_sha256": "invalid"}):
            with self.subTest(change=change), self.assertRaises(op.Refused):
                op.parse_result(json.dumps({**RESULT, **change}).encode())
        with self.assertRaises(op.Refused):
            op.parse_result(b'{"result":"readback_matched","result":"readback_matched"}')

    def test_prepare_and_check_only_invoke_the_fixed_readonly_action(self):
        runner = mock.Mock()
        runner.root.return_value = (0, json.dumps(RESULT).encode())
        digest = "a" * 64
        for action in ("prepare", "check"):
            with (self.subTest(action=action), mock.patch.object(op.base, "install") as install,
                  mock.patch.object(op.base, "inspect") as inspect):
                self.assertEqual(op.execute(runner, action, digest), RESULT)
                runner.root.assert_called_once_with(
                    op.HELPER, "check", limit=op.base.HELPER_OUTPUT_LIMIT,
                    allowed_codes=(0, 1), with_code=True, timeout=25)
                self.assertEqual(inspect.call_count, 1 if action == "prepare" else 2)
                self.assertEqual(install.call_count, 1 if action == "prepare" else 0)
                runner.reset_mock()

    def test_install_failure_never_starts_helper(self):
        runner = mock.Mock()
        with (mock.patch.object(op.base, "install", side_effect=op.Refused("existing directory")),
              self.assertRaisesRegex(op.Refused, "existing directory")):
            op.execute(runner, "prepare", "a" * 64)
        self.assertEqual(runner.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
