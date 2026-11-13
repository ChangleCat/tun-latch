import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("first_flow_operator", Path(__file__).with_name("pf-lab-first-flow.py"))
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)

DIGEST = "a" * 64
PLAN = "b" * 64
ANCHOR = "tunlatch-lab-" + "1" * 32


def status(phase="prepared", **changes):
    return (json.dumps({"scope": "first_physical_flow_batch", "phase": phase, "anchor": ANCHOR,
                        "actual_protection": "unknown", "plan_sha256": PLAN, **changes}) + "\n").encode()


class FirstFlowOperator(unittest.TestCase):
    def test_unreviewed_build_or_plan_closes_privileged_entry(self):
        for binary, plan in ((None, None), (DIGEST, None), (None, PLAN)):
            with (self.subTest(binary=binary, plan=plan),
                  mock.patch.object(op, "AUDITED_BINARY_SHA256", binary),
                  mock.patch.object(op, "APPROVED_PLAN_SHA256", plan),
                  self.assertRaises(op.Refused)):
                op.approved()

    def test_frozen_input_binds_interface_and_all_three_phases(self):
        cases = []
        for index, (family, protocol) in enumerate(op.flow.ORDER):
            src, dst = ("192.0.2.1", "192.0.2.2") if family == "ipv4" else ("[2001:db8::1]", "[2001:db8::2]")
            cases.append({"family": family, "protocol": protocol, "source": f"{src}:{55000 + index}",
                          "destination": f"{dst}:443"})
        raw = json.dumps(op.flow.peer.generate_controls({"cases": cases})).encode()
        data = op.frozen_input(raw, "en0")
        self.assertEqual(json.loads(data), {"interface": "en0", "phases": json.loads(raw)})
        self.assertNotEqual(data, op.frozen_input(raw, "en1"))
        for interface in ("utun0", "en00", "en0;bad"):
            with self.subTest(interface=interface), self.assertRaises(op.Refused):
                op.frozen_input(raw, interface)
        with self.assertRaises((ValueError, op.Refused)):
            op.frozen_input(b'{"before":{}}', "en0")

    def test_report_is_strict_and_rejects_invalid_or_duplicate_fields(self):
        self.assertEqual(op.report(status())["phase"], "prepared")
        for raw in (status("other"), status(anchor="tunlatch-lab-" + "0" * 32),
                    status(actual_protection="active"), status(extra=True),
                    b'{"scope":"a","scope":"b"}'):
            with self.subTest(raw=raw), self.assertRaises(op.Refused):
                op.report(raw)

    def test_stage_requires_confirmation_and_unchanged_protected_status(self):
        runner = mock.Mock()
        with (mock.patch.object(op.base, "inspect"),
              mock.patch.object(op, "invoke", side_effect=[status(), status(), status("hook_and_filter_verified")]) as invoke):
            result = op.execute(runner, "stage", DIGEST, PLAN, confirm=lambda _: "STAGE-PF-FIRST-FLOW")
        self.assertEqual(op.report(result)["phase"], "hook_and_filter_verified")
        self.assertEqual(invoke.call_args_list[-1], mock.call(runner, "stage", b"STAGE-PF-FIRST-FLOW\n"))
        with (mock.patch.object(op.base, "inspect"),
              mock.patch.object(op, "invoke", side_effect=[status(), status("unsettled")]) as invoke,
              self.assertRaises(op.Refused)):
            op.execute(runner, "stage", DIGEST, PLAN, confirm=lambda _: "STAGE-PF-FIRST-FLOW")
        self.assertEqual(invoke.call_count, 2)

    def test_activate_and_recover_use_the_reference_held_phase(self):
        runner = mock.Mock()
        for action, before, after in (
            ("activate", "hook_and_filter_verified", "reference_held"),
            ("recover", "reference_held", "restored"),
        ):
            ack = op.CONFIRMATIONS[action][0]
            with (mock.patch.object(op.base, "inspect"),
                  mock.patch.object(op, "invoke", side_effect=[status(before), status(before), status(after)]) as invoke):
                result = op.execute(runner, action, DIGEST, PLAN, confirm=lambda _: ack)
            self.assertEqual(op.report(result)["phase"], after)
            self.assertEqual(invoke.call_args_list[-1], mock.call(runner, action, (ack + "\n").encode()))

    def test_fixed_commands_fit_the_shared_runner_budget(self):
        runner = mock.Mock()
        runner.root.return_value = (0, status())
        for action in ("prepare", "status", "stage", "activate", "recover"):
            self.assertEqual(op.invoke(runner, action), status())
            self.assertLessEqual(runner.root.call_args.kwargs["timeout"], 45)

    def test_recovery_is_separate_and_never_accepts_plan_path(self):
        runner = mock.Mock()
        with (mock.patch.object(op.base, "inspect"),
              mock.patch.object(op, "invoke", side_effect=[status("unsettled"), status("unsettled"),
                                                            status("restored")]) as invoke):
            op.execute(runner, "recover", DIGEST, PLAN, confirm=lambda _: "RECOVER-PF-FIRST-FLOW")
        self.assertEqual(invoke.call_args_list[-1], mock.call(runner, "recover", b"RECOVER-PF-FIRST-FLOW\n"))
        with (mock.patch.object(op.base, "inspect"), mock.patch.object(op, "invoke", return_value=status()),
              self.assertRaises(op.Refused)):
            op.execute(runner, "recover", DIGEST, PLAN, confirm=lambda _: "RECOVER-PF-FIRST-FLOW")

    def test_prepare_does_not_run_helper_when_plan_or_boot_mismatches(self):
        runner = mock.Mock()
        data = b"example"
        with (mock.patch.object(op.base, "install") as install, mock.patch.object(op, "invoke") as invoke,
              self.assertRaises(op.Refused)):
            op.execute(runner, "prepare", DIGEST, PLAN, data=data, boot="boot")
        install.assert_not_called()
        invoke.assert_not_called()
        with (mock.patch.object(op.base, "install"), mock.patch.object(op.stage, "boot", return_value="other"),
              mock.patch.object(op, "invoke") as invoke, self.assertRaises(op.Refused)):
            op.execute(runner, "prepare", DIGEST, hashlib.sha256(data).hexdigest(), data=data, boot="boot")
        invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
