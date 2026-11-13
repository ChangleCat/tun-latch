import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("first_flow_operator", Path(__file__).with_name("pf-lab-first-flow.py"))
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)

DIGEST = "a" * 64
PLAN = "b" * 64
ANCHOR = "tunlatch-lab-" + "1" * 32
BATCH = b'{"interface":"en0","phases":{}}'


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

    def test_counters_require_held_reference_and_exact_session(self):
        runner = mock.Mock()
        with (mock.patch.object(op.base, "inspect"),
              mock.patch.object(op, "invoke", side_effect=[
                  status("reference_held"), status("counters_before_recorded")]) as invoke):
            result = op.execute(runner, "counters-before", DIGEST, PLAN)
        self.assertEqual(op.report(result)["phase"], "counters_before_recorded")
        self.assertEqual(invoke.call_args_list[-1], mock.call(runner, "counters-before"))
        with (mock.patch.object(op.base, "inspect"),
              mock.patch.object(op, "invoke", return_value=status("hook_and_filter_verified")) as invoke,
              self.assertRaises(op.Refused)):
            op.execute(runner, "counters-after", DIGEST, PLAN)
        invoke.assert_called_once_with(runner, "status")

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

    def test_attended_run_orders_phases_and_recovery(self):
        runner = mock.Mock()
        capture = mock.Mock()
        capture.child.poll.return_value = None
        capture.finish.return_value = status("capture_recorded")
        states = iter(["prepared", "prepared", "reference_held", "reference_held",
                       "restored", "restored"])
        actions = []

        def execute(_runner, action, *_args, **_kwargs):
            actions.append(action)
            return status(next(states) if action == "status" else "prepared")

        output = mock.Mock()
        output.buffer = io.BytesIO()
        def send_result(phase, _role):
            print(json.dumps({"role": "sender", "phase": phase}))
            return 1 if phase == "blocked" else 0
        with (mock.patch.object(op, "execute", side_effect=execute),
              mock.patch.object(op, "Capture", return_value=capture),
              mock.patch.object(op.flow, "preflight", return_value={"boot": "boot"}) as preflight,
              mock.patch.object(op.flow.peer, "select_phase", side_effect=lambda _doc, phase: phase),
              mock.patch.object(op.flow.peer, "run", side_effect=send_result) as send,
              mock.patch.object(op.sys, "stdout", output)):
            op.attended_run(runner, DIGEST, PLAN, BATCH, "boot",
                            confirm=lambda prompt: prompt.split("请输入 ")[1].split("：")[0])
        self.assertEqual([call.args[0] for call in send.call_args_list], ["before", "blocked", "after"])
        self.assertEqual(preflight.call_count, 3)
        self.assertEqual([action for action in actions if action != "status"],
                         ["prepare", "stage", "activate", "counters-before", "counters-after", "recover"])
        capture.finish.assert_called_once()

    def test_capture_uses_fixed_command_and_two_checked_reports(self):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        child = mock.Mock()
        child.stdin = io.BytesIO()
        child.stdout = os.fdopen(out_read, "rb", buffering=0)
        child.stderr = os.fdopen(err_read, "rb", buffering=0)
        child.wait.return_value = 0
        try:
            os.write(out_write, status("capture_ready"))
            with (mock.patch.object(op.base, "inspect"),
                  mock.patch.object(op.subprocess, "Popen", return_value=child) as popen):
                capture = op.Capture(mock.Mock(), DIGEST, PLAN, ANCHOR)
                capture.ready()
                os.write(out_write, status("capture_recorded"))
                os.close(out_write)
                out_write = None
                os.close(err_write)
                err_write = None
                self.assertEqual(op.report(capture.finish())["phase"], "capture_recorded")
            self.assertEqual(popen.call_args.args[0], op.stage.ROOT + [op.HELPER, "capture"])
            self.assertTrue(child.stdin.closed)
        finally:
            child.stdout.close()
            child.stderr.close()
            if out_write is not None:
                os.close(out_write)
            if err_write is not None:
                os.close(err_write)

    def test_uncertain_writer_does_not_trigger_recovery(self):
        capture = mock.Mock()
        capture.child.poll.return_value = None
        capture.finish.return_value = status("capture_recorded")
        actions = []

        def execute(_runner, action, *_args, **_kwargs):
            actions.append(action)
            if action == "stage":
                raise op.Refused("unknown writer")
            return status()

        with (mock.patch.object(op, "execute", side_effect=execute),
              mock.patch.object(op, "Capture", return_value=capture),
              mock.patch.object(op.flow, "preflight", return_value={"boot": "boot"}),
              mock.patch.object(op.flow.peer, "select_phase", return_value=[]),
              mock.patch.object(op.flow.peer, "run", return_value=0),
              self.assertRaises(op.Refused)):
            op.attended_run(mock.Mock(), DIGEST, PLAN, BATCH, "boot",
                            confirm=lambda prompt: prompt.split("请输入 ")[1].split("：")[0])
        self.assertNotIn("recover", actions)

    def test_peer_prompt_interrupt_recovers_before_stopping_capture(self):
        capture = mock.Mock()
        capture.child.poll.return_value = None
        capture.finish.return_value = status("capture_recorded")
        actions = []
        states = iter(["prepared", "prepared", "reference_held"])

        def execute(_runner, action, *_args, **_kwargs):
            actions.append(action)
            return status(next(states) if action == "status" else "prepared")

        def confirm(prompt):
            if "PEER-READY-BLOCKED" in prompt:
                raise EOFError
            return prompt.split("请输入 ")[1].split("：")[0]

        capture.finish.side_effect = lambda: (actions.append("finish"), status("capture_recorded"))[1]
        with (mock.patch.object(op, "execute", side_effect=execute),
              mock.patch.object(op, "Capture", return_value=capture),
              mock.patch.object(op.flow, "preflight", return_value={"boot": "boot"}),
              mock.patch.object(op.flow.peer, "select_phase", return_value=[]),
              mock.patch.object(op.flow.peer, "run", return_value=0),
              self.assertRaises(EOFError)):
            op.attended_run(mock.Mock(), DIGEST, PLAN, BATCH, "boot", confirm=confirm)
        self.assertLess(actions.index("recover"), actions.index("finish"))


if __name__ == "__main__":
    unittest.main()
