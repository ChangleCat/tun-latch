import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("pf_lab_sync_operator", Path(__file__).with_name("pf-lab-sync.py"))
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


def status(phase="preflight_ready", slot="absent", baseline=None):
    report = {"scope": "unattached_filter_trial", "phase": phase,
              "anchor": "not_allocated" if phase == "preflight_ready" else "tunlatch-lab-1234abcd",
              "active_slot": slot, "actual_protection": "unknown", "recovery_qualified": False}
    if phase == "preflight_ready" or baseline is not None:
        report["baseline_sha256"] = baseline if baseline is not None else "a" * 64
    return json.dumps(report).encode()


class FakeRunner:
    def __init__(self, replies=()):
        self.calls = []
        self.replies = iter(replies)

    def root(self, *argv, **kwargs):
        self.calls.append((argv, kwargs))
        result = next(self.replies)
        return (0, result) if kwargs.get("with_code") and isinstance(result, bytes) else result


class SyncOperatorTests(unittest.TestCase):
    def test_digest_closed_without_independent_review(self):
        with mock.patch.object(operator, "AUDITED_BINARY_SHA256", None):
            with self.assertRaises(operator.Refused):
                operator.audited_digest()

    def test_stage_requires_ack_and_rechecks_status(self):
        runner = FakeRunner([status("prepared"), status("prepared"), b"submitted"])
        with mock.patch.object(operator, "inspect") as inspect:
            result = operator.execute(runner, "stage", "a" * 64, lambda _: "STAGE-PF-SYNC")
        self.assertEqual(result, b"submitted")
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual([args for args, _ in runner.calls], [
            (operator.HELPER, "status"), (operator.HELPER, "status"),
            (operator.HELPER, "stage")])

    def test_changed_status_and_wrong_ack_never_submit(self):
        for answers, ack in [([status()], "wrong"), ([status(), status("prepared")], "STAGE-PF-SYNC")]:
            with self.subTest(ack=ack):
                runner = FakeRunner(answers)
                with mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused):
                    operator.execute(runner, "stage", "a" * 64, lambda _: ack)
                self.assertNotIn((operator.HELPER, "stage"), [args for args, _ in runner.calls])

    def test_recovery_uses_distinct_confirmation(self):
        runner = FakeRunner([status("stage_intent_unsettled", "candidate")])
        with mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused):
            operator.execute(runner, "recover", "a" * 64, lambda _: "STAGE-PF-SYNC")
        self.assertEqual([args for args, _ in runner.calls], [(operator.HELPER, "status")])

    def test_existing_directory_stops_before_staging(self):
        runner = mock.Mock()
        runner.root.side_effect = operator.Refused("directory exists")
        with (mock.patch.object(operator.staging, "source_bytes", return_value=b"binary"),
              mock.patch.object(operator.stage, "dependencies"),
              mock.patch.object(operator.stage, "protected_parents"),
              mock.patch.object(operator.stage, "boot", return_value="boot")):
            with self.assertRaises(operator.Refused):
                operator.prepare(runner, "a" * 64)
        runner.root.assert_called_once_with("/bin/mkdir", "-m", "700", operator.SESSION)

    def test_helper_has_fixed_timeout_and_reports_valid_refusal(self):
        runner = FakeRunner([(1, b'{"result":"refused","reason":"PF enabled"}\n')])
        with self.assertRaisesRegex(operator.Refused, "PF enabled"):
            operator.invoke(runner, "prepare")
        self.assertEqual(runner.calls, [((operator.HELPER, "prepare"), {
            "limit": 4096, "allowed_codes": (0, 1), "with_code": True, "timeout": 45})])

    def test_invalid_nonzero_output_never_succeeds_or_echoes_untrusted_text(self):
        for raw in (b"secret", b'{"result":"refused","reason":"bad\\nline"}',
                    b'{"result":"refused","reason":"x","reason":"y"}',
                    b'{"result":"refused","reason":""}',
                    b'{"result":"refused","reason":"x","extra":1}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(operator.Refused, "拒绝信息无效"):
                    operator.invoke(FakeRunner([(1, raw)]), "status")

    def test_unapproved_helper_action_never_runs(self):
        runner = FakeRunner()
        with self.assertRaises(operator.Refused):
            operator.invoke(runner, "arbitrary")
        self.assertEqual(runner.calls, [])

    def test_runner_default_and_explicit_timeout_forwarding(self):
        runner = operator.stage.Runner()
        with mock.patch.object(runner, "call", return_value=b"") as call:
            runner.root("/usr/bin/stat")
            self.assertIsNone(call.call_args.args[-1])
            runner.root(operator.HELPER, "status", timeout=45)
            self.assertEqual(call.call_args.args[-1], 45)
        for timeout in (0, 46, float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(operator.Refused):
                runner.call([], timeout=timeout)

    def test_preflight_initializes_only_after_confirmation_and_recheck(self):
        runner = FakeRunner([status(), status(), status("prepared", baseline="a" * 64), b"submitted"])
        with mock.patch.object(operator, "inspect"):
            self.assertEqual(operator.execute(runner, "stage", "a" * 64,
                                              lambda _: "STAGE-PF-SYNC"), b"submitted")
        self.assertEqual([args[-1] for args, _ in runner.calls],
                         ["status", "status", "prepare", "stage"])

    def test_changed_or_missing_prepared_baseline_never_stages(self):
        for prepared in (status("prepared", baseline="b" * 64), status("prepared")):
            runner = FakeRunner([status(), status(), prepared])
            with (mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused)):
                operator.execute(runner, "stage", "a" * 64, lambda _: "STAGE-PF-SYNC")
            self.assertNotIn((operator.HELPER, "stage"), [args for args, _ in runner.calls])

    def test_bad_preflight_or_initialization_never_stages(self):
        invalid = json.loads(status())
        invalid["baseline_sha256"] = "bad"
        for responses in ([json.dumps(invalid).encode()],
                          [status(), status(), status("stage_outcome_unknown")]):
            runner = FakeRunner(responses)
            with mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused):
                operator.execute(runner, "stage", "a" * 64, lambda _: "STAGE-PF-SYNC")
            self.assertNotIn((operator.HELPER, "stage"), [args for args, _ in runner.calls])

    def test_main_refuses_writes_before_any_privileged_operation(self):
        for action in ("stage", "recover", "capture-unknown"):
            with (self.subTest(action=action), mock.patch.object(operator.os, "geteuid", return_value=501),
                  mock.patch.object(operator.sys, "argv", ["operator", action]),
                  mock.patch.object(operator, "audited_digest") as digest,
                  self.assertRaises(operator.Refused)):
                operator.main()
            digest.assert_not_called()

    def test_capture_unknown_requires_unrecognized_unsettled_status(self):
        for phase in ("stage_intent_unsettled", "stage_outcome_unknown", "recovery_unknown"):
            report = json.loads(status(phase, "unrecognized"))
            report.update(slot_sha256="a" * 64, slot_bytes=65536)
            runner = FakeRunner([json.dumps(report).encode(), b"captured"])
            with self.subTest(phase=phase), mock.patch.object(operator, "inspect"):
                self.assertEqual(operator.execute(runner, "capture-unknown", "b" * 64), b"captured")
            self.assertEqual(runner.calls[-1][0], (operator.HELPER, "capture-unknown"))
        for report in (status("prepared"), status("stage_outcome_unknown", "candidate")):
            runner = FakeRunner([report])
            with (mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused)):
                operator.execute(runner, "capture-unknown", "b" * 64)
            self.assertEqual(len(runner.calls), 1)

    def test_recover_refuses_unknown_slot_before_prompt(self):
        report = json.loads(status("stage_outcome_unknown", "unrecognized"))
        report.update(slot_sha256="a" * 64, slot_bytes=20)
        runner = FakeRunner([json.dumps(report).encode()])
        confirm = mock.Mock()
        with mock.patch.object(operator, "inspect"), self.assertRaises(operator.Refused):
            operator.execute(runner, "recover", "b" * 64, confirm)
        confirm.assert_not_called()

    def test_unknown_slot_metadata_must_be_bounded_and_complete(self):
        for metadata in ({}, {"slot_sha256": "a" * 64},
                         {"slot_sha256": "a" * 64, "slot_bytes": 65537},
                         {"slot_sha256": "a" * 64, "slot_bytes": True}):
            report = json.loads(status("stage_outcome_unknown", "unrecognized"))
            report.update(metadata)
            with self.subTest(metadata=metadata), self.assertRaises(operator.Refused):
                operator.status_phase(json.dumps(report).encode())

    def test_bootstrap_finishes_with_read_only_preflight(self):
        runner = FakeRunner([b"", b"binary", b"", operator.manifest("a" * 64, "boot"),
                             b"", status()])
        with (mock.patch.object(operator.staging, "source_bytes", return_value=b"binary"),
              mock.patch.object(operator.stage, "dependencies"),
              mock.patch.object(operator.stage, "protected_parents"),
              mock.patch.object(operator.stage, "boot", return_value="boot"),
              mock.patch.object(operator, "inspect", return_value=6)):
            self.assertEqual(operator.prepare(runner, "a" * 64), status())
        self.assertEqual(runner.calls[-1][0], (operator.HELPER, "status"))
        self.assertNotIn((operator.HELPER, "prepare"), [args for args, _ in runner.calls])

    def test_replace_preflight_archives_before_preparing(self):
        archive = "/private/var/root/tunlatch-pf-sync-archive.Ab123456"
        listing = b"operator-manifest.json\npf-lab-sync\n"
        runner = FakeRunner([listing, status(), listing, status(), (archive + "\n").encode(),
                             b"", listing, status(), b""])
        with (mock.patch.object(operator, "inspect") as inspect,
              mock.patch.object(operator, "directory_identity", return_value=(b"1", b"100")),
              mock.patch.object(operator.staging, "source_bytes"),
              mock.patch.object(operator.stage, "dependencies"),
              mock.patch.object(operator, "prepare", return_value=b"new") as prepare):
            self.assertEqual(operator.execute(runner, "replace-preflight", "b" * 64), b"new")
        self.assertEqual(inspect.call_count, 3)
        for call in inspect.call_args_list:
            self.assertEqual(call.args[1], operator.OLD_PREFLIGHT_SHA256)
        self.assertEqual(runner.calls[-1][0],
                         ("/bin/mv", "-n", operator.SESSION, archive + "/tunlatch-pf-sync"))
        prepare.assert_called_once_with(runner, "b" * 64)

    def test_replace_refuses_non_preflight_extra_members_or_changed_status(self):
        listing = b"operator-manifest.json\npf-lab-sync\n"
        for replies in ([b"extra\n"], [listing, status("prepared")],
                        [listing, status(), listing, status(baseline="b" * 64)]):
            runner = FakeRunner(replies)
            with (self.subTest(replies=replies), mock.patch.object(operator, "inspect"),
                  mock.patch.object(operator, "directory_identity", return_value=(b"1", b"100")),
                  mock.patch.object(operator.staging, "source_bytes"),
                  mock.patch.object(operator.stage, "dependencies"),
                  mock.patch.object(operator, "prepare") as prepare,
                  self.assertRaises(operator.Refused)):
                operator.replace_preflight(runner, "b" * 64)
            prepare.assert_not_called()
            self.assertFalse(any(args[0] in ("/usr/bin/mktemp", "/bin/mv") for args, _ in runner.calls))

    def test_replace_reports_archive_on_prepare_failure(self):
        archive = "/private/var/root/tunlatch-pf-sync-archive.Ab123456"
        listing = b"operator-manifest.json\npf-lab-sync\n"
        runner = FakeRunner([listing, status(), listing, status(), (archive + "\n").encode(),
                             b"", listing, status(), b""])
        with (mock.patch.object(operator, "inspect"),
              mock.patch.object(operator, "directory_identity", return_value=(b"1", b"100")),
              mock.patch.object(operator.staging, "source_bytes"),
              mock.patch.object(operator.stage, "dependencies"),
              mock.patch.object(operator, "prepare", side_effect=operator.Refused("failure")),
              mock.patch.object(operator.sys, "stderr") as stderr,
              self.assertRaises(operator.Refused)):
            operator.replace_preflight(runner, "b" * 64)
        self.assertIn(archive, "".join(call.args[0] for call in stderr.write.call_args_list))

    def test_replace_requires_same_filesystem_and_preserved_directory_identity(self):
        archive = "/private/var/root/tunlatch-pf-sync-archive.Ab123456"
        listing = b"operator-manifest.json\npf-lab-sync\n"
        original = (b"1", b"100")
        for identities, moved in (([original, (b"2", b"1")], False),
                                  ([original, (b"1", b"2"), original, (b"1", b"99")], True)):
            runner = FakeRunner([listing, status(), listing, status(), (archive + "\n").encode(),
                                 b"", listing, status(), b""])
            with (self.subTest(identities=identities), mock.patch.object(operator, "inspect"),
                  mock.patch.object(operator, "directory_identity", side_effect=identities),
                  mock.patch.object(operator.staging, "source_bytes"),
                  mock.patch.object(operator.stage, "dependencies"),
                  mock.patch.object(operator, "prepare") as prepare,
                  self.assertRaises(operator.Refused)):
                operator.replace_preflight(runner, "b" * 64)
            prepare.assert_not_called()
            self.assertEqual(any(args[0] == "/bin/mv" for args, _ in runner.calls), moved)


if __name__ == "__main__":
    unittest.main()
