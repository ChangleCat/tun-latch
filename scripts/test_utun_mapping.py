import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("utun_mapping_operator", Path(__file__).with_name("utun-mapping.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class OperatorTests(unittest.TestCase):
    def test_fixed_profile_and_manifest(self):
        self.assertEqual(m.stage.SOURCE, m.SOURCE)
        self.assertEqual(m.SOURCE.name, "utun_mapping")
        self.assertNotEqual(m.stage.SOURCE.name, "identity_readonly")
        expected = b'{"boot":"boot-id","mode":"create-one-test-utun","sha256":"abc"}\n'
        self.assertEqual(m.manifest_bytes("abc", "boot-id"), expected)
        self.assertRaises(m.Refused, m.session_path, "/private/var/root/tunlatch-utun-mapping.abcdefgh/../other")

    def test_source_checks_digest_links_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "helper"
            source.write_bytes(b"reviewed binary")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with mock.patch.object(m, "SOURCE", source):
                self.assertEqual(m.source_bytes(digest), b"reviewed binary")
                with self.assertRaises(m.Refused):
                    m.source_bytes("0" * 64)
                os.link(source, Path(directory) / "other")
                with self.assertRaises(m.Refused):
                    m.source_bytes(digest)
                (Path(directory) / "other").unlink()
                source.unlink()
                source.symlink_to(Path(directory) / "other")
                with self.assertRaises(OSError):
                    m.source_bytes(digest)

    def test_default_plan_never_invokes_runner(self):
        with mock.patch.object(m.os, "geteuid", return_value=501), mock.patch.object(m.stage, "Runner", side_effect=AssertionError), mock.patch("sys.argv", ["operator"]), mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            m.main()
            self.assertIn("内核可能自动", out.getvalue())

    def test_collect_requires_ack_and_reviewed_hash_before_runner(self):
        for argv in (["operator", "collect"], ["operator", "collect", "--ack", m.ACK]):
            with self.subTest(argv=argv), mock.patch.object(m.os, "geteuid", return_value=501), mock.patch.object(m.stage, "Runner", side_effect=AssertionError), mock.patch.object(m, "AUDITED_BINARY_SHA256", None), mock.patch("sys.argv", argv):
                with self.assertRaises(m.Refused):
                    m.main()

    def test_rejects_root_even_for_plan(self):
        with mock.patch.object(m.os, "geteuid", return_value=0), mock.patch("sys.argv", ["operator"]):
            with self.assertRaises(m.Refused):
                m.main()

    def test_one_attempt_precedes_fixed_command_and_no_retry(self):
        class Runner:
            def __init__(self):
                self.calls = []
            def root(self, *argv, **kwargs):
                self.calls.append(argv)
                if argv[0] == "/bin/mkdir":
                    return b""
                if argv[0].endswith("/utun_mapping"):
                    raise m.Refused("timeout")
                raise AssertionError(argv)
        runner = Runner()
        session = "/private/var/root/tunlatch-utun-mapping.abcdefgh"
        with mock.patch.object(m.stage, "protected_parents"), mock.patch.object(m, "inspect", return_value=10), mock.patch.object(m, "check_manifest"):
            with self.assertRaises(m.Refused):
                m.sample(runner, session, "a" * 64)
        self.assertEqual(runner.calls, [("/bin/mkdir", session + "/attempt"),
                                        (session + "/utun_mapping", "--run-controlled-utun-mapping")])

    def test_result_requires_exact_consistent_schema(self):
        result = {"result": "complete", "stage": "complete", "error": None,
                  "observed_ifname": "utun5", "mapping": {"fd": 7, "ifname": "utun5", "unit": 6, "control_id": 4, "ifindex": 9},
                  "owned_fd_released": True, "close_errno": None, "fd_after_close": "absent",
                  "interface_after_close": "present", "kernel_may_set_interface_up": True,
                  "program_configures_addresses_routes": False, "system_side_effects_unknown": True,
                  "actual_protection": "unknown", "tun_ownership": "unknown"}
        self.assertEqual(m.validate_result(json.dumps(result).encode()), result)
        invalid = [dict(result, claimedSuccess=True), dict(result, actual_protection="active"),
                   dict(result, fd_after_close="unknown"), dict(result, owned_fd_released=False),
                   dict(result, mapping=dict(result["mapping"], ifname="utun6")),
                   dict(result, mapping=dict(result["mapping"], unit=True))]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(m.Refused):
                m.validate_result(json.dumps(item).encode())
        with self.assertRaises(m.Refused):
            m.validate_result(b'{"result":"complete","result":"incomplete"}')
        incomplete = dict(result, result="incomplete", stage="post_close", error="post_observation_incomplete",
                          fd_after_close="unknown", interface_after_close="unknown")
        self.assertEqual(m.validate_result(json.dumps(incomplete).encode()), incomplete)

    @staticmethod
    def incomplete():
        return {"result": "incomplete", "stage": "before", "error": "name_or_peer_mismatch",
                "mapping": None, "observed_ifname": "utun5", "owned_fd_released": True,
                "close_errno": None, "fd_after_close": "unknown", "interface_after_close": "present",
                "kernel_may_set_interface_up": True, "program_configures_addresses_routes": False,
                "system_side_effects_unknown": True, "actual_protection": "unknown", "tun_ownership": "unknown"}

    def test_incomplete_known_interface_and_no_mapping(self):
        result = self.incomplete()
        self.assertEqual(m.validate_result(json.dumps(result).encode()), result)
        failed_close = dict(result, owned_fd_released=None, close_errno=5)
        self.assertEqual(m.validate_result(json.dumps(failed_close).encode()), failed_close)
        result["observed_ifname"] = None
        with self.assertRaises(m.Refused):
            m.validate_result(json.dumps(result).encode())

    def test_exit_code_mismatch_refused_and_second_attempt_does_not_run_helper(self):
        result = self.incomplete()
        class Runner:
            def __init__(self):
                self.attempted = False
                self.helper_calls = 0
            def root(self, *args, **kwargs):
                if args[0] == "/bin/mkdir":
                    if self.attempted:
                        raise m.Refused("attempt exists")
                    self.attempted = True
                    return b""
                if args[0].endswith("/utun_mapping"):
                    self.helper_calls += 1
                    return 0, json.dumps(result).encode()  # incomplete must exit 1
                if args[0] == "/usr/bin/tee":
                    return kwargs["data"]
                if args[0] == "/bin/chmod":
                    return b""
                raise AssertionError(args)
        runner = Runner()
        session = "/private/var/root/tunlatch-utun-mapping.abcdefgh"
        with mock.patch.object(m.stage, "protected_parents"), mock.patch.object(m, "inspect", return_value=10), mock.patch.object(m, "check_manifest"):
            with self.assertRaises(m.Refused):
                m.sample(runner, session, "a" * 64)
            with self.assertRaises(m.Refused):
                m.sample(runner, session, "a" * 64)
        self.assertEqual(runner.helper_calls, 1)

    def test_watchdog_start_failure_is_incomplete(self):
        result = dict(self.incomplete(), stage="socket", error="watchdog_unavailable",
                      observed_ifname=None, owned_fd_released=None, interface_after_close="unknown")
        self.assertEqual(m.validate_result(json.dumps(result).encode()), result)

    def test_complete_with_failure_exit_is_refused(self):
        complete = dict(self.incomplete(), result="complete", stage="complete", error=None,
                        mapping={"fd": 7, "ifname": "utun5", "unit": 6, "control_id": 4, "ifindex": 9},
                        fd_after_close="absent", interface_after_close="absent")
        class Runner:
            def root(self, *args, **kwargs):
                if args[0] == "/bin/mkdir" or args[0] == "/bin/chmod":
                    return b""
                if args[0].endswith("/utun_mapping"):
                    return 1, json.dumps(complete).encode()
                if args[0] == "/usr/bin/tee":
                    return kwargs["data"]
                raise AssertionError(args)
        with mock.patch.object(m.stage, "protected_parents"), mock.patch.object(m, "inspect", return_value=10), mock.patch.object(m, "check_manifest"):
            with self.assertRaises(m.Refused):
                m.sample(Runner(), "/private/var/root/tunlatch-utun-mapping.abcdefgh", "a" * 64)

    def test_manifest_rejects_boot_and_mode_mismatch(self):
        class Runner:
            def __init__(self, data):
                self.data = data
            def root(self, *args, **kwargs):
                return self.data
        session = "/private/var/root/tunlatch-utun-mapping.abcdefgh"
        expected = "a" * 64
        records = [m.manifest_bytes(expected, "different-boot"),
                   m.manifest_bytes(expected, "current-boot").replace(b"create-one-test-utun", b"different-test-mode")]
        for record in records:
            with self.subTest(record=record), mock.patch.object(m, "inspect_file", return_value=len(record)), mock.patch.object(m.stage, "boot", return_value="current-boot"):
                with self.assertRaises(m.Refused):
                    m.check_manifest(Runner(record), session, expected)

    def test_collect_failure_preserves_prepared_record_and_prints_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "result.json")
            def output(_runner):
                return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), path
            with mock.patch.object(m.stage, "open_output", side_effect=output), mock.patch.object(m, "prepare", return_value=("session", 42)), mock.patch.object(m, "sample", side_effect=m.Refused("timeout")), mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                with self.assertRaises(m.Refused):
                    m.collect(object(), "a" * 64)
                self.assertIn(path, stderr.getvalue())
            saved = json.loads(Path(path).read_text())
            self.assertEqual(saved["stage"], "prepared")
            self.assertEqual(saved["session"], "session")
            self.assertEqual(saved["actual_protection"], "unknown")

    def test_incomplete_saved_and_main_exits_nonzero(self):
        result = self.incomplete()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "result.json")
            def output(_runner):
                return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), path
            with mock.patch.object(m.stage, "open_output", side_effect=output), mock.patch.object(m, "prepare", return_value=("session", 42)), mock.patch.object(m, "sample", return_value=({"session": "session"}, result)), mock.patch("sys.stderr", new_callable=io.StringIO):
                metadata, diagnostic = m.collect(object(), "a" * 64)
            self.assertEqual(json.loads(Path(path).read_text())["diagnostic"], result)
        with mock.patch.object(m.os, "geteuid", return_value=501), mock.patch.object(m, "AUDITED_BINARY_SHA256", "a" * 64), mock.patch.object(m, "collect", return_value=(metadata, diagnostic)), mock.patch("sys.argv", ["operator", "collect", "--ack", m.ACK]), mock.patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as exc:
                m.main()
            self.assertEqual(exc.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
