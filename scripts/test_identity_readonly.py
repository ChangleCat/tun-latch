"""Tests use ordinary-user fakes only; no sudo or privileged sampling."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("identity_readonly", Path(__file__).with_name("identity-readonly.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class IdentityReadonlyTests(unittest.TestCase):
    def test_pid_digest_and_session_are_literal_and_bounded(self):
        self.assertEqual(tool.checked_pid("2147483647"), "2147483647")
        for pid in ("0", "01", "-1", "2147483648", "1 --other"):
            with self.subTest(pid=pid), self.assertRaises(Exception):
                tool.checked_pid(pid)
        for session in ("/tmp/test", "/private/var/root/tunlatch-identity.12345678/..", "/private/var/root/tunlatch-identity.1234567;"):
            with self.assertRaises(tool.Refused):
                tool.session_path(session)
        with self.assertRaises(tool.Refused):
            tool.checked_digest("A" * 64)

    def test_plan_and_root_entry_never_execute_commands(self):
        with patch.object(tool.sys, "argv", ["tool"]), patch.object(tool.subprocess, "Popen") as popen:
            tool.main()
            popen.assert_not_called()
        with patch.object(tool.sys, "argv", ["tool", "prepare", "--pid", "123"]), \
             patch.object(tool.os, "geteuid", return_value=0), patch.object(tool.subprocess, "Popen") as popen:
            with self.assertRaises(tool.Refused):
                tool.main()
            popen.assert_not_called()

    def test_unreviewed_digest_never_starts_root_operations(self):
        with patch.object(tool.sys, "argv", ["tool", "prepare", "--pid", "123"]), \
             patch.object(tool, "AUDITED_BINARY_SHA256", None), patch.object(tool.subprocess, "Popen") as popen:
            with self.assertRaises(tool.Refused):
                tool.main()
            popen.assert_not_called()

    def test_result_schema_rejects_opaque_extra_and_duplicate_keys(self):
        value = {"result":"complete_raw", "process":{"pid":123,"effective_uid":0,"birth_seconds":1,"birth_microseconds":2},
                 "fds":[{"fd":3,"kind":2}], "controls":[{"fd":3,"name":"test","id":1,"unit":2}],
                 "actual_protection":"unknown", "tun_ownership":"unknown"}
        self.assertEqual(tool.validate_result(json.dumps(value).encode(), "123")["result"], "complete_raw")
        value["controls"][0]["socket"] = 123
        with self.assertRaises(tool.Refused):
            tool.validate_result(json.dumps(value).encode(), "123")
        with self.assertRaises(tool.Refused):
            tool.validate_result(b'{"result":"incomplete","result":"complete_raw"}', "123")
        incomplete = {"result":"incomplete", "stage":"Process", "problem":"Unavailable", "errno":None,
                      "actual_protection":"unknown", "tun_ownership":"unknown"}
        self.assertEqual(tool.validate_result(json.dumps(incomplete).encode(), "123")["result"], "incomplete")

    def test_sample_marks_once_and_exposes_only_metadata(self):
        session = "/private/var/root/tunlatch-identity.12345678"
        raw = json.dumps({"result":"incomplete", "stage":"Process", "problem":"Unavailable", "errno":1,
                          "actual_protection":"unknown", "tun_ownership":"unknown"}).encode()
        class Fake:
            def __init__(self): self.calls = []
            def root(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                if args[0].endswith("identity_readonly"): return (1, raw)
                if args[0] == "/usr/bin/tee": return kwargs["data"]
                return b""
        fake = Fake()
        with patch.object(tool, "protected_parents"), patch.object(tool, "inspect", return_value=10), \
             patch.object(tool, "read_manifest", return_value="123"):
            result = tool.sample(fake, session, "a" * 64)
        self.assertEqual(fake.calls[0][0], ("/bin/mkdir", session + "/attempt"))
        self.assertEqual(fake.calls[1][0], (session + "/identity_readonly", "--pid", "123"))
        self.assertEqual(result["result"], "incomplete")
        self.assertNotIn("errno", result)

    def test_sample_rejects_both_exit_and_result_mismatches_after_recording(self):
        session = "/private/var/root/tunlatch-identity.12345678"
        incomplete = {"result":"incomplete", "stage":"Process", "problem":"Unavailable", "errno":1,
                      "actual_protection":"unknown", "tun_ownership":"unknown"}
        complete = {"result":"complete_raw", "process":{"pid":123,"effective_uid":0,
                    "birth_seconds":1,"birth_microseconds":2}, "fds":[], "controls":[],
                    "actual_protection":"unknown", "tun_ownership":"unknown"}
        class Fake:
            def __init__(self, code, raw): self.code, self.raw, self.saved = code, raw, False
            def root(self, *args, **kwargs):
                if args[0].endswith("identity_readonly"): return (self.code, self.raw)
                if args[0] == "/usr/bin/tee":
                    self.saved = True
                    return kwargs["data"]
                return b""
        for code, payload in ((0, incomplete), (1, complete)):
            fake = Fake(code, json.dumps(payload).encode())
            with patch.object(tool, "protected_parents"), patch.object(tool, "inspect", return_value=10), \
                 patch.object(tool, "read_manifest", return_value="123"):
                with self.assertRaises(tool.Refused):
                    tool.sample(fake, session, "a" * 64)
            self.assertTrue(fake.saved)

    def test_incomplete_summary_exits_nonzero(self):
        summary = {"result":"incomplete", "actual_protection":"unknown", "tun_ownership":"unknown"}
        with patch.object(tool.sys, "argv", ["tool", "run", "--session",
                                            "/private/var/root/tunlatch-identity.12345678"]), \
             patch.object(tool, "AUDITED_BINARY_SHA256", "a" * 64), \
             patch.object(tool, "sample", return_value=summary), \
             patch("builtins.print") as printed:
            with self.assertRaises(SystemExit) as failure:
                tool.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(json.loads(printed.call_args.args[0]), summary)

    def test_collect_writes_validated_diagnostic_in_fresh_private_directory(self):
        session = "/private/var/root/tunlatch-identity.12345678"
        prepared = {"session": session, "pid": 123, "sha256": "a" * 64, "size": 42, "prepared": True}
        metadata = {"session": session, "pid":123, "result":"complete_raw", "actual_protection":"unknown", "tun_ownership":"unknown"}
        diagnostic = {"result":"complete_raw", "process":{"pid":123,"effective_uid":0,"birth_seconds":1,"birth_microseconds":2},
                      "fds":[], "controls":[], "actual_protection":"unknown", "tun_ownership":"unknown"}
        runner = tool.Runner()
        with patch.object(tool, "prepare", return_value=prepared) as prepare, \
             patch.object(tool, "sample", return_value=(metadata, diagnostic)) as sample:
            result = tool.collect(runner, "a" * 64, "123")
        output = Path(result["output_path"])
        try:
            prepare.assert_called_once_with(runner, "a" * 64, "123")
            sample.assert_called_once_with(runner, session, "a" * 64, include_result=True)
            self.assertEqual(json.loads(output.read_bytes()), {"session":metadata, "diagnostic":diagnostic})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(str(output.parent.parent), "/private/tmp")
        finally:
            shutil.rmtree(output.parent)

    def test_collect_incomplete_result_is_written(self):
        session = "/private/var/root/tunlatch-identity.12345678"
        metadata = {"session": session, "result":"incomplete"}
        diagnostic = {"result":"incomplete", "stage":"Process", "problem":"Unavailable", "errno":1,
                      "actual_protection":"unknown", "tun_ownership":"unknown"}
        with patch.object(tool, "prepare", return_value={"session": session}), \
             patch.object(tool, "sample", return_value=(metadata, diagnostic)):
            result = tool.collect(tool.Runner(), "a" * 64, "123")
        output = Path(result["output_path"])
        try:
            self.assertEqual(json.loads(output.read_bytes())["diagnostic"], diagnostic)
            self.assertEqual(result["result"], "incomplete")
        finally:
            shutil.rmtree(output.parent)

    def test_collect_failure_preserves_prepared_status_without_false_success(self):
        prepared = {"session":"/private/var/root/tunlatch-identity.12345678"}
        with patch.object(tool, "prepare", return_value=prepared), \
             patch.object(tool, "sample", side_effect=tool.Refused("unknown")), \
             patch("builtins.print") as printed:
            with self.assertRaises(tool.Refused):
                tool.collect(tool.Runner(), "a" * 64, "123")
        output = Path(printed.call_args.args[0].removeprefix("诊断文件："))
        try:
            data = json.loads(output.read_bytes())
            self.assertEqual(data["stage"], "prepared")
            self.assertEqual(data["result"], "incomplete")
            self.assertEqual(data["session"], prepared)
        finally:
            shutil.rmtree(output.parent)

    def test_fresh_output_directories_are_unique_and_do_not_overwrite(self):
        runner = tool.Runner()
        fd1, output1 = tool.open_output(runner)
        fd2, output2 = tool.open_output(runner)
        try:
            self.assertNotEqual(output1, output2)
            self.assertEqual(os.fstat(fd1).st_nlink, 1)
            self.assertEqual(os.fstat(fd2).st_nlink, 1)
        finally:
            os.close(fd1)
            os.close(fd2)
            shutil.rmtree(Path(output1).parent)
            shutil.rmtree(Path(output2).parent)

    def test_tmp_acl_refuses_before_any_directory_creation(self):
        class Fake:
            def call(self, argv, **kwargs):
                self.argv = argv
                return b"drwxrwxrwt+ 1 root wheel 0 /private/tmp\n 0: everyone allow read\n"
        fake = Fake()
        with patch.object(tool.tempfile, "mkdtemp") as mkdir:
            with self.assertRaises(tool.Refused):
                tool.open_output(fake)
            mkdir.assert_not_called()
        self.assertEqual(fake.argv, ["/bin/ls", "-lde", "/private/tmp"])

    def test_cli_refuses_arbitrary_output_path(self):
        with patch.object(tool.sys, "argv", ["tool", "collect", "--pid", "123", "--output", "/tmp/test"]), \
             patch("sys.stderr"):
            with self.assertRaises(SystemExit) as failure:
                tool.main()
        self.assertEqual(failure.exception.code, 2)

    def test_collect_incomplete_exits_nonzero_after_output(self):
        summary = {"result":"incomplete", "actual_protection":"unknown", "tun_ownership":"unknown"}
        with patch.object(tool.sys, "argv", ["tool", "collect", "--pid", "123"]), \
             patch.object(tool, "AUDITED_BINARY_SHA256", "a" * 64), \
             patch.object(tool, "collect", return_value=summary) as collect, \
             patch("builtins.print") as printed:
            with self.assertRaises(SystemExit) as failure:
                tool.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(collect.call_args.args[2:], ("123",))
        self.assertEqual(json.loads(printed.call_args.args[0]), summary)

    def test_runner_preserves_accepted_exit_code_and_defaults_to_zero_only(self):
        runner = tool.Runner()
        argv = [sys.executable, "-c", "import sys; print('result'); sys.exit(1)"]
        self.assertEqual(runner.call(argv, allowed_codes=(0, 1), with_code=True), (1, b"result\n"))
        with self.assertRaises(tool.Refused):
            runner.call(argv)

    def test_runner_caps_output_and_timeout_without_kill(self):
        runner = tool.Runner()
        with self.assertRaises(tool.Refused):
            runner.call([sys.executable, "-c", "print('x'*10000)"], limit=20)
        with patch.object(tool, "COMMAND_TIME", 0.05):
            with self.assertRaises(tool.Refused):
                runner.call([sys.executable, "-c", "import time; time.sleep(.1)"])
        # Only these ordinary-user test children are waited on; this says nothing
        # about any privileged descendants of a real timed-out command.
        for child in runner.children:
            child.wait(timeout=2)

    def test_source_rejects_actual_fifo_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "fifo"
            os.mkfifo(fifo)
            with patch.object(tool, "SOURCE", fifo), self.assertRaises(tool.Refused):
                tool.source_bytes("a" * 64)

    def test_manifest_binds_fixed_pid_digest_and_boot(self):
        session = "/private/var/root/tunlatch-identity.12345678"
        digest = "a" * 64
        current = "11111111-1111-1111-1111-111111111111"
        class Fake:
            def __init__(self, data): self.data = data
            def root(self, *args, **kwargs):
                if args[0] == "/usr/bin/stat":
                    return f"0:600:Regular File:1:{len(self.data)}\n".encode()
                if args[0] == "/bin/ls": return b"-rw------- 1 root wheel 10 file\n"
                if args[0] == "/bin/cat": return self.data
                raise AssertionError(args)
        with patch.object(tool, "boot", return_value=current):
            self.assertEqual(tool.read_manifest(Fake(tool.manifest_bytes(digest, "123", current)), session, digest), "123")
            for data in (tool.manifest_bytes(digest, "123", "22222222-2222-2222-2222-222222222222"),
                         tool.manifest_bytes("b" * 64, "123", current),
                         tool.manifest_bytes(digest, "0", current),
                         tool.manifest_bytes(digest, "123", current) + b" "):
                with self.assertRaises(tool.Refused):
                    tool.read_manifest(Fake(data), session, digest)

    def test_run_rejects_new_pid_before_any_root_call(self):
        with patch.object(tool.sys, "argv", ["tool", "run", "--pid", "456", "--session",
                                            "/private/var/root/tunlatch-identity.12345678"]), \
             patch.object(tool, "AUDITED_BINARY_SHA256", "a" * 64), \
             patch.object(tool.subprocess, "Popen") as popen:
            with self.assertRaises(tool.Refused):
                tool.main()
            popen.assert_not_called()

    def test_dependencies_reject_unknown_rpaths_and_libraries(self):
        class Fake:
            def __init__(self, libs, loads): self.out = [libs, loads]
            def call(self, *_a, **_k): return self.out.pop(0)
        linker = b"cmd LC_LOAD_DYLINKER\n cmdsize 32\n name /usr/lib/dyld (offset 12)\n"
        libs = b"binary:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
        with patch.object(tool, "source_bytes"):
            tool.dependencies(Fake(libs, linker), "a" * 64)
            for badlibs, badloads in ((libs.replace(b"/usr/lib/", b"/tmp/"), linker),
                                       (libs, linker + b"cmd LC_RPATH\n")):
                with self.assertRaises(tool.Refused):
                    tool.dependencies(Fake(badlibs, badloads), "a" * 64)


if __name__ == "__main__":
    unittest.main()
