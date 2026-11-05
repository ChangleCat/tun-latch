"""Ordinary-user checks; never invoke sudo or a PF kernel operation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("reference", Path(__file__).with_name("pf-lab-reference.py"))
ref = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ref)


class ReferenceTests(unittest.TestCase):
    def test_only_complete_unique_canonical_tokens(self):
        for value in (1, 12345, 2**64-1):
            for prefix in (b"", b"^D\x08\x08"):
                data = prefix + ref.NOTICE.encode() + f"pf enabled\r\nToken : {value}\r\n".encode()
                self.assertEqual(ref.parse_token(data), str(value))
        bad = [b"", b"pf enabled\n", b"Token : 1\n", b"pf enabled\nToken : 0\n",
               b"pf enabled\nToken : 01\n", b"pf enabled\nToken : -1\n",
               b"pf enabled\nToken : 1", b"pf enabled\nToken : 18446744073709551616\n",
               b"pf enabled\nToken : 1\nToken : 2\n", b"pf enabled\nToken : 1\nerror\n",
               b"^D\x08\x08^D\x08\x08pf enabled\nToken : 1\n", b"x"*4097]
        for data in bad:
            with self.subTest(data=data[:60]), self.assertRaises(ref.Refused):
                ref.parse_token(data)

    def test_paths_cannot_inject_or_adopt_arbitrary_records(self):
        self.assertEqual(ref.session_path("/var/root/tunlatch-pf-reference.aB123456"),
                         "/var/root/tunlatch-pf-reference.aB123456")
        for value in ("/tmp/session", "/var/root/tunlatch-pf-reference.1234567",
                      "/var/root/tunlatch-pf-reference.12345678/..",
                      "/var/root/tunlatch-pf-reference.12345678;id", "-X 1"):
            with self.assertRaises(ref.Refused):
                ref.session_path(value)

    def test_zero_exit_with_error_is_not_success(self):
        argv = ref.PREFIX + ["/sbin/pfctl", "-s", "info"]
        for error in (b"pfctl: DIOCGETRULES: Invalid argument\n",
                      ref.NOTICE.encode()+b"kernel error\n"):
            with patch.object(ref.subprocess, "run", return_value=subprocess.CompletedProcess(argv, 0, b"", error)):
                with self.assertRaises(ref.Refused):
                    ref.command(argv)
        with patch.object(ref.subprocess, "run", return_value=subprocess.CompletedProcess(argv, 0, b"ok", ref.NOTICE.encode())):
            self.assertEqual(ref.command(argv), b"ok")

    def test_release_argv_is_only_exact_token_under_system_recorder(self):
        with patch.object(ref, "command", return_value=b"") as run:
            ref.record("/var/root/tunlatch-pf-reference.12345678", "release.txt", "/sbin/pfctl", "-X", "12345")
            self.assertEqual(run.call_args.args[0], ref.PREFIX + ["/usr/bin/script", "-q", "-F",
                "/var/root/tunlatch-pf-reference.12345678/release.txt", "/sbin/pfctl", "-X", "12345"])

    def test_wrong_boot_or_directory_or_acl_stops(self):
        s = "/var/root/tunlatch-pf-reference.12345678"
        recorded = b"11111111-1111-1111-1111-111111111111\n"
        current = b"22222222-2222-2222-2222-222222222222\n"
        cases = [(b"501:700:Directory\n", b"drwx------ 2 root wheel 64 path\n"),
                 (b"0:700:Symbolic Link\n", b"drwx------ 2 root wheel 64 path\n"),
                 (b"0:700:Directory\n", b"drwx------+ 2 root wheel 64 path\n 0: acl\n"),
                 (b"0:700:Directory\n", b"drwx------ 2 root wheel 64 path\n")]
        for meta, listing in cases:
            with patch.object(ref, "root", side_effect=[meta, listing]), \
                 patch.object(ref, "protected_record", return_value=recorded), \
                 patch.object(ref, "boot", return_value=current), self.assertRaises(ref.Refused):
                ref.inspect(s)

    def test_release_requires_new_explicit_takeover_and_never_retries(self):
        s = "/var/root/tunlatch-pf-reference.12345678"
        for already, answer in ((True, "TAKEOVER-AND-RELEASE"), (False, "no")):
            with patch.object(ref.sys, "argv", ["tool", "release", s]), \
                 patch.object(ref, "command", return_value=b""), \
                 patch.object(ref, "inspect"), patch.object(ref, "exists", return_value=already), \
                 patch.object(ref, "protected_record", return_value=b"pf enabled\nToken : 1\n"), \
                 patch("builtins.input", return_value=answer), patch.object(ref, "root") as root, \
                 self.assertRaises(ref.Refused):
                ref.main()
            root.assert_not_called()

    def test_missing_reply_does_not_infer_token_from_global_inventory(self):
        with patch.object(ref.sys, "argv", ["tool", "release", "/var/root/tunlatch-pf-reference.12345678"]), \
             patch.object(ref, "command", return_value=b""), patch.object(ref, "inspect"), \
             patch.object(ref, "exists", return_value=False), \
             patch.object(ref, "protected_record", return_value=b"pf enabled\n"), \
             patch.object(ref, "root") as root, self.assertRaises(ref.Refused):
            ref.main()
        root.assert_not_called()

    def test_release_once_and_independent_observation_without_global_cleanup(self):
        session = "/var/root/tunlatch-pf-reference.12345678"
        for info, success in ((b"Status: Disabled for 0 days\n", True),
                              (b"Status: Enabled for 0 days\n", False)):
            with patch.object(ref.sys, "argv", ["tool", "release", session]), \
                 patch.object(ref, "command", return_value=b""), patch.object(ref, "inspect"), \
                 patch.object(ref, "exists", return_value=False), \
                 patch.object(ref, "protected_record", return_value=b"pf enabled\nToken : 12345\n"), \
                 patch("builtins.input", return_value="TAKEOVER-AND-RELEASE"), \
                 patch.object(ref, "record", return_value=b"") as record, \
                 patch.object(ref, "root", side_effect=[b"", info, b"No pf starter references held\n"]) as root:
                if success:
                    ref.main()
                else:
                    with self.assertRaises(ref.Refused):
                        ref.main()
                self.assertEqual([c.args for c in record.call_args_list], [
                    (session, "release.txt", "/sbin/pfctl", "-X", "12345"),
                    (session, "after-info.txt", "/sbin/pfctl", "-s", "info"),
                    (session, "after-references.txt", "/sbin/pfctl", "-s", "References")])
                self.assertEqual([c.args for c in root.call_args_list], [
                    ("/bin/mkdir", session+"/release-attempt"),
                    ("/sbin/pfctl", "-s", "info"), ("/sbin/pfctl", "-s", "References")])

    def test_root_entry_is_rejected_before_any_system_operation(self):
        with patch.object(ref.sys, "argv", ["tool", "prepare"]), \
             patch.object(ref.os, "geteuid", return_value=0), \
             patch.object(ref, "command") as command, self.assertRaises(ref.Refused):
            ref.main()
        command.assert_not_called()

    def test_installed_recorder_preserves_reply_and_child_exit_without_root(self):
        with tempfile.TemporaryDirectory(prefix="tunlatch-reference-recorder.") as tmp:
            path = Path(tmp)/"reply"
            result = subprocess.run(["/usr/bin/env", "-i", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                                     "/usr/bin/script", "-q", "-F", str(path), "/usr/bin/printf",
                                     "pf enabled\nToken : 12345\n"], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(ref.parse_token(result.stdout), "12345")
            self.assertEqual(ref.parse_token(path.read_bytes()), "12345")
            result = subprocess.run(["/usr/bin/script", "-q", "-F", str(Path(tmp)/"failure"),
                                     "/usr/bin/false"], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_reviewed_capture_and_changed_leaf_missing_inventory_old_capture(self):
        fixture = Path(__file__).parents[1]/"docs/development-plan-2026-11-02/evidence/W05/operator-preflight/literal-queries/observed/capture"
        # Local ignored evidence is optional; published tests must remain portable.
        if not fixture.exists():
            self.skipTest("local operator evidence not included in checkout")
        intent = json.loads((fixture/"collection-intent.json").read_text())
        with patch.object(ref.time, "time", return_value=intent["started_unix"]+1):
            self.assertEqual(ref.check_capture(fixture), 49)
        with patch.object(ref.time, "time", return_value=intent["started_unix"]+121):
            with self.assertRaises(ref.Refused):
                ref.check_capture(fixture)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            for p in fixture.iterdir():
                (dest/p.name).write_bytes(p.read_bytes())
            q = json.loads((dest/"query-07.json").read_text())
            q["stdout"] = "block drop all\n"
            q["stdout_sha256"] = ref.hashlib.sha256(q["stdout"].encode()).hexdigest()
            (dest/"query-07.json").write_text(json.dumps(q))
            with patch.object(ref.time, "time", return_value=intent["started_unix"]+1), self.assertRaises(ref.Refused):
                ref.check_capture(dest)

    def test_portable_capture_rejects_leaf_tables_directory_errors_and_stale_data(self):
        def fixture(path):
            names = ["com.apple"]
            kinds = ["Rules", "Nat", "Anchors", 'AnchorRules(Literal("com.apple"))',
                     'AnchorNat(Literal("com.apple"))', 'AnchorTables(Literal("com.apple"))',
                     "Interfaces", "Info", "References", "Rules", "Nat", "References", "Anchors"]
            outputs = ['anchor "com.apple/*" all\n', "", "com.apple\n", "", "", "",
                       "lo0\n", "Status: Disabled for 0 days\n", "No pf starter references held\n",
                       'anchor "com.apple/*" all\n', "", "No pf starter references held\n", "com.apple\n"]
            entries = []
            for i, (kind, output) in enumerate(zip(kinds, outputs), 1):
                q = dict(query=kind, stdout=output, stderr=ref.NOTICE, diagnostic="captured",
                         truncated=False, capture_failed=False, command_tree_reclaimed=True, reason="Success")
                for stream in ("stdout", "stderr"):
                    q[stream+"_sha256"] = ref.hashlib.sha256(q[stream].encode()).hexdigest()
                name = f"query-{i:02}.json"
                (path/name).write_text(json.dumps(q))
                entries.append(dict(file=name, status="captured"))
            (path/"summary.json").write_text(json.dumps(dict(result="captured_requires_review", literal_anchor_count=len(names), queries=entries)))
            (path/"collection-intent.json").write_text(json.dumps(dict(started_unix=int(time.time()))))
        for index, output in ((4, "block drop all\n"), (6, "existing_table\n"),
                              (13, "different\n"), (8, "Status: Enabled for 0 days\n"),
                              (9, "unknown reference format\n"), (7, "lo0 (skip)\n")):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)
                fixture(path)
                self.assertEqual(ref.check_capture(path), 13)
                name = path/f"query-{index:02}.json"
                q = json.loads(name.read_text())
                q["stdout"] = output
                q["stdout_sha256"] = ref.hashlib.sha256(output.encode()).hexdigest()
                name.write_text(json.dumps(q))
                with self.subTest(index=index), self.assertRaises(ref.Refused):
                    ref.check_capture(path)


if __name__ == "__main__":
    unittest.main()
