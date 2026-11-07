import argparse
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("correlate", Path(__file__).with_name("identity-correlate.py"))
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)
PID = "123"
HASH = "a" * 40
SHA = "b" * 64
SESSION = "/private/var/root/tunlatch-identity-correlate.abcdefgh"


def candidate():
    return {"result": "candidate", "basis": "utun_control_unit_minus_one",
            "process": {"pid": 123, "effective_uid": 0, "birth_seconds": 1, "birth_microseconds": 2},
            "fd": 3, "control_id": 4, "unit": 5, "ifname": "utun4", "ifindex": 6,
            "sampling_milliseconds": 7, "matched_expected_cdhash": HASH,
            "tun_ownership": "unknown", "actual_protection": "unknown", "authorization": "none"}


def raw(value):
    return json.dumps(value).encode()


class CorrelateTests(unittest.TestCase):
    def test_without_audited_digest_no_privileged_attempt_can_start(self):
        args = ["tool", "collect", "--pid", PID, "--cdhash", HASH, "--ack", operator.ACK]
        with patch.object(operator.sys, "argv", args), patch.object(operator, "AUDITED_BINARY_SHA256", None), patch.object(operator, "collect") as collect:
            with self.assertRaises(operator.Refused):
                operator.main()
            collect.assert_not_called()

    def test_cdhash_is_nonzero_fixed_lower_hex(self):
        for value in ("0" * 40, "A" * 40, "a" * 39, "a" * 41):
            with self.assertRaises(argparse.ArgumentTypeError):
                operator.checked_cdhash(value)
        self.assertEqual(operator.checked_cdhash(HASH), HASH)

    def test_manifest_binds_all_fields(self):
        value = json.loads(operator.manifest_bytes(SHA, PID, HASH, "boot"))
        self.assertEqual(value, {"sha256": SHA, "pid": 123, "cdhash": HASH,
                                 "boot": "boot", "mode": operator.MODE})

    def test_candidate_and_unavailable_validation(self):
        self.assertEqual(operator.validate_result(raw(candidate()), PID, HASH), candidate())
        unavailable = {"result": "unavailable", "reason": "target_uid_mismatch", "tun_ownership": "unknown",
                       "actual_protection": "unknown", "authorization": "none"}
        self.assertEqual(operator.validate_result(raw(unavailable), PID, HASH), unavailable)
        for reason in ("root_observer", "arbitrary", ""):
            unavailable["reason"] = reason
            with self.assertRaises(operator.Refused):
                operator.validate_result(raw(unavailable), PID, HASH)

    def test_rejects_boundary_and_identity_mismatches(self):
        for key, value in (("authorization", "allowed"), ("actual_protection", "active"),
                           ("matched_expected_cdhash", "c" * 40), ("ifname", "utun5"),
                           ("unit", True), ("sampling_milliseconds", 1000), ("extra", 1)):
            obj = candidate()
            obj[key] = value
            with self.subTest(key=key), self.assertRaises(operator.Refused):
                operator.validate_result(raw(obj), PID, HASH)
        obj = candidate()
        obj["process"]["effective_uid"] = 501
        with self.assertRaises(operator.Refused):
            operator.validate_result(raw(obj), PID, HASH)
        with self.assertRaises(operator.Refused):
            operator.validate_result(raw(candidate()).replace(b'"result": "candidate"', b'"result": "candidate", "result": "candidate"'), PID, HASH)

    def test_attempt_precedes_exact_helper_and_mismatch_fails(self):
        class Runner:
            def __init__(self):
                self.calls = []
            def root(self, *args, **kwargs):
                self.calls.append(args)
                if args[0].endswith("/identity_correlate"):
                    return 1, raw(candidate())
                if args[0] == "/usr/bin/tee":
                    return kwargs["data"]
                return b""
        runner = Runner()
        with patch.object(operator.stage, "protected_parents"), patch.object(operator, "inspect", return_value=10), patch.object(operator, "check_manifest"):
            with self.assertRaises(operator.Refused):
                operator.sample(runner, SESSION, SHA, PID, HASH)
        self.assertEqual(runner.calls[0], ("/bin/mkdir", SESSION + "/attempt"))
        self.assertEqual(runner.calls[1], (SESSION + "/identity_correlate", "--pid", PID, "--cdhash", HASH))

    def test_session_path_and_manifest_mismatch(self):
        self.assertEqual(operator.session_path(SESSION), SESSION)
        with self.assertRaises(operator.Refused):
            operator.session_path(SESSION + "/../elsewhere")
        class Runner:
            def root(self, *args, **kwargs):
                return operator.manifest_bytes(SHA, "124", HASH, "boot")
        with patch.object(operator, "inspect_file", return_value=len(operator.manifest_bytes(SHA, "124", HASH, "boot"))), patch.object(operator.stage, "boot", return_value="boot"):
            with self.assertRaises(operator.Refused):
                operator.check_manifest(Runner(), SESSION, SHA, PID, HASH)

    def test_protected_file_digest_and_manifest_checks_precede_attempt(self):
        calls = []
        receipt = operator.manifest_bytes(SHA, PID, HASH, "boot")
        helper = SESSION + "/identity_correlate"
        manifest = SESSION + "/manifest.json"

        class Runner:
            def root(self, program, *args, **kwargs):
                calls.append((program, *args))
                if program == "/usr/bin/stat":
                    return {
                        SESSION: b"0:700:Directory\n",
                        helper: b"0:500:Regular File:1:10\n",
                        manifest: f"0:600:Regular File:1:{len(receipt)}\n".encode(),
                    }[args[-1]]
                if program == "/bin/ls":
                    return {SESSION: b"drwx------ dir", helper: b"-r-x------ exe",
                            manifest: b"-rw------- record"}[args[-1]]
                if program == "/usr/bin/shasum":
                    return f"{SHA}  {helper}\n".encode()
                if program == "/bin/cat":
                    return receipt
                if program == "/bin/mkdir":
                    raise operator.Refused("attempt already exists")
                self_unexpected = (program, args, kwargs)
                raise AssertionError(self_unexpected)

        with patch.object(operator.stage, "protected_parents", side_effect=lambda _: calls.append(("parents",))), \
             patch.object(operator.stage, "boot", side_effect=lambda _: calls.append(("boot",)) or "boot"):
            with self.assertRaisesRegex(operator.Refused, "attempt already exists"):
                operator.sample(Runner(), SESSION, SHA, PID, HASH)
        self.assertEqual(calls, [
            ("parents",),
            ("/usr/bin/stat", "-f", "%u:%Lp:%HT", SESSION),
            ("/bin/ls", "-lde", SESSION),
            ("/usr/bin/stat", "-f", "%u:%Lp:%HT:%l:%z", helper),
            ("/bin/ls", "-lde", helper),
            ("/usr/bin/shasum", "-a", "256", helper),
            ("/usr/bin/stat", "-f", "%u:%Lp:%HT:%l:%z", manifest),
            ("/bin/ls", "-lde", manifest),
            ("/bin/cat", manifest), ("boot",),
            ("/bin/mkdir", SESSION + "/attempt"),
        ])


if __name__ == "__main__":
    unittest.main()
