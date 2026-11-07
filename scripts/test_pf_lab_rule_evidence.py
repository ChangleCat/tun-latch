"""Ordinary-user receipt checks. No fake command reaches sudo or PF."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("rule_evidence", Path(__file__).with_name("pf-lab-rule-evidence.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
SESSION = "/var/root/tunlatch-pf-rule.Abc01234"
BOOT = "01234567-89ab-cdef-0123-456789abcdef"
CLOSED = {
    "payload_absent": True, "slot_state": "empty", "filter_empty": True,
    "anchor_listed_in_inventory": True,
    "empty_anchor_metadata": "preserved; not global or parent deletion",
    "PF_disabled_zero_references_observed": True, "blocking_or_failure_safety_qualified": False,
}


class SavedRecords:
    def __init__(self):
        self.calls = []
        self.directory = "/private" + SESSION
        self.dirs = {self.directory} | {self.directory + "/" + name for name in tool.rule.MARKERS}
        records = {
            "boot.txt": (BOOT + "\n").encode(), "candidate.pf": tool.rule.profile(SESSION)[1],
            "empty.pf": b"", "stage.txt": tool.rule.LOAD_NOTICE, "clear.txt": tool.rule.LOAD_NOTICE,
            "closed.json": (json.dumps(CLOSED, sort_keys=True) + "\n").encode(),
        }
        self.files = {self.directory + "/" + name: data for name, data in records.items()}

    def root(self, program, *args, **options):
        self.calls.append((program, *args))
        path = args[-1]
        if program == "/bin/test":
            return (0 if args[0] == "-e" and path in self.files else 1), b""
        if program == "/usr/bin/stat":
            if path in self.dirs:
                return b"0:700:Directory:2:64:1:2:3:4\n"
            return f"0:600:Regular File:1:{len(self.files[path])}:1:2:3:4\n".encode()
        if program == "/bin/ls":
            return b"drwx------ record\n" if path in self.dirs else b"-rw------- record\n"
        if program == "/bin/cat":
            return self.files[path]
        raise AssertionError((program, args, options))


class RuleEvidenceTests(unittest.TestCase):
    def summarize(self, records):
        with patch.object(tool.stage, "protected_parents"), patch.object(tool.stage, "boot", return_value=BOOT):
            return tool.summarize(records, SESSION)

    def test_records_support_only_the_conditional_nonempty_branch(self):
        records = SavedRecords()
        result = self.summarize(records)
        self.assertEqual(result["recorded_close"], CLOSED)
        self.assertEqual(result["recovery_branch_inference"], "consistent_with_matching_nonempty_pre_clear")
        self.assertEqual(result["pre_clear_raw_snapshot"], "not_recorded")
        self.assertFalse(result["executed_source_verified"])
        self.assertTrue(result["recorded_close_is_historical"])
        self.assertEqual(result["ownership"], "unknown")
        self.assertEqual(result["live_pf_queries"], 0)
        self.assertEqual(result["pf_writes"], 0)
        self.assertNotIn(BOOT, json.dumps(result))
        self.assertTrue(all(call[0] in {"/usr/bin/stat", "/bin/ls", "/bin/cat", "/bin/test"} for call in records.calls))

    def test_missing_or_unrecognized_clear_receipt_leaves_branch_unknown(self):
        records = SavedRecords()
        path = records.directory + "/clear.txt"
        for raw in (None, b"", tool.rule.LOAD_NOTICE + b"unexpected error\n"):
            with self.subTest(raw=raw):
                if raw is None:
                    records.files.pop(path)
                else:
                    records.files[path] = raw
                result = self.summarize(records)
                self.assertEqual(result["recovery_branch_inference"], "unknown")
                self.assertEqual(result["clear_receipt"]["state"], "not_observed" if raw is None else "unrecognized")
                self.assertNotIn("unexpected error", json.dumps(result))

    def test_refuses_arbitrary_paths_candidate_changes_and_unknown_close_records(self):
        records = SavedRecords()
        with self.assertRaises(tool.rule.Refused):
            tool.summarize(records, SESSION + "/../other")
        self.assertEqual(records.calls, [])
        with self.assertRaises(tool.Refused):
            tool.read_record(records, records.directory, "../file")
        self.assertEqual(records.calls, [])
        records.files[records.directory + "/candidate.pf"] += b"other\n"
        with self.assertRaises(tool.Refused):
            self.summarize(records)
        with self.assertRaises(tool.Refused):
            tool.closed_record(b'{"payload_absent":true}\n')


if __name__ == "__main__":
    unittest.main()
