"""No sudo, PF writes, enabling, traffic or networking; fixed -n parser test only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("rule", Path(__file__).with_name("pf-lab-rule.py"))
rule = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rule)
SESSION = "/var/root/tunlatch-pf-rule.A1b2C3d4"


class Fake:
    def __init__(self):
        self.session = SESSION
        self.anchor, self.rules = rule.profile(SESSION)
        self.files = {"candidate.pf": self.rules, "empty.pf": b""}
        self.marks = set()
        self.root = {"root-rules": b'anchor "com.apple/*" all\n', "root-nat": b"",
                     "inventory": b"com.apple\n"}
        self.image = b""
        self.present = False
        self.residue = True
        self.extra_names = set()
        self.extra_leaf = {}
        self.pf_disabled = True
        self.refs = b"No pf starter references held\n"
        self.identity_ok = True
        self.fail_submit = None
        self.calls = []

    def inspect(self):
        if not self.identity_ok:
            raise rule.Refused("boot/ownership/ACL mismatch")

    def read(self, name):
        return self.files[name]

    def exists(self, name):
        return name in self.files or name in self.marks

    def mark(self, name):
        if self.exists(name):
            raise rule.Refused("already exists")
        self.marks.add(name)

    def write(self, name, data):
        if self.exists(name):
            raise rule.Refused("overwrite")
        self.files[name] = data

    def baseline(self, key, args):
        value = self.query(*args)
        self.files["before-" + key + ".txt"] = value
        return value

    def query(self, *args):
        if args == ("-s", "info"):
            return b"Status: Disabled for 0 days\n" if self.pf_disabled else b"Status: Enabled for 0 days\n"
        if args == ("-s", "References"):
            return self.refs
        for key, query in rule.ROOT_QUERIES:
            if args == query:
                if key == "inventory":
                    names = rule.inventory(self.root[key]) | self.extra_names
                    if self.present:
                        names.add(self.anchor)
                    return ("\n".join(sorted(names)) + "\n").encode()
                return self.root[key]
        if args[:2] == ("-a", self.anchor):
            return self.image if args[3] == "rules" else self.extra_leaf.get(args[3], b"")
        raise AssertionError(args)

    def submit(self, anchor, empty):
        self.calls.append((anchor, empty))
        if self.fail_submit == "before":
            raise rule.Refused("unknown submit, before mutation")
        self.image = b"" if empty else self.rules
        self.present = self.residue or not empty
        if self.fail_submit == "after":
            raise rule.Refused("lost reply after mutation")


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tunlatch-rule-unit.")
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name)
        self.reset()
        self.checker = patch.object(rule.reference, "check_capture", return_value=13)
        self.checked = self.checker.start()
        self.addCleanup(self.checker.stop)
        self.native = patch.object(rule.reference, "root", side_effect=AssertionError("unexpected sudo/PF"))
        self.native.start()
        self.addCleanup(self.native.stop)

    def reset(self):
        self.fake = Fake()
        for i, (key, _) in enumerate(rule.ROOT_QUERIES, 1):
            (self.capture/f"query-{i:02}.json").write_text(json.dumps({"stdout": self.fake.root[key].decode()}))

    def lab(self):
        return rule.Rules(self.fake, lambda _anchor, data: data)

    def stage(self, **kwargs):
        self.lab().stage(self.capture, lambda: True, **kwargs)

    def test_normal_stage_and_new_process_recovery_touch_only_own_filter(self):
        foreign = self.fake.root.copy()
        self.stage()
        result = self.lab().recover(lambda: True)
        self.assertTrue(result["filter_empty"])
        self.assertEqual(self.fake.root, foreign)
        self.assertEqual(self.fake.calls, [(self.fake.anchor, False), (self.fake.anchor, True)])
        self.assertIn("closed.json", self.fake.files)
        self.assertTrue(result["anchor_listed_in_inventory"])
        self.assertTrue(self.fake.pf_disabled)

    def test_lost_submit_reply_before_or_after_kernel_change_is_inspected_not_replayed(self):
        for failure in ("before", "after"):
            with self.subTest(failure=failure):
                self.reset()
                self.fake.fail_submit = failure
                with self.assertRaises(rule.Refused):
                    self.stage()
                self.assertIn("load-intent", self.fake.marks)
                self.fake.fail_submit = None
                result = self.lab().recover(lambda: True)
                self.assertTrue(result["filter_empty"])
                self.assertEqual(len([c for c in self.fake.calls if not c[1]]), 1)
                self.assertEqual(len([c for c in self.fake.calls if c[1]]), int(failure == "after"))

    def test_controlled_stop_after_system_return_needs_no_submit_ack_to_recover(self):
        with self.assertRaisesRegex(rule.Refused, "不是内核阶段"):
            self.stage(stop_after_submit=True)
        self.assertEqual(self.fake.image, self.fake.rules)
        self.lab().recover(lambda: True)
        self.assertEqual(self.fake.image, b"")

    def test_existing_slot_is_not_adopted_or_overwritten(self):
        self.fake.root["inventory"] += self.fake.anchor.encode() + b"\n"
        (self.capture/"query-03.json").write_text(json.dumps({"stdout": self.fake.root["inventory"].decode()}))
        with self.assertRaises(rule.Refused):
            self.stage()
        self.assertFalse(self.fake.calls)
        self.assertNotIn("load-intent", self.fake.marks)

    def test_stale_capture_after_prompt_prevents_any_pf_write(self):
        self.checked.side_effect = [13, rule.Refused("stale")]
        with self.assertRaises(rule.Refused):
            self.stage()
        self.assertFalse(self.fake.calls)
        self.assertFalse(self.fake.marks)

    def test_disabled_and_zero_reference_preconditions_are_required(self):
        for field, value in (("pf_disabled", False), ("refs", b"foreign reference\n")):
            with self.subTest(field=field):
                self.reset()
                setattr(self.fake, field, value)
                with self.assertRaises(rule.Refused):
                    self.stage()
                self.assertFalse(self.fake.calls)

    def test_identity_candidate_and_empty_recovery_data_cannot_change(self):
        for field in ("identity", "candidate", "empty"):
            with self.subTest(field=field):
                self.reset()
                self.stage()
                if field == "identity":
                    self.fake.identity_ok = False
                else:
                    self.fake.files[field + ".pf"] = b"foreign data\n"
                with self.assertRaises(rule.Refused):
                    self.lab().recover(lambda: True)
                self.assertEqual(len(self.fake.calls), 1)

    def test_foreign_rule_nat_table_child_or_control_change_prevents_clear(self):
        for kind in ("rules", "nat", "Tables", "Anchors", "root-rules", "root-nat", "inventory", "subtree"):
            with self.subTest(kind=kind):
                self.reset()
                self.stage()
                if kind == "rules":
                    self.fake.image = b"pass all\n"
                elif kind in ("nat", "Tables", "Anchors"):
                    self.fake.extra_leaf[kind] = b"foreign\n"
                elif kind == "inventory":
                    self.fake.extra_names.add("other")
                elif kind == "subtree":
                    self.fake.extra_names.add(self.fake.anchor + "/child")
                else:
                    self.fake.root[kind] = b"foreign\n"
                with self.assertRaises(rule.Refused):
                    self.lab().recover(lambda: True)
                self.assertEqual(len(self.fake.calls), 1)

    def test_mutation_during_takeover_prompt_stops_before_clear(self):
        self.stage()
        def changed():
            self.fake.image = b"different rules\n"
            return True
        with self.assertRaises(rule.Refused):
            self.lab().recover(changed)
        self.assertEqual(len(self.fake.calls), 1)

    def test_unknown_clear_preserves_attempt_and_never_retries(self):
        self.stage()
        self.fake.fail_submit = "after"
        with self.assertRaises(rule.Refused):
            self.lab().recover(lambda: True)
        calls = self.fake.calls.copy()
        with self.assertRaises(rule.Refused):
            self.lab().recover(lambda: True)
        self.assertEqual(self.fake.calls, calls)
        self.assertNotIn("closed.json", self.fake.files)

    def test_second_stage_second_recovery_and_user_cancellation_do_not_write(self):
        with self.assertRaises(rule.Refused):
            self.lab().stage(self.capture, lambda: False)
        self.assertFalse(self.fake.calls)
        self.stage()
        with self.assertRaises(rule.Refused):
            self.stage()
        with self.assertRaises(rule.Refused):
            self.lab().recover(lambda: False)
        self.assertEqual(len(self.fake.calls), 1)
        self.lab().recover(lambda: True)
        with self.assertRaises(rule.Refused):
            self.lab().recover(lambda: True)
        self.assertEqual(len(self.fake.calls), 2)

    def test_absent_or_empty_anchor_metadata_both_preserve_foreign_state(self):
        self.fake.residue = False
        self.stage()
        result = self.lab().recover(lambda: True)
        self.assertFalse(result["anchor_listed_in_inventory"])

    def test_unlisted_nonempty_filter_before_first_submit_is_not_overwritten(self):
        self.fake.image = b"foreign rules\n"
        self.fake.present = False
        with self.assertRaises(rule.Refused):
            self.stage()
        self.assertFalse(self.fake.calls)
        self.assertNotIn("load-intent", self.fake.marks)

    def test_unlisted_slot_is_still_directly_read_before_declaring_filter_empty(self):
        self.stage()
        self.fake.present = False  # Directory omission does not imply no filter.
        self.assertEqual(self.fake.image, self.fake.rules)
        self.lab().recover(lambda: True)
        self.assertEqual(self.fake.image, b"")
        self.assertEqual(self.fake.calls, [(self.fake.anchor, False), (self.fake.anchor, True)])

    def test_direct_slot_read_error_cannot_be_replaced_by_an_empty_directory_result(self):
        self.stage()
        self.fake.present = False
        original = self.fake.query
        def query(*args):
            if args[:2] == ("-a", self.fake.anchor):
                raise rule.Refused("direct slot read failed")
            return original(*args)
        with patch.object(self.fake, "query", side_effect=query), self.assertRaises(rule.Refused):
            self.lab().recover(lambda: True)
        self.assertEqual(len(self.fake.calls), 1)

    def test_incomplete_intent_cannot_authorize_recovery(self):
        for marker in ("stage-once", "baseline-ready", "load-intent"):
            with self.subTest(marker=marker):
                self.reset()
                self.stage()
                self.fake.marks.remove(marker)
                with self.assertRaises(rule.Refused):
                    self.lab().recover(lambda: True)
                self.assertEqual(len(self.fake.calls), 1)

    def test_framing_accepts_only_exact_notices_and_retains_errors(self):
        altq = rule.reference.NOTICE.encode()
        for data in (altq + rule.LOAD_NOTICE, rule.LOAD_NOTICE + altq):
            self.assertEqual(rule.normalize_record(b"^D\x08\x08" + data, load=True), b"")
            self.assertIn(rule.LOAD_NOTICE, rule.normalize_record(data))
        for data in (altq + altq, rule.LOAD_NOTICE + b"pfctl: DIOCGETRULES: Invalid argument\n"):
            self.assertNotEqual(rule.normalize_record(data, load=True), b"")
        for data in (b"partial", b"\x00\n", b"x" * 65537):
            with self.assertRaises(rule.Refused):
                rule.normalize_record(data)

    def test_closed_paths_and_inventory_reject_injection_and_missing_parents(self):
        for path in ("/tmp/x", SESSION + "/..", SESSION + ";id", SESSION + " "):
            with self.assertRaises(rule.Refused):
                rule.profile(path)
        for value in (b"a\na\n", b"a/b\n", b"../bad\n", b"*\n", b"-f\n", b"a\x00\n"):
            with self.assertRaises(rule.Refused):
                rule.inventory(value)
        with self.assertRaises(rule.Refused):
            rule.System(SESSION).path("../../etc/pf.conf")

    def test_native_no_action_parser_accepts_fixed_filter_and_no_state_rules(self):
        anchor, rules = rule.profile(SESSION)
        self.assertEqual(rule.canonical(anchor, rules), rules)
        self.assertEqual(len(rules.splitlines()), 4)
        self.assertNotIn(b"keep state", rules)
        self.assertNotIn("/", anchor)

    def test_system_submit_uses_filter_only_exact_slot_and_preserves_kernel_errors(self):
        system = rule.System(SESSION)
        with patch.object(system, "exists", return_value=False):
            for empty in (False, True):
                log, name = ("clear.txt", "empty.pf") if empty else ("stage.txt", "candidate.pf")
                with patch.object(rule.reference, "record", return_value=rule.LOAD_NOTICE) as record:
                    system.submit(self.fake.anchor, empty)
                    record.assert_called_once_with(SESSION, log, "/sbin/pfctl", "-a", self.fake.anchor,
                                                   "-R", "-o", "none", "-f", SESSION+"/"+name)
            with patch.object(rule.reference, "record", return_value=rule.LOAD_NOTICE+b"pfctl: kernel error\n"):
                with self.assertRaises(rule.Refused):
                    system.submit(self.fake.anchor, True)
        with self.assertRaises(rule.Refused):
            system.submit("com.apple", True)

    def test_native_boundary_rejects_arbitrary_queries_payloads_and_invalid_cli_before_auth(self):
        system = rule.System(SESSION)
        for args in (("-E",), ("-F", "all"), ("-a", "com.apple", "-s", "rules")):
            with self.assertRaises(rule.Refused):
                system.query(*args)
        for name, data in (("candidate.pf", b"pass all\n"), ("empty.pf", b"block all\n")):
            with self.assertRaises(rule.Refused):
                system.write(name, data)
        for args in (["tool", "stage"], ["tool", "recover", "/tmp/not-owned"]):
            with patch.object(rule.sys, "argv", args), patch.object(rule.reference, "command") as run:
                with self.assertRaises(rule.Refused):
                    rule.main()
                run.assert_not_called()

    def test_default_plan_has_no_privileged_or_pf_kernel_calls(self):
        with patch.object(rule.sys, "argv", ["tool"]), patch.object(rule.reference, "command") as run:
            rule.main()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
