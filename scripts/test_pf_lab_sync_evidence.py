"""Offline checks of the closed synchronous PF trial evidence reader."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('sync_evidence', Path(__file__).with_name('pf-lab-sync-evidence.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
ANCHOR = 'tunlatch-lab-01020304'
BOOT = '01234567-89ab-cdef-0123-456789abcdef'
RULES = b'private rule fixture\n'


def encode(value):
    return (json.dumps(value, separators=(',', ':')) + '\n').encode()


def fixture():
    baseline = {'root_rules': list(b'root\n'), 'root_nat': [], 'inventory': ['com.apple'],
                'foreign': {'com.apple': [[], []]}}
    framed = b''.join(struct.pack('>Q', len(item)) + item for item in (b'root\n', b'', b'com.apple'))
    framed += struct.pack('>Q', 1)
    framed += struct.pack('>Q', 9) + b'com.apple' + b'\0' * 16
    digest = hashlib.sha256(b'tunlatch-pf-slot-baseline\0' + framed).digest()
    approval = {'helper_sha256': 'a' * 64, 'baseline_sha256': digest.hex(), 'boot': BOOT}
    absent = encode({'baseline': baseline, 'slot': 'Absent'})
    before_clear = encode({'baseline': baseline, 'slot': {'Active': list(RULES)}})
    nonce = bytes([1, 2, 3, 4] + [9] * 28)
    session = encode({'boot': BOOT, 'helper': [0xaa] * 32, 'nonce': list(nonce),
                      'created_ticks': 1234, 'baseline': list(digest),
                      'prepared_observation': list(hashlib.sha256(absent).digest())})
    records = {'session.json': session, 'prepare.json': absent, 'before-stage.json': absent,
               'before-recovery.json': before_clear, 'after-recovery.json': absent,
               'recovery-return.sha256': hashlib.sha256(absent).hexdigest().encode() + b'\n'}
    for phase, snapshot, steps in (('stage', absent, [(1, 3)]),
                                   ('recovery', before_clear, [(1, 3), (2, 3), (4, 0)])):
        plan = hashlib.sha256(hashlib.sha256(session).digest() + phase.encode()
                              + hashlib.sha256(snapshot).digest()).digest()
        header = b'TLABLOG\0' + nonce + plan
        ledger = header + hashlib.sha256(header).digest()
        for sequence, (event, operation) in enumerate(steps, 1):
            entry = struct.pack('>QBB', sequence, event, operation) + ledger[-32:]
            ledger += entry + hashlib.sha256(entry).digest()
        records[phase + '/session.journal'] = ledger
    return approval, records


class Reader:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def root(self, *args, **kwargs):
        self.calls.append(args)
        path = args[-1].removeprefix(tool.sync.SESSION + '/')
        if path in ('stage', 'recovery'):
            if args[0] == '/usr/bin/stat':
                return b'1:2:0:700:Directory\n'
            if args[:2] == ('/bin/ls', '-lde'):
                return b'drwx------ root wheel fixture\n'
        if path in self.records:
            data = self.records[path]
            if args[0] == '/usr/bin/stat':
                return f'0:600:Regular File:1:{len(data)}\n'.encode()
            if args[:2] == ('/bin/ls', '-lde'):
                return b'-rw------- root wheel fixture\n'
            if args[0] == '/bin/cat':
                return data
        raise AssertionError(args)


class SyncEvidenceTests(unittest.TestCase):
    def test_verified_report_has_digests_but_no_rule_text(self):
        approval, records = fixture()
        result = tool.audit_records(records, approval, ANCHOR)
        self.assertEqual(result['baseline_sha256'], approval['baseline_sha256'])
        self.assertEqual(result['candidate_sha256'], hashlib.sha256(RULES).hexdigest())
        self.assertEqual(result['candidate_bytes'], len(RULES))
        self.assertEqual(set(result['record_sha256']), set(records))
        self.assertNotIn('private rule', json.dumps(result))

    def test_refuses_unexpected_slot_or_broken_record_binding(self):
        approval, records = fixture()
        for name, changed in (
            ('before-recovery.json', records['before-stage.json']),
            ('after-recovery.json', records['before-recovery.json']),
            ('recovery-return.sha256', b'0' * 64 + b'\n'),
            ('stage/session.journal', records['stage/session.journal'][:-1]),
            ('recovery/session.journal', records['recovery/session.journal'] + b'x'),
        ):
            with self.subTest(name=name), self.assertRaises(tool.Refused):
                tool.audit_records({**records, name: changed}, approval, ANCHOR)
        with self.assertRaises(tool.Refused):
            tool.audit_records(records, approval, 'tunlatch-lab-00000000')

    def test_fixed_paths_and_two_matching_read_only_status_calls(self):
        approval, records = fixture()
        report = encode({'scope': 'unattached_filter_trial', 'anchor': ANCHOR,
                         'phase': 'recovery_readback_recorded', 'active_slot': 'absent',
                         'actual_protection': 'unknown', 'recovery_qualified': False})
        runner = Reader(records)
        with (patch.object(tool.sync, 'approved_trial', return_value=approval),
              patch.object(tool.sync.stage, 'boot', return_value=BOOT),
              patch.object(tool.sync, 'require_local') as receipt,
              patch.object(tool.sync, 'inspect'),
              patch.object(tool.sync, 'invoke', return_value=report) as invoke):
            self.assertEqual(tool.audit(runner)['status'], 'verified')
            self.assertEqual([call.args[1] for call in invoke.call_args_list], ['status', 'status'])
            receipt.assert_any_call(tool.sync.STAGE_RETURN, {**approval, 'anchor': ANCHOR})
        self.assertEqual({args[0] for args in runner.calls}, {'/usr/bin/stat', '/bin/ls', '/bin/cat'})
        with self.assertRaises(tool.Refused):
            tool.read_record(runner, '../unexpected')


if __name__ == '__main__':
    unittest.main()
