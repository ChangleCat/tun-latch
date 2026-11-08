import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('fault_operator', Path(__file__).with_name('pf-lab-sync-fault.py'))
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


def report(phase, slot, anchor='tunlatch-lab-1234abcd'):
    return json.dumps({'scope': 'unattached_filter_trial', 'anchor': anchor,
                       'phase': phase, 'active_slot': slot, 'actual_protection': 'unknown',
                       'recovery_qualified': False}).encode()


class FaultOperatorTests(unittest.TestCase):
    def test_old_and_new_deployments_are_isolated(self):
        self.assertEqual(op.old.SESSION, '/private/var/root/tunlatch-pf-sync')
        self.assertEqual(op.base.SESSION, op.SESSION)
        self.assertNotEqual(op.old.MANIFEST, op.MANIFEST)
        self.assertNotEqual(op.old.MODE, op.MODE)
        self.assertNotEqual(op.old.stage, op.stage)
        self.assertNotEqual(op.old.APPROVAL, op.APPROVAL)

    def test_digest_and_all_mutations_are_closed(self):
        with mock.patch.object(op, 'AUDITED_BINARY_SHA256', None), self.assertRaises(op.Refused):
            op.audited_digest()
        runner = mock.Mock()
        for action in ('stage-fault', 'recover-fault', 'capture-unknown'):
            with self.subTest(action=action), self.assertRaises(op.Refused):
                op.execute(runner, action, 'a' * 64)
        runner.assert_not_called()

    def test_prepare_requires_old_protected_closed_readback(self):
        runner = mock.Mock()
        approval = {'helper_sha256': 'a' * 64, 'baseline_sha256': 'b' * 64, 'boot': 'boot'}
        for phase, slot in [('recovery_unknown', 'empty'),
                            ('recovery_readback_recorded', 'candidate'),
                            ('recovery_readback_recorded', 'empty'),
                            ('stage_intent_unsettled', 'empty')]:
            with (self.subTest(phase=phase, slot=slot),
                  mock.patch.object(op.old, 'approved_trial', return_value=approval),
                  mock.patch.object(op.old, 'inspect'),
                  mock.patch.object(op.old, 'invoke', return_value=report(phase, slot)),
                  mock.patch.object(op.base, 'prepare') as prepare,
                  self.assertRaises(op.Refused)):
                op.prepare(runner, 'a' * 64)
                prepare.assert_not_called()
        preflight = json.loads(report('preflight_ready', 'absent', 'not_allocated'))
        preflight['baseline_sha256'] = approval['baseline_sha256']
        raw = json.dumps(preflight).encode()
        with (mock.patch.object(op.old, 'approved_trial', return_value=approval),
              mock.patch.object(op.old, 'inspect') as inspect,
              mock.patch.object(op.old, 'require_local') as receipt,
              mock.patch.object(op.old, 'invoke', return_value=report('recovery_readback_recorded', 'absent')),
              mock.patch.object(op.base, 'prepare', return_value=raw) as prepare):
            self.assertEqual(op.prepare(runner, 'a' * 64), raw)
            inspect.assert_called_once_with(runner, op.old.AUDITED_BINARY_SHA256)
            receipt.assert_called_once_with(op.old.STAGE_RETURN, {**approval, 'anchor': 'tunlatch-lab-1234abcd'})
            prepare.assert_called_once_with(runner, 'a' * 64)
        preflight['baseline_sha256'] = 'c' * 64
        with (mock.patch.object(op, 'check_previous_closed', return_value=approval['baseline_sha256']),
              mock.patch.object(op.base, 'prepare', return_value=json.dumps(preflight).encode()),
              self.assertRaises(op.Refused)):
            op.prepare(runner, 'a' * 64)

    def test_status_inspects_fixed_deployment_and_requires_preflight(self):
        preflight = json.loads(report('preflight_ready', 'absent', 'not_allocated'))
        preflight['baseline_sha256'] = 'a' * 64
        raw = json.dumps(preflight).encode()
        with (mock.patch.object(op.base, 'inspect') as inspect,
              mock.patch.object(op.base, 'invoke', return_value=raw)):
            self.assertEqual(op.status(mock.sentinel.runner, 'a' * 64), raw)
            inspect.assert_called_once_with(mock.sentinel.runner, 'a' * 64)
        with (mock.patch.object(op.base, 'inspect'),
              mock.patch.object(op.base, 'invoke', return_value=report('invalid', 'absent')),
              self.assertRaises(op.Refused)):
            op.status(mock.sentinel.runner, 'a' * 64)

    def test_fault_flow_checks_baseline_attempt_witness_and_distinct_ack(self):
        approval = {'helper_sha256': 'a' * 64, 'baseline_sha256': 'b' * 64, 'boot': 'boot'}
        initial = json.loads(report('preflight_ready', 'absent', 'not_allocated'))
        initial['baseline_sha256'] = approval['baseline_sha256']
        initial = json.dumps(initial).encode()
        prepared = json.loads(report('prepared', 'absent'))
        prepared['baseline_sha256'] = approval['baseline_sha256']
        prepared = json.dumps(prepared).encode()
        returned = report('fault_writer_reaped', 'not_read')
        events = []
        def invoke(_runner, action):
            events.append(action)
            return {'prepare': prepared, 'stage-fault': returned}[action]
        with (mock.patch.object(op, 'PF_WRITES_AUTHORIZED', True),
              mock.patch.object(op.stage, 'boot', return_value='boot'),
              mock.patch.object(op, 'status', side_effect=[initial, initial]),
              mock.patch.object(op.base, 'save_local', side_effect=lambda *_: events.append('attempt')),
              mock.patch.object(op, 'invoke', side_effect=invoke)):
            self.assertEqual(op.execute(None, 'stage-fault', 'a' * 64,
                                        lambda _: 'STAGE-PF-SYNC-FAULT', approval=approval), returned)
        self.assertEqual(events, ['attempt', 'prepare', 'stage-fault'])
        observed = report('fault_writer_reaped', 'candidate')
        recovered = report('recovery_readback_verified', 'empty')
        with (mock.patch.object(op, 'PF_WRITES_AUTHORIZED', True),
              mock.patch.object(op.stage, 'boot', return_value='boot'),
              mock.patch.object(op.base, 'require_local') as require,
              mock.patch.object(op, 'status', side_effect=[observed, observed]),
              mock.patch.object(op, 'invoke', return_value=recovered)):
            self.assertEqual(op.execute(None, 'recover-fault', 'a' * 64,
                                        lambda _: 'RECOVER-PF-SYNC-FAULT', approval=approval), recovered)
            require.assert_called_once_with(op.STAGE_ATTEMPT, approval)
        for slot in ('not_read', 'unrecognized'):
            observed = report('fault_writer_reaped', slot)
            if slot == 'unrecognized':
                value = json.loads(observed)
                value.update(slot_sha256='c' * 64, slot_bytes=1)
                observed = json.dumps(value).encode()
            with (mock.patch.object(op, 'PF_WRITES_AUTHORIZED', True),
                  mock.patch.object(op.stage, 'boot', return_value='boot'),
                  mock.patch.object(op.base, 'require_local'),
                  mock.patch.object(op, 'status', return_value=observed),
                  mock.patch.object(op, 'invoke') as call,
                  self.assertRaises(op.Refused)):
                op.execute(None, 'recover-fault', 'a' * 64, approval=approval)
            call.assert_not_called()

    def test_attempt_record_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage-attempt.json'
            approval = {'helper_sha256': 'a' * 64, 'baseline_sha256': 'b' * 64,
                        'boot': '12345678-1234-1234-1234-123456789abc'}
            op.base.save_local(path, approval)
            self.assertEqual(op.base.read_local(path), approval)
            with self.assertRaises(FileExistsError):
                op.base.save_local(path, approval)
            path.chmod(0o644)
            with self.assertRaises(op.Refused):
                op.base.read_local(path)


if __name__ == '__main__':
    unittest.main()
