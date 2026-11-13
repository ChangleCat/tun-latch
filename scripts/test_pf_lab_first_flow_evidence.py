import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('first_flow_evidence', Path(__file__).with_name('pf-lab-first-flow-evidence.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def fixture():
    cases = []
    for i, (family, protocol) in enumerate(tool.operator.flow.ORDER):
        src, dst = ('192.0.2.1', '192.0.2.2') if family == 'ipv4' else ('[2001:db8::1]', '[2001:db8::2]')
        cases.append({'family': family, 'protocol': protocol, 'source': f'{src}:{55000+i}',
                      'destination': f'{dst}:443'})
    phases = tool.operator.flow.peer.generate_controls({'cases': cases})
    frozen = tool.operator.frozen_input(json.dumps(phases).encode(), 'en0')
    digest = hashlib.sha256(frozen).hexdigest()
    counter = {'binding': [1] * 32, 'observed_us': 6, 'rules': 'rules', 'labels': 'labels'}
    capture = b'capture'
    obj = {'scope': 'first_physical_flow_batch', 'phase': 'evidence_recorded',
           'anchor': 'tunlatch-lab-' + '1' * 32, 'actual_protection': 'unknown',
           'plan_sha256': digest, 'plan': json.loads(frozen),
           'capture': {'binding': [2] * 32, 'started_us': 1, 'ended_us': 30, 'dropped': 0,
                       'sha256': hashlib.sha256(capture).hexdigest()}, 'pcap_hex': capture.hex(),
           'counters_before': counter, 'counters_after': {**counter, 'observed_us': 20}}
    local = {'windows': {'before': {'start_us': 2, 'end_us': 5},
                         'blocked': {'start_us': 7, 'end_us': 19},
                         'after': {'start_us': 21, 'end_us': 29}},
             'reports': {phase: {} for phase in tool.PHASES}}
    return obj, local, digest


def encoded(value):
    return json.dumps(value).encode()


class Evidence(unittest.TestCase):
    def test_assembles_protected_records_without_claiming_send(self):
        obj, local, digest = fixture()
        manifest, capture = tool.assemble(encoded(obj), encoded(local), digest)
        result = json.loads(manifest)
        self.assertEqual(capture, b'capture')
        self.assertEqual(result['pf']['anchor_suffix'], '1' * 32)
        self.assertEqual(result['plan'], obj['plan']['phases'])
        self.assertTrue(all(not case['sent'] for case in result['evidence']))

    def test_rejects_tampering_binding_and_invalid_windows(self):
        obj, local, digest = fixture()
        for mutator in (
            lambda o, l: o.update(pcap_hex='00'),
            lambda o, l: o['counters_after'].update(binding=[3] * 32),
            lambda o, l: o['plan'].update(interface='en1'),
            lambda o, l: l['windows']['blocked'].update(start_us=5),
            lambda o, l: l['windows']['blocked'].update(end_us=21),
            lambda o, l: o.update(actual_protection='active'),
            lambda o, l: l.update(evidence=[]),
        ):
            one, two = copy.deepcopy(obj), copy.deepcopy(local)
            mutator(one, two)
            with self.subTest(mutator=mutator), self.assertRaises((tool.Refused, ValueError)):
                tool.assemble(encoded(one), encoded(two), digest)
        with self.assertRaises(ValueError):
            tool.assemble(b'{"scope":1,"scope":2}', encoded(local), digest)

    def test_sender_attempts_require_matching_plan_and_qualified_stage(self):
        obj, local, digest = fixture()
        cases = obj['plan']['phases']['blocked']['cases']
        items = [{**case, 'result': 'unavailable', 'stage': ('connect' if case['protocol'] == 'tcp' else 'receive'),
                  'error_kind': 'TimedOut', 'errno': None} for case in cases]
        local['sender_report'] = {'status': 'incomplete', 'role': 'sender', 'helper_sha256': 'a' * 64,
                                  'pf_verdict': 'not_evaluated', 'cases': items}
        manifest, _ = tool.assemble(encoded(obj), encoded(local), digest)
        evidence = json.loads(manifest)['evidence']
        self.assertTrue(all(not e['sent'] for e in evidence if e['protocol'] == 'tcp'))
        self.assertTrue(all(e['sent'] for e in evidence if e['protocol'] == 'udp'))
        items[0]['stage'] = 'connect_attempted'
        manifest, _ = tool.assemble(encoded(obj), encoded(local), digest)
        self.assertTrue(json.loads(manifest)['evidence'][0]['sent'])
        items[0]['source'] = '192.0.2.5:1234'
        with self.assertRaises(tool.Refused):
            tool.assemble(encoded(obj), encoded(local), digest)
        items[0] = {**cases[0], 'result': 'unavailable', 'stage': 'bind',
                    'error_kind': 'Other', 'errno': None}
        manifest, _ = tool.assemble(encoded(obj), encoded(local), digest)
        self.assertFalse(json.loads(manifest)['evidence'][0]['sent'])

    def test_fixed_action_is_gated_and_inspected(self):
        runner = mock.Mock()
        runner.root.return_value = (0, b'{}')
        with (mock.patch.object(tool.operator, 'approved', return_value=('a' * 64, 'b' * 64)),
              mock.patch.object(tool.operator.base, 'inspect') as inspect):
            self.assertEqual(tool.read_evidence(runner), (b'{}', 'b' * 64))
        self.assertEqual(inspect.call_count, 2)
        runner.root.assert_called_once_with(tool.operator.HELPER, 'evidence', limit=tool.MAX_REPLY,
                                            allowed_codes=(0, 1), with_code=True, timeout=45)


if __name__ == '__main__':
    unittest.main()
