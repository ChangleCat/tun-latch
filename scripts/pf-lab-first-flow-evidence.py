#!/usr/bin/env python3
"""Export a restored trial's protected evidence and assess it offline as an ordinary user."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


operator = load('_first_flow_operator', 'pf-lab-first-flow.py')
Refused = operator.Refused
MAX_REPLY = 2_300_000
MAX_LOCAL = 65536
MAX_PCAP = 1024 * 1024
EVALUATOR = Path(__file__).resolve().parent.parent / 'target/debug/examples/pf_lab_capture_eval'
PHASES = ('before', 'blocked', 'after')


def parse(raw):
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=operator.base.unique_fields)


def uint(value):
    return type(value) is int and 0 <= value < 2**64


def binding(value):
    return (isinstance(value, list) and len(value) == 32
            and all(type(x) is int and 0 <= x <= 255 for x in value))


def sender_evidence(report, cases):
    """Validate the exact blocked batch; the evaluator independently checks PF deltas."""
    if report is None:
        return [{'family': c['family'], 'protocol': c['protocol'], 'sent': False} for c in cases]
    keys = {'status', 'role', 'helper_sha256', 'cases', 'pf_verdict'}
    if (not isinstance(report, dict) or set(report) != keys or report['role'] != 'sender'
            or report['pf_verdict'] != 'not_evaluated' or not isinstance(report['helper_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', report['helper_sha256'])
            or not isinstance(report['cases'], list) or len(report['cases']) != len(cases)):
        raise Refused('发送端报告格式错误')
    indexed = {}
    all_completed = True
    for item in report['cases']:
        if not isinstance(item, dict):
            raise Refused('发送端报告格式错误')
        key = (item.get('family'), item.get('protocol'))
        if not all(isinstance(value, str) for value in key) or key in indexed:
            raise Refused('发送端报告重复')
        indexed[key] = item
    evidence = []
    for case in cases:
        item = indexed.get((case['family'], case['protocol']))
        if not isinstance(item, dict) or any(item.get(k) != v for k, v in case.items()):
            raise Refused('发送端报告与冻结计划不符')
        extra = set(item) - set(case)
        if item.get('result') == 'echo_matched' and extra == {'result'}:
            sent = True
        elif item.get('result') == 'unavailable' and extra == {'result', 'stage', 'error_kind', 'errno'}:
            all_completed = False
            stage, kind, errno = item['stage'], item['error_kind'], item['errno']
            if (not isinstance(stage, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', stage)
                    or not isinstance(kind, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', kind)
                    or (errno is not None and (type(errno) is not int or not -(2**31) <= errno < 2**31))):
                raise Refused('发送端失败记录格式错误')
            # A TCP attempt records an actual socket connect call, which alone does
            # not prove that a packet reached PF. The evaluator also requires an
            # independent outbound hit on the exact, exclusive probe tuple.
            stages = ({'receive', 'peer', 'nonce', 'deadline'} if case['protocol'] == 'udp'
                      else {'connect_attempted', 'write', 'shutdown_write', 'read', 'read_eof',
                            'nonce', 'deadline'})
            sent = stage in stages
        else:
            raise Refused('发送端结果格式错误')
        evidence.append({'family': case['family'], 'protocol': case['protocol'], 'sent': sent})
    if report['status'] != ('completed' if all_completed else 'incomplete'):
        raise Refused('发送端报告状态不一致')
    return evidence


def assemble(raw, local_raw, approved_plan):
    if not 0 < len(raw) <= MAX_REPLY or not 0 < len(local_raw) <= MAX_LOCAL:
        raise Refused('证据超出大小限制')
    obj, local = parse(raw), parse(local_raw)
    required = {'scope', 'phase', 'anchor', 'actual_protection', 'plan_sha256', 'plan',
                'capture', 'pcap_hex', 'counters_before', 'counters_after'}
    if (not isinstance(obj, dict) or set(obj) != required
            or obj['scope'] != 'first_physical_flow_batch' or obj['phase'] != 'evidence_recorded'
            or obj['actual_protection'] != 'unknown' or obj['plan_sha256'] != approved_plan
            or not isinstance(obj['anchor'], str)
            or not re.fullmatch(r'tunlatch-lab-[0-9a-f]{32}', obj['anchor'])
            or int(obj['anchor'][-32:], 16) == 0):
        raise Refused('受保护证据身份不符')
    plan = obj['plan']
    if not isinstance(plan, dict) or set(plan) != {'interface', 'phases'}:
        raise Refused('冻结计划格式错误')
    raw_plan = json.dumps(plan['phases'], separators=(',', ':')).encode()
    frozen = operator.frozen_input(raw_plan, plan['interface'])
    if hashlib.sha256(frozen).hexdigest() != approved_plan:
        raise Refused('冻结计划摘要不符')
    cap = obj['capture']
    if (not isinstance(cap, dict) or set(cap) != {'binding', 'started_us', 'ended_us', 'dropped', 'sha256'}
            or not binding(cap['binding']) or not all(uint(cap[k]) for k in ('started_us', 'ended_us', 'dropped'))
            or cap['started_us'] >= cap['ended_us'] or not isinstance(cap['sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', cap['sha256'])):
        raise Refused('抓包记录格式错误')
    pcap_hex = obj['pcap_hex']
    if (not isinstance(pcap_hex, str) or len(pcap_hex) > 2 * MAX_PCAP
            or len(pcap_hex) % 2 or not re.fullmatch(r'[0-9a-f]*', pcap_hex)):
        raise Refused('抓包内容格式错误')
    pcap = bytes.fromhex(pcap_hex)
    if hashlib.sha256(pcap).hexdigest() != cap['sha256']:
        raise Refused('抓包摘要不符')
    before, after = obj['counters_before'], obj['counters_after']
    for counter in (before, after):
        if (not isinstance(counter, dict) or set(counter) != {'binding', 'observed_us', 'rules', 'labels'}
                or not binding(counter['binding']) or not uint(counter['observed_us'])
                or any(not isinstance(counter[k], str) for k in ('rules', 'labels'))):
            raise Refused('计数记录格式错误')
    if (before['binding'] != after['binding'] or before['rules'] != after['rules']
            or not cap['started_us'] <= before['observed_us'] < after['observed_us'] <= cap['ended_us']):
        raise Refused('计数记录不属于同一阶段')
    if not isinstance(local, dict) or set(local) not in ({'windows', 'reports'}, {'windows', 'reports', 'sender_report'}):
        raise Refused('本地报告格式错误')
    if not isinstance(local['reports'], dict) or set(local['reports']) != set(PHASES):
        raise Refused('需要三个阶段的接收端报告')
    windows = local['windows']
    if not isinstance(windows, dict) or set(windows) != set(PHASES):
        raise Refused('时间窗口格式错误')
    for phase in PHASES:
        window = windows[phase]
        if (not isinstance(window, dict) or set(window) != {'start_us', 'end_us'}
                or not all(uint(window[k]) for k in window) or window['start_us'] >= window['end_us']):
            raise Refused('时间窗口格式错误')
    if not (cap['started_us'] <= windows['before']['start_us']
            and windows['before']['end_us'] < windows['blocked']['start_us']
            and before['observed_us'] <= windows['blocked']['start_us']
            and windows['blocked']['end_us'] <= after['observed_us']
            and windows['blocked']['end_us'] < windows['after']['start_us']
            and windows['after']['end_us'] <= cap['ended_us']):
        raise Refused('时间窗口与受保护记录不符')
    evidence = sender_evidence(local.get('sender_report'), plan['phases']['blocked']['cases'])
    manifest = {'plan': plan['phases'], 'interface': plan['interface'],
                'capture_complete': True, 'capture_dropped': cap['dropped'],
                'capture_start_us': cap['started_us'], 'capture_end_us': cap['ended_us'],
                'windows': windows, 'evidence': evidence, 'reports': local['reports'],
                'pf': {'anchor_suffix': obj['anchor'][-32:], 'rules_before': before['rules'],
                       'rules_after': after['rules'], 'labels_before': before['labels'],
                       'labels_after': after['labels']}}
    data = (json.dumps(manifest, separators=(',', ':')) + '\n').encode()
    if len(data) > MAX_LOCAL:
        raise Refused('评估输入超出大小限制')
    return data, pcap


def read_evidence(runner):
    expected, digest = operator.approved()
    operator.base.inspect(runner, expected)
    code, raw = runner.root(operator.HELPER, 'evidence', limit=MAX_REPLY,
                            allowed_codes=(0, 1), with_code=True, timeout=45)
    raw = operator.base.checked_helper_output(code, raw)
    operator.base.inspect(runner, expected)
    return raw, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local', type=Path, required=True, help='local windows and receiver reports JSON')
    for phase in PHASES:
        parser.add_argument('--receiver-' + phase, type=Path, help='final receiver report for ' + phase)
    parser.add_argument('--output-dir', type=Path, required=True, help='new private evidence directory')
    parser.add_argument('--evaluate', action='store_true', help='run the prebuilt fixed offline evaluator')
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused('请以普通用户运行')
    with args.local.open('rb') as source:
        local = source.read(MAX_LOCAL + 1)
    receiver_paths = [getattr(args, 'receiver_' + phase) for phase in PHASES]
    if any(receiver_paths):
        if not all(receiver_paths):
            raise Refused('须同时提供三个接收端报告')
        combined = parse(local)
        if not isinstance(combined, dict) or set(combined) not in ({'windows'}, {'windows', 'sender_report'}):
            raise Refused('时间窗口文件格式错误')
        reports = {}
        for phase, path in zip(PHASES, receiver_paths):
            with path.open('rb') as source:
                raw_report = source.read(MAX_LOCAL + 1)
            if not 0 < len(raw_report) <= MAX_LOCAL:
                raise Refused('接收端报告超出大小限制')
            reports[phase] = parse(raw_report)
        combined['reports'] = reports
        local = json.dumps(combined, separators=(',', ':')).encode()
    runner = operator.stage.Runner()
    raw, digest = read_evidence(runner)
    manifest, pcap = assemble(raw, local, digest)
    args.output_dir = args.output_dir.absolute()
    args.output_dir.mkdir(mode=0o700)
    for name, data in (('manifest.json', manifest), ('capture.pcap', pcap),
                       ('protected-evidence.json', raw), ('local-evidence.json', local)):
        fd = os.open(args.output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
    if args.evaluate:
        result = runner.call([str(EVALUATOR), str(args.output_dir / 'manifest.json'),
                              str(args.output_dir / 'capture.pcap')], limit=MAX_LOCAL, timeout=45)
        sys.stdout.buffer.write(result)
    else:
        print(json.dumps({'result': 'exported', 'directory': str(args.output_dir),
                          'actual_protection': 'unknown', 'direct_attempt_evidence': 'see manifest; PF delta required'}))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        print('停止：' + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('中断：保留已写入的证据。', file=sys.stderr)
        sys.exit(2)
