#!/usr/bin/env python3
"""Read-only audit of the fixed, closed synchronous PF laboratory trial."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('sync', Path(__file__).with_name('pf-lab-sync.py'))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)
Refused = sync.Refused
NAMES = ('session.json', 'prepare.json', 'before-stage.json', 'before-recovery.json',
         'after-recovery.json', 'recovery-return.sha256')
JOURNALS = {'stage/session.journal': 178, 'recovery/session.journal': 326}
MAX_RECORD = 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse(raw):
    obj = json.loads(raw, object_pairs_hook=sync.unique_fields)
    if json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode() + b'\n' != raw:
        raise Refused('记录不是规范 JSON')
    return obj


def octets(value):
    if not isinstance(value, list) or any(type(x) is not int or not 0 <= x <= 255 for x in value):
        raise Refused('记录字节无效')
    return bytes(value)


def baseline(value):
    if not isinstance(value, dict) or set(value) != {'root_rules', 'root_nat', 'inventory', 'foreign'}:
        raise Refused('基线格式无效')
    inventory, foreign = value['inventory'], value['foreign']
    if (not isinstance(inventory, list) or any(not isinstance(n, str) for n in inventory)
            or not isinstance(foreign, dict) or inventory != sorted(foreign)
            or len(inventory) > 16):
        raise Refused('基线清单无效')
    h = hashlib.sha256(b'tunlatch-pf-slot-baseline\0')
    def add(data):
        h.update(len(data).to_bytes(8, 'big'))
        h.update(data)
    add(octets(value['root_rules']))
    add(octets(value['root_nat']))
    for name in inventory:
        add(name.encode())
    h.update(len(foreign).to_bytes(8, 'big'))
    for name in inventory:
        pair = foreign[name]
        if not isinstance(pair, list) or len(pair) != 2:
            raise Refused('外部基线无效')
        add(name.encode())
        add(octets(pair[0]))
        add(octets(pair[1]))
    return h.hexdigest()


def check_journals(records, nonce):
    # These are the only sequences the approved normal-return path emits.
    # Keep the encoding tied to Ledger::create/append and Bound::phase_plan.
    write_intent = b'\x01\x03'
    session_digest = hashlib.sha256(records['session.json']).digest()
    for phase, transitions in (
        ('stage', (write_intent,)),
        ('recovery', (write_intent, b'\x02\x03', b'\x04\x00')),
    ):
        observation = records[f'before-{phase}.json']
        plan = hashlib.sha256(session_digest + phase.encode('ascii')
                              + hashlib.sha256(observation).digest()).digest()
        expected = b'TLABLOG\0' + nonce + plan
        tail = hashlib.sha256(expected).digest()
        expected += tail
        for sequence, transition in enumerate(transitions, 1):
            entry = sequence.to_bytes(8, 'big') + transition + tail
            tail = hashlib.sha256(entry).digest()
            expected += entry + tail
        if records[f'{phase}/session.journal'] != expected:
            raise Refused('持久日志与该阶段观察或预期序列不一致')


def audit_records(records, approval, anchor):
    session = parse(records['session.json'])
    if not isinstance(session, dict) or set(session) != {'boot', 'helper', 'nonce', 'created_ticks', 'baseline', 'prepared_observation'}:
        raise Refused('会话格式无效')
    helper, nonce = octets(session['helper']), octets(session['nonce'])
    base, prepared = octets(session['baseline']), octets(session['prepared_observation'])
    if (len(helper) != 32 or helper.hex() != approval['helper_sha256'] or len(nonce) != 32
            or not any(nonce) or anchor != 'tunlatch-lab-' + nonce[:4].hex()
            or session['boot'] != approval['boot'] or type(session['created_ticks']) is not int
            or not 0 < session['created_ticks'] < 2**64 or len(base) != 32
            or base.hex() != approval['baseline_sha256'] or len(prepared) != 32
            or prepared.hex() != sha(records['prepare.json'])):
        raise Refused('会话身份或初始记录不匹配')
    snapshots = []
    for name in NAMES[1:5]:
        obj = parse(records[name])
        if not isinstance(obj, dict) or set(obj) != {'baseline', 'slot'} or baseline(obj['baseline']) != base.hex():
            raise Refused('观察记录或基线不匹配')
        snapshots.append(obj)
    if snapshots[0]['slot'] != 'Absent' or snapshots[1]['slot'] != 'Absent' or snapshots[3]['slot'] != 'Absent':
        raise Refused('观察到的槽位不符合预期')
    candidate = snapshots[2]['slot']
    if not isinstance(candidate, dict) or set(candidate) != {'Active'}:
        raise Refused('恢复前缺少活动槽位字节')
    candidate = octets(candidate['Active'])
    if not 0 < len(candidate) <= 65536:
        raise Refused('恢复前活动槽位长度无效')
    if records['recovery-return.sha256'] != (sha(records['after-recovery.json']) + '\n').encode():
        raise Refused('恢复回读摘要不匹配')
    check_journals(records, nonce)
    return {'baseline_sha256': base.hex(), 'candidate_sha256': sha(candidate),
            'candidate_bytes': len(candidate),
            'record_sha256': {name: sha(data) for name, data in records.items()}}


def phase_directory(runner, phase):
    path = sync.SESSION + '/' + phase
    identity = runner.root('/usr/bin/stat', '-f', '%d:%i:%u:%Lp:%HT', path, limit=256)
    lines = runner.root('/bin/ls', '-lde', path, limit=4096).splitlines()
    if (not re.fullmatch(rb'-?[0-9]+:[0-9]+:0:700:Directory\n', identity)
            or len(lines) != 1 or not lines[0].startswith(b'drwx------ ')):
        raise Refused('受保护阶段目录属性异常')
    return identity


def read_record(runner, name):
    if name not in NAMES and name not in JOURNALS:
        raise Refused('非固定记录')
    path = sync.SESSION + '/' + name
    maximum = JOURNALS.get(name, MAX_RECORD)
    size = sync.staging.inspect_file(runner, path, '600', maximum)
    data = runner.root('/bin/cat', path, limit=maximum)
    if len(data) != size or sync.staging.inspect_file(runner, path, '600', maximum) != size:
        raise Refused('记录读取时变化')
    return data


def audit(runner):
    approval = sync.approved_trial()
    if approval is None or approval['boot'] != sync.stage.boot(runner):
        raise Refused('批准或启动身份不匹配')
    sync.require_local(sync.STAGE_ATTEMPT, approval)
    sync.inspect(runner, sync.audited_digest())
    before = sync.invoke(runner, 'status')
    status = sync.status_phase(before, include_baseline=True)
    if status['phase'] != 'recovery_readback_recorded' or status['active_slot'] != 'absent':
        raise Refused('恢复状态不是已记录且空缺')
    sync.require_local(sync.STAGE_RETURN, {**approval, 'anchor': status['anchor']})
    phases = ('stage', 'recovery')
    identities = tuple(phase_directory(runner, phase) for phase in phases)
    records = {name: read_record(runner, name) for name in (*NAMES, *JOURNALS)}
    result = audit_records(records, approval, status['anchor'])
    sync.inspect(runner, sync.audited_digest())
    if (tuple(phase_directory(runner, phase) for phase in phases) != identities
            or sync.invoke(runner, 'status') != before or sync.stage.boot(runner) != approval['boot']):
        raise Refused('核验期间状态变化')
    return {'status': 'verified', 'anchor': status['anchor'], 'phase': status['phase'], 'active_slot': 'absent',
            'actual_protection': 'unknown', 'recovery_qualified': False, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=('plan', 'audit'))
    if os.geteuid() == 0:
        raise Refused('请以普通用户运行脚本')
    if parser.parse_args().action == 'plan':
        print(json.dumps({'actions': ['audit'], 'pf_writes': 0, 'filesystem_writes': 0}))
        return
    print(json.dumps(audit(sync.stage.Runner()), sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, TypeError, UnicodeError, RecursionError) as error:
        print('停止：' + str(error), file=sys.stderr)
        sys.exit(1)
