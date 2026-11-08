#!/usr/bin/env python3
"""Isolated PF abnormal-return trial controller; never run as root.

Deployment and status are read-only with respect to PF. PF mutation is disabled
until the exact binary and a separate trial scope have been reviewed and approved.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


def load_operator(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name('pf-lab-sync.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Two independent module instances: the old protected deployment must be checked
# with its own fixed paths and digest, not with the new experiment's parameters.
old = load_operator('_pf_sync_previous')
base = load_operator('_pf_sync_fault_base')
stage = base.stage
Refused = base.Refused
SESSION = '/private/var/root/tunlatch-pf-sync-fault'
HELPER = SESSION + '/pf-lab-sync'
MANIFEST = SESSION + '/operator-manifest.json'
MODE = 'pf-sync-fault-after-submit'
SOURCE = Path(__file__).resolve().parent.parent / 'target/pf-sync-fault/release/examples/pf_lab_sync'
LOCAL_TRIAL = Path(__file__).resolve().parent.parent / 'docs/.pf-lab-sync-fault'
APPROVAL = LOCAL_TRIAL / 'approval.json'
STAGE_ATTEMPT = LOCAL_TRIAL / 'stage-attempt.json'
AUDITED_BINARY_SHA256 = '2f4220c54c322bc25ff3e78a7606a52014ae0d150c39f08e670b0b2291494cd5'
base.SESSION = SESSION
base.HELPER = HELPER
base.MANIFEST = MANIFEST
base.MODE = MODE
base.SOURCE = SOURCE
base.APPROVAL = APPROVAL
base.STAGE_ATTEMPT = STAGE_ATTEMPT
base.staging.SOURCE = SOURCE
stage.SOURCE = SOURCE


def audited_digest():
    if AUDITED_BINARY_SHA256 is None:
        raise Refused('尚无经独立审阅的新构建摘要；所有特权操作关闭')
    return stage.checked_digest(AUDITED_BINARY_SHA256)


def check_previous_closed(runner):
    """Recheck the old root-owned helper, manifest, ledger and live readback."""
    expected = old.audited_digest()
    approval = old.approved_trial()
    if approval is None:
        raise Refused('旧实验的本地批准记录缺失；保留现场')
    old.inspect(runner, expected)
    previous = old.status_phase(old.invoke(runner, 'status'), include_baseline=True)
    if previous['phase'] != 'recovery_readback_recorded' or previous['active_slot'] != 'absent':
        raise Refused('旧实验没有确认关闭并清空；保留现场')
    old.require_local(old.STAGE_RETURN, {**approval, 'anchor': previous['anchor']})
    return approval['baseline_sha256']


def prepare(runner, expected):
    previous_baseline = check_previous_closed(runner)
    raw = base.prepare(runner, expected)
    if parse_status(raw).get('baseline_sha256') != previous_baseline:
        raise Refused('新预检基线与已关闭旧实验不同；保留现场')
    return raw


def parse_status(raw):
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=base.unique_fields)
        phase = obj['phase']
        allowed = {'preflight_ready', 'prepared', 'fault_writer_reaped', 'fault_unconfirmed',
                   'recovery_unknown', 'recovery_readback_verified', 'recovery_readback_recorded'}
        if phase not in allowed:
            raise ValueError('unknown phase')
        # Reuse the old report shape validator, whose not_read phase has a different name.
        validation = dict(obj)
        if phase == 'fault_writer_reaped' and obj.get('active_slot') == 'not_read':
            validation['phase'] = 'submit_returned_unverified'
        if phase in ('fault_unconfirmed', 'fault_writer_reaped') and obj.get('active_slot') == 'unrecognized':
            validation['phase'] = 'stage_outcome_unknown'
        base.status_phase(json.dumps(validation).encode())
        return obj
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        raise Refused('helper 状态 JSON 或阶段无效；保留现场') from error


def invoke(runner, action):
    if action not in ('prepare', 'status', 'stage-fault', 'recover-fault'):
        raise Refused('未知 helper 动作')
    # Reuse bounded execution and strict error handling from the old operator.
    if action in ('prepare', 'status'):
        return base.invoke(runner, action)
    code, output = runner.root(HELPER, action, limit=base.HELPER_OUTPUT_LIMIT,
                               allowed_codes=(0, 1), with_code=True, timeout=base.HELPER_TIMEOUT)
    return base.checked_helper_output(code, output)


def status(runner, expected):
    base.inspect(runner, expected)
    raw = invoke(runner, 'status')
    parse_status(raw)
    return raw


def execute(runner, action, expected, confirm=input, *, approval=None):
    if action == 'prepare':
        return prepare(runner, expected)
    if action == 'status':
        return status(runner, expected)
    if action not in ('stage-fault', 'recover-fault') or approval is None:
        raise Refused('本次异常返回实验的 PF 写入尚未单独审阅和批准')
    if (approval.get('helper_sha256') != expected
            or approval.get('boot') != stage.boot(runner)):
        raise Refused('本次批准与 helper 或当前启动不匹配')
    before = status(runner, expected)
    previous = parse_status(before)
    if action == 'stage-fault':
        if (previous['phase'] != 'preflight_ready'
                or previous.get('baseline_sha256') != approval.get('baseline_sha256')):
            raise Refused('当前阶段或基线与批准不符；保留现场')
        ack = 'STAGE-PF-SYNC-FAULT'
    else:
        base.require_local(STAGE_ATTEMPT, approval)
        if (previous['phase'] != 'fault_writer_reaped'
                or previous['active_slot'] not in ('absent', 'empty', 'candidate')):
            raise Refused('缺少受保护的写入者终止证明或槽位无法识别；保留现场')
        ack = 'RECOVER-PF-SYNC-FAULT'
    print('只读状态：\n' + before.decode('utf-8', 'strict'), flush=True)
    if confirm('请输入 ' + ack + '：') != ack:
        raise Refused('未确认本次动作')
    if status(runner, expected) != before:
        raise Refused('确认期间状态发生变化；保留现场')
    if action == 'recover-fault':
        raw = invoke(runner, action)
        result = parse_status(raw)
        if (result['phase'] != 'recovery_readback_verified'
                or result['anchor'] != previous['anchor']
                or result['active_slot'] not in ('absent', 'empty')):
            raise Refused('恢复回读未验证；保留现场')
        return raw
    base.save_local(STAGE_ATTEMPT, approval)
    initialized = parse_status(invoke(runner, 'prepare'))
    if (initialized['phase'] != 'prepared'
            or initialized.get('baseline_sha256') != approval['baseline_sha256']):
        raise Refused('初始化阶段或基线与批准不一致；保留现场')
    raw = invoke(runner, action)
    result = parse_status(raw)
    if (result['phase'] != 'fault_writer_reaped' or result['active_slot'] != 'not_read'
            or result['anchor'] != initialized['anchor']):
        raise Refused('未确认写入者被终止；保留现场')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan',
                        choices=('plan', 'prepare', 'status', 'stage-fault', 'recover-fault'))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused('不要 sudo 整个程序')
    base.AUDITED_BINARY_SHA256 = AUDITED_BINARY_SHA256
    runner = stage.Runner()
    approval = (base.approved_trial()
                if args.action in ('plan', 'stage-fault', 'recover-fault') else None)
    if args.action == 'plan':
        actions = ['prepare', 'status'] if AUDITED_BINARY_SHA256 else []
        write_approved = bool(actions and approval and approval['boot'] == stage.boot(runner))
        if write_approved:
            actions.extend(['stage-fault', 'recover-fault'])
        print(json.dumps({'directory': SESSION, 'helper': HELPER,
                          'digest_reviewed': AUDITED_BINARY_SHA256 is not None,
                          'pf_writes_reviewed': write_approved,
                          'actions': actions,
                          'limitations': ['原实验批准不适用于本实验。',
                                          '超时或中断时保留现场，状态可能未知。']},
                         ensure_ascii=False, indent=2))
        return
    result = execute(runner, args.action, audited_digest(), approval=approval)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except (Refused, old.Refused, OSError, ValueError, UnicodeError) as error:
        print('停止：' + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('中断：保留现场；特权命令树和 PF 状态可能未知。', file=sys.stderr)
        sys.exit(2)
