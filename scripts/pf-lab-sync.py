#!/usr/bin/env python3
"""Fixed, manually operated PF synchronization experiment; never run as root.

No digest is approved until the exact release build is independently reviewed.
Timeouts and interruptions leave the privileged process tree and PF state unknown.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

_spec = importlib.util.spec_from_file_location(
    "_pf_sync_staging", Path(__file__).with_name("utun-mapping.py"))
staging = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(staging)
stage = staging.stage
Refused = stage.Refused
SOURCE = Path(__file__).resolve().parent.parent / "target/release/examples/pf_lab_sync"
SESSION = "/private/var/root/tunlatch-pf-sync"
HELPER = SESSION + "/pf-lab-sync"
MANIFEST = SESSION + "/operator-manifest.json"
MODE = "pf-sync-manual-trial"
HELPER_TIMEOUT = 45
HELPER_OUTPUT_LIMIT = 4096
# Replace only after independent review of the precise release binary.
AUDITED_BINARY_SHA256 = "3afeab571c1b43be8c26816d65747cb95e7a09a64dcb1213015583af76101365"
OLD_PREFLIGHT_SHA256 = "4fa655e5913edebf2515f4ab182130e3592c913e731bf4e8a468b5380f341257"
LOCAL_TRIAL = Path(__file__).resolve().parent.parent / "docs" / ".pf-lab-sync"
APPROVAL = LOCAL_TRIAL / "approval.json"
STAGE_ATTEMPT = LOCAL_TRIAL / "stage-attempt.json"
STAGE_RETURN = LOCAL_TRIAL / "stage-return.json"
TRIAL_ACTIONS = ("stage", "recover", "capture-unknown")
staging.SOURCE = SOURCE
stage.SOURCE = SOURCE


def unique_fields(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field")
        obj[key] = value
    return obj


def check_local_directory(path):
    info = os.lstat(path.parent)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Refused("本地实验记录目录不是本人独占的 0700 目录")


def read_local(path):
    check_local_directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as record:
        info = os.fstat(record.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 512):
            raise Refused("本地实验记录的权限、类型或大小无效")
        raw = record.read(513)
    if len(raw) != info.st_size:
        raise Refused("本地实验记录读取期间变化")
    return json.loads(raw, object_pairs_hook=unique_fields)


def save_local(path, value):
    check_local_directory(path)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as record:
        os.fchmod(record.fileno(), 0o600)
        record.write(data)
        record.flush()
        os.fsync(record.fileno())
    if read_local(path) != value:
        raise Refused("本地实验记录回读不一致；保留现场")


def approved_trial():
    try:
        approval = read_local(APPROVAL)
    except FileNotFoundError:
        return None
    if (not isinstance(approval, dict)
            or set(approval) != {"helper_sha256", "baseline_sha256", "boot"}
            or approval["helper_sha256"] != AUDITED_BINARY_SHA256
            or not isinstance(approval["baseline_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", approval["baseline_sha256"])
            or not isinstance(approval["boot"], str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", approval["boot"])):
        raise Refused("本地单槽实验批准记录无效")
    return approval


def require_local(path, expected):
    try:
        matched = read_local(path) == expected
    except FileNotFoundError:
        matched = False
    if not matched:
        raise Refused("缺少匹配的本次暂存记录；保留现场")


def audited_digest():
    if AUDITED_BINARY_SHA256 is None:
        raise Refused("尚无经独立审阅的构建摘要；所有特权操作关闭")
    return stage.checked_digest(AUDITED_BINARY_SHA256)


def manifest(expected, boot):
    return (json.dumps({"boot": boot, "mode": MODE, "sha256": expected},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def inspect(runner, expected):
    stage.protected_parents(runner)
    if runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT", SESSION) != b"0:700:Directory\n":
        raise Refused("固定目录不是 root 独占目录")
    listing = runner.root("/bin/ls", "-lde", SESSION).splitlines()
    if len(listing) != 1 or not listing[0].startswith(b"drwx------ "):
        raise Refused("固定目录 ACL 异常")
    size = staging.inspect_file(runner, HELPER, "500", stage.MAX_BINARY)
    digest = runner.root("/usr/bin/shasum", "-a", "256", HELPER, limit=4096)
    if digest != (expected + "  " + HELPER + "\n").encode():
        raise Refused("受保护 helper 摘要不匹配")
    length = staging.inspect_file(runner, MANIFEST, "600", 512)
    data = runner.root("/bin/cat", MANIFEST, limit=512)
    if len(data) != length or data != manifest(expected, stage.boot(runner)):
        raise Refused("记录不匹配当前启动、实验模式或摘要")
    return size


def invoke(runner, action):
    if action not in ("prepare", "status", "stage", "recover", "capture-unknown"):
        raise Refused("未知 helper 动作")
    code, output = runner.root(HELPER, action, limit=HELPER_OUTPUT_LIMIT,
                               allowed_codes=(0, 1), with_code=True, timeout=HELPER_TIMEOUT)
    if code == 0:
        return output

    try:
        obj = json.loads(output.decode("utf-8", "strict"), object_pairs_hook=unique_fields)
        if (not isinstance(obj, dict) or set(obj) != {"result", "reason"}
                or obj["result"] != "refused" or not isinstance(obj["reason"], str)
                or not 1 <= len(obj["reason"]) <= 200
                or not all(char.isprintable() for char in obj["reason"])):
            raise ValueError("invalid refusal")
    except (ValueError, UnicodeError) as error:
        raise Refused("helper 返回非零且拒绝信息无效；保留现场，状态未知") from error
    raise Refused("helper 拒绝：" + obj["reason"] + "；保留现场")


def prepare(runner, expected):
    data = staging.source_bytes(expected)
    stage.dependencies(runner, expected)
    stage.protected_parents(runner)
    boot = stage.boot(runner)
    # mkdir is intentionally exclusive: existing or partially prepared trials
    # are never reused, reset, or removed by this operator.
    runner.root("/bin/mkdir", "-m", "700", SESSION)
    print("固定目录已创建；失败或中断时保留现场：" + SESSION, file=sys.stderr, flush=True)
    if runner.root("/usr/bin/tee", HELPER, data=data, limit=stage.MAX_BINARY) != data:
        raise Refused("helper 写入不完整")
    runner.root("/bin/chmod", "500", HELPER)
    record = manifest(expected, boot)
    if runner.root("/usr/bin/tee", MANIFEST, data=record, limit=512) != record:
        raise Refused("记录写入不完整")
    runner.root("/bin/chmod", "600", MANIFEST)
    if inspect(runner, expected) != len(data):
        raise Refused("受保护 helper 长度不匹配")
    status = invoke(runner, "status")
    if status_phase(status) != "preflight_ready":
        raise Refused("首次检查未报告 preflight_ready；保留现场")
    return status


def status_phase(raw, *, include_baseline=False):
    try:
        obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_fields)
        if not isinstance(obj, dict):
            raise ValueError("invalid phase")
        phase = obj["phase"]
        keys = {"scope", "anchor", "phase", "active_slot", "actual_protection",
                "recovery_qualified"}
        if (not isinstance(phase, str) or obj["scope"] != "unattached_filter_trial"
                or obj["actual_protection"] != "unknown" or obj["recovery_qualified"] is not False):
            raise ValueError("invalid report")
        if phase == "preflight_ready":
            if (set(obj) != keys | {"baseline_sha256"} or obj["anchor"] != "not_allocated"
                    or obj["active_slot"] != "absent"
                    or not isinstance(obj["baseline_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", obj["baseline_sha256"])):
                raise ValueError("invalid preflight")
        elif (set(obj) - {"slot_sha256", "slot_bytes"} not in (keys, keys | {"baseline_sha256"})
              or ("baseline_sha256" in obj and
                  (phase != "prepared" or not isinstance(obj["baseline_sha256"], str)
                   or not re.fullmatch(r"[0-9a-f]{64}", obj["baseline_sha256"])))
              or not isinstance(obj["anchor"], str)
              or not re.fullmatch(r"tunlatch-lab-[0-9a-f]{8}", obj["anchor"])
              or (obj["active_slot"] != "not_read" if phase == "submit_returned_unverified"
                  else obj["active_slot"] not in ("absent", "empty", "candidate", "unrecognized"))
              or (phase == "prepared" and obj["active_slot"] != "absent")):
            raise ValueError("invalid trial report")
        if obj["active_slot"] == "unrecognized":
            if (phase not in ("stage_intent_unsettled", "stage_outcome_unknown", "recovery_unknown")
                    or not isinstance(obj["slot_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", obj["slot_sha256"])
                    or type(obj["slot_bytes"]) is not int or not 1 <= obj["slot_bytes"] <= 65536):
                raise ValueError("invalid unknown slot metadata")
        elif {"slot_sha256", "slot_bytes"} & obj.keys():
            raise ValueError("unexpected unknown slot metadata")
        return obj if include_baseline else phase
    except (ValueError, UnicodeError, KeyError, TypeError) as error:
        raise Refused("helper 状态 JSON 或阶段无效；保留现场") from error


def directory_identity(runner, path):
    raw = runner.root("/usr/bin/stat", "-f", "%d:%i:%u:%Lp:%HT", path, limit=256)
    match = re.fullmatch(rb"(-?[0-9]+):([0-9]+):0:700:Directory\n", raw)
    lines = runner.root("/bin/ls", "-lde", path, limit=4096).splitlines()
    if not match or len(lines) != 1 or not lines[0].startswith(b"drwx------ "):
        raise Refused("归档路径的目录身份或 ACL 不合格；保留现场")
    return match.groups()


def replace_preflight(runner, expected):
    if expected == OLD_PREFLIGHT_SHA256:
        raise Refused("替换需要经独立审阅的新构建摘要")
    # Verify the replacement and dependencies before moving the existing copy.
    staging.source_bytes(expected)
    stage.dependencies(runner, expected)

    def check_old():
        inspect(runner, OLD_PREFLIGHT_SHA256)
        if runner.root("/bin/ls", "-1A", SESSION, limit=512) != (
                b"operator-manifest.json\npf-lab-sync\n"):
            raise Refused("旧目录成员不符合纯预检部署；保留现场")
        raw = invoke(runner, "status")
        if status_phase(raw) != "preflight_ready":
            raise Refused("旧部署不是纯预检状态；保留现场")
        return raw

    before = check_old()
    original = directory_identity(runner, SESSION)
    if check_old() != before:
        raise Refused("旧部署状态发生变化；保留现场")
    raw_archive = runner.root("/usr/bin/mktemp", "-d",
                              "/private/var/root/tunlatch-pf-sync-archive.XXXXXXXX", limit=256)
    if not re.fullmatch(rb"/private/var/root/tunlatch-pf-sync-archive\.[A-Za-z0-9]{8}\n", raw_archive):
        raise Refused("归档目录输出无效；保留现场")
    archive = raw_archive.decode("ascii").strip()
    print("旧部署归档目录（失败或中断时保留）：" + archive, file=sys.stderr, flush=True)
    archived = archive + "/tunlatch-pf-sync"
    if (directory_identity(runner, archive)[0] != original[0]
            or runner.root("/bin/ls", "-1A", archive, limit=512) != b""):
        raise Refused("归档目录不在同一文件系统或非空；保留现场：" + archive)
    # Recheck after creating the archive, immediately before the no-clobber move.
    if check_old() != before or directory_identity(runner, SESSION) != original:
        raise Refused("旧部署状态发生变化；保留现场：" + archive)
    runner.root("/bin/mv", "-n", SESSION, archived)
    if directory_identity(runner, archived) != original:
        raise Refused("归档目录与原部署身份不一致；保留现场：" + archive)
    return prepare(runner, expected)


def execute(runner, action, expected, confirm=input, *, approval=None):
    if action == "prepare":
        return prepare(runner, expected)
    if action == "replace-preflight":
        return replace_preflight(runner, expected)
    if action not in ("status", *TRIAL_ACTIONS):
        raise Refused("未知动作")
    if action in TRIAL_ACTIONS and (approval is None or approval["helper_sha256"] != expected
                                    or approval["boot"] != stage.boot(runner)):
        raise Refused("本次批准与 helper 或当前启动不匹配")
    inspect(runner, expected)
    before = invoke(runner, "status")
    previous = status_phase(before, include_baseline=True)
    phase = previous["phase"]
    if action == "status":
        return before
    if action != "stage":
        require_local(STAGE_ATTEMPT, approval)
    if action == "capture-unknown":
        if (phase not in ("stage_intent_unsettled", "stage_outcome_unknown", "recovery_unknown")
                or previous["active_slot"] != "unrecognized"):
            raise Refused("当前状态不允许记录未知槽位；保留现场")
        return invoke(runner, action)
    if action == "stage" and (phase != "preflight_ready"
                              or previous["baseline_sha256"] != approval["baseline_sha256"]):
        raise Refused("当前阶段或基线与获准的首次暂存不符；保留现场")
    if action == "recover":
        if phase != "stage_intent_unsettled" or previous["active_slot"] == "unrecognized":
            raise Refused("当前阶段或槽位不允许人工恢复；保留现场")
        require_local(STAGE_RETURN, {**approval, "anchor": previous["anchor"]})
    print("只读状态：\n" + before.decode("utf-8", "strict"), flush=True)
    print("确认当前试验独占、原写入者已结束，独立核查期限及现场；不确定时停止。", flush=True)
    ack = "STAGE-PF-SYNC" if action == "stage" else "TAKEOVER-PF-SYNC-RECOVERY"
    if confirm("请输入 " + ack + "：") != ack:
        raise Refused("未确认本次动作")
    inspect(runner, expected)
    after = invoke(runner, "status")
    if before != after:
        raise Refused("确认期间状态发生变化；保留现场")
    if action == "recover":
        return invoke(runner, action)
    save_local(STAGE_ATTEMPT, approval)
    initialized = status_phase(invoke(runner, "prepare"), include_baseline=True)
    if (initialized["phase"] != "prepared"
            or initialized.get("baseline_sha256") != approval["baseline_sha256"]):
        raise Refused("初始化阶段或基线与批准不一致；保留现场")
    raw = invoke(runner, "stage")
    submitted = status_phase(raw, include_baseline=True)
    if (submitted["phase"] != "submit_returned_unverified"
            or submitted["anchor"] != initialized["anchor"]):
        raise Refused("缺少本次提交正常返回记录；保留现场")
    save_local(STAGE_RETURN, {**approval, "anchor": initialized["anchor"]})
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan",
                        choices=("plan", "prepare", "replace-preflight", "status", "stage", "recover",
                                 "capture-unknown"))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("不要 sudo 整个程序")
    approval = approved_trial() if args.action != "status" else None
    if args.action == "plan":
        actions = ["status"] if AUDITED_BINARY_SHA256 is not None else []
        if actions and approval:
            actions.extend(TRIAL_ACTIONS)
        elif actions:
            actions.append("prepare")
            if AUDITED_BINARY_SHA256 != OLD_PREFLIGHT_SHA256:
                actions.append("replace-preflight")
        print(json.dumps({"directory": SESSION, "helper": HELPER,
                          "actions": actions, "pf_writes_reviewed": approval is not None,
                          "digest_reviewed": AUDITED_BINARY_SHA256 is not None,
                          "limits": ["已有目录即拒绝，绝不自动删除或重用。",
                                     "暂存和恢复分别需要在场确认、独立检查有效期限及连续独占。",
                                     "超时、中断或异常保留现场，特权命令树和 PF 状态可能未知。",
                                     "实验不证明实际保护或自动恢复。"]}, ensure_ascii=False, indent=2))
        return
    if args.action in TRIAL_ACTIONS and approval is None:
        raise Refused("PF 写入尚未获得单独审阅与批准")
    if args.action in ("prepare", "replace-preflight") and approval is not None:
        raise Refused("本次批准只覆盖已部署的单槽实验；保留当前部署")
    expected = audited_digest()
    result = execute(stage.Runner(), args.action, expected, approval=approval)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, UnicodeError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留现场；特权命令树和 PF 状态可能未知。", file=sys.stderr)
        sys.exit(2)
