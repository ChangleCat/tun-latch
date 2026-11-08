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
AUDITED_BINARY_SHA256 = "4fa655e5913edebf2515f4ab182130e3592c913e731bf4e8a468b5380f341257"
# Requires a separate scope review and approval before any real PF write.
PF_WRITES_REVIEWED = False
staging.SOURCE = SOURCE
stage.SOURCE = SOURCE


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
    if action not in ("prepare", "status", "stage", "recover"):
        raise Refused("未知 helper 动作")
    code, output = runner.root(HELPER, action, limit=HELPER_OUTPUT_LIMIT,
                               allowed_codes=(0, 1), with_code=True, timeout=HELPER_TIMEOUT)
    if code == 0:
        return output

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate field")
            obj[key] = value
        return obj

    try:
        obj = json.loads(output.decode("utf-8", "strict"), object_pairs_hook=unique)
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
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate field")
            obj[key] = value
        return obj
    try:
        obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
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
        elif (set(obj) not in (keys, keys | {"baseline_sha256"})
              or ("baseline_sha256" in obj and
                  (phase != "prepared" or not isinstance(obj["baseline_sha256"], str)
                   or not re.fullmatch(r"[0-9a-f]{64}", obj["baseline_sha256"])))
              or not isinstance(obj["anchor"], str)
              or not re.fullmatch(r"tunlatch-lab-[0-9a-f]{8}", obj["anchor"])
              or obj["active_slot"] not in ("absent", "empty", "candidate")
              or (phase == "prepared" and obj["active_slot"] != "absent")):
            raise ValueError("invalid trial report")
        return obj if include_baseline else phase
    except (ValueError, UnicodeError, KeyError, TypeError) as error:
        raise Refused("helper 状态 JSON 或阶段无效；保留现场") from error


def execute(runner, action, expected, confirm=input):
    if action == "prepare":
        return prepare(runner, expected)
    if action not in ("status", "stage", "recover"):
        raise Refused("未知动作")
    inspect(runner, expected)
    before = invoke(runner, "status")
    previous = status_phase(before, include_baseline=True)
    phase = previous["phase"]
    if action == "status":
        return before
    if action == "stage" and phase not in ("preflight_ready", "prepared"):
        raise Refused("当前阶段不允许首次暂存；保留现场")
    if action == "recover" and phase not in ("stage_intent_unsettled", "stage_outcome_unknown"):
        raise Refused("当前阶段不允许人工恢复；保留现场")
    print("只读状态：\n" + before.decode("utf-8", "strict"), flush=True)
    print("确认当前试验独占、原写入者已结束，独立核查期限及现场；不确定时停止。", flush=True)
    ack = "STAGE-PF-SYNC" if action == "stage" else "TAKEOVER-PF-SYNC-RECOVERY"
    if confirm("请输入 " + ack + "：") != ack:
        raise Refused("未确认本次动作")
    inspect(runner, expected)
    after = invoke(runner, "status")
    if before != after:
        raise Refused("确认期间状态发生变化；保留现场")
    if action == "stage" and phase == "preflight_ready":
        prepared = invoke(runner, "prepare")
        initialized = status_phase(prepared, include_baseline=True)
        if (initialized["phase"] != "prepared"
                or initialized.get("baseline_sha256") != previous["baseline_sha256"]):
            raise Refused("初始化阶段或基线与确认的预检不一致；保留现场")
    return invoke(runner, action)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan",
                        choices=("plan", "prepare", "status", "stage", "recover"))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("不要 sudo 整个程序")
    if args.action == "plan":
        actions = ["prepare", "status"] if AUDITED_BINARY_SHA256 is not None else []
        if actions and PF_WRITES_REVIEWED:
            actions.extend(["stage", "recover"])
        print(json.dumps({"directory": SESSION, "helper": HELPER,
                          "actions": actions, "pf_writes_reviewed": PF_WRITES_REVIEWED,
                          "digest_reviewed": AUDITED_BINARY_SHA256 is not None,
                          "limits": ["已有目录即拒绝，绝不自动删除或重用。",
                                     "暂存和恢复分别需要在场确认、独立检查有效期限及连续独占。",
                                     "超时、中断或异常保留现场，特权命令树和 PF 状态可能未知。",
                                     "实验不证明实际保护或自动恢复。"]}, ensure_ascii=False, indent=2))
        return
    if args.action in ("stage", "recover") and not PF_WRITES_REVIEWED:
        raise Refused("PF 写入尚未获得单独审阅与批准")
    expected = audited_digest()
    result = execute(stage.Runner(), args.action, expected)
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
