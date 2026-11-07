#!/usr/bin/env python3
"""Summarize saved receipts from one closed PF rule-slot session. Never query PF."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


def load_sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load_sibling("_receipt_transport", "identity-readonly.py")
rule = load_sibling("_receipt_rule_profile", "pf-lab-rule.py")
Refused = stage.Refused
ACK = "READ-SAVED-PF-RECEIPTS"
RECORDS = ("boot.txt", "candidate.pf", "empty.pf", "stage.txt", "clear.txt", "closed.json")
STAT = "%u:%Lp:%HT:%l:%z:%d:%i:%m:%c"


def inspect(runner, path, directory):
    raw = runner.root("/usr/bin/stat", "-f", STAT, path, limit=512)
    match = re.fullmatch(rb"0:(\d{3}):([^:\n]+):(\d+):(\d+):(-?\d+):(\d+):(-?\d+):(-?\d+)\n", raw)
    if not match:
        raise Refused("受保护记录的属性无法核实")
    mode, kind, links, size, *_ = match.groups()
    if directory:
        valid = kind == b"Directory" and mode in (b"700", b"755")
        permissions = b"drwx------ " if mode == b"700" else b"drwxr-xr-x "
    else:
        valid = (kind == b"Regular File" and mode in (b"600", b"644")
                 and links == b"1" and int(size) <= rule.MAX_FILE)
        permissions = b"-rw------- " if mode == b"600" else b"-rw-r--r-- "
    lines = runner.root("/bin/ls", "-lde", path, limit=4096).splitlines()
    if not valid or len(lines) != 1 or not lines[0].startswith(permissions):
        raise Refused("受保护记录的类型、权限或 ACL 不合格")
    return raw, mode, int(size)


def exists(runner, path):
    # A dangling symlink is an unexpected object, not an absent receipt.
    for flag in ("-e", "-L"):
        code, output = runner.root("/bin/test", flag, path, limit=512,
                                   allowed_codes=(0, 1), with_code=True)
        if output:
            raise Refused("记录存在性查询返回未知输出")
        if code == 0:
            return True
    return False


def read_record(runner, session, name):
    if name not in RECORDS:
        raise Refused("不允许读取该记录")
    path = session + "/" + name
    before, _, size = inspect(runner, path, directory=False)
    data = runner.root("/bin/cat", path, limit=rule.MAX_FILE)
    if len(data) != size or inspect(runner, path, directory=False)[0] != before:
        raise Refused("记录读取期间变化")
    return data


def closed_record(data):
    # Compare the exact bytes emitted by the two possible successful close branches.
    for state in ("empty", "absent"):
        observed = {
            "payload_absent": True, "slot_state": state,
            "filter_empty": True if state == "empty" else None,
            "anchor_listed_in_inventory": state == "empty",
            "empty_anchor_metadata": "preserved; not global or parent deletion",
            "PF_disabled_zero_references_observed": True,
            "blocking_or_failure_safety_qualified": False,
        }
        if data == (json.dumps(observed, sort_keys=True) + "\n").encode():
            return observed
    raise Refused("关闭记录不是完整的已知格式")


def receipt(data):
    if data is None:
        return {"state": "not_observed"}
    state = "unrecognized"
    try:
        known_notice = rule.LOAD_NOTICE in data.replace(b"\r\n", b"\n")
        if known_notice and not rule.normalize_record(data, load=True):
            state = "load_notice_only"
    except rule.Refused:
        pass
    return {"state": state, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def summarize(runner, requested):
    anchor, candidate = rule.profile(requested)
    session = "/private" + requested
    stage.protected_parents(runner)
    before, mode, _ = inspect(runner, session, directory=True)
    if mode != b"700":
        raise Refused("会话目录须为 root 私有 0700")
    for marker in rule.MARKERS:
        inspect(runner, session + "/" + marker, directory=True)
    boot = rule.reference.transcript(read_record(runner, session, "boot.txt")).lower()
    if not rule.reference.UUID.fullmatch(boot):
        raise Refused("启动记录格式错误")
    if read_record(runner, session, "candidate.pf") != candidate or read_record(runner, session, "empty.pf"):
        raise Refused("归档候选或空恢复文件与固定范围不一致")
    staged = receipt(read_record(runner, session, "stage.txt"))
    clear_path = session + "/clear.txt"
    has_clear = exists(runner, clear_path)
    cleared = receipt(read_record(runner, session, "clear.txt") if has_clear else None)
    closed = closed_record(read_record(runner, session, "closed.json"))
    if exists(runner, clear_path) != has_clear or inspect(runner, session, directory=True)[0] != before:
        raise Refused("会话目录读取期间变化")
    stage.protected_parents(runner)
    branch = ("consistent_with_matching_nonempty_pre_clear"
              if staged["state"] == cleared["state"] == "load_notice_only" else "unknown")
    return {
        "purpose": "historical_rule_receipts", "session": requested, "anchor": anchor,
        "current_boot_matches_receipt": boot.decode().strip() == stage.boot(runner),
        "stage_receipt": staged, "clear_receipt": cleared, "recorded_close": closed,
        "recovery_branch_inference": branch, "pre_clear_raw_snapshot": "not_recorded",
        "executed_source_verified": False,
        "inference_requires": "receipts created by the audited recover flow without substitution",
        "recorded_close_is_historical": True,
        "live_pf_queries": 0, "pf_writes": 0, "ownership": "unknown",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", help="closed /var/root/tunlatch-pf-rule.XXXXXXXX session")
    parser.add_argument("--ack", required=True, choices=(ACK,))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("以普通用户执行脚本，在同一终端完成系统认证")
    print(json.dumps(summarize(stage.Runner(), args.session), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (Refused, rule.Refused, OSError, ValueError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("中断：已保留原始记录。", file=sys.stderr)
        sys.exit(2)
