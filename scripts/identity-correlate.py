#!/usr/bin/env python3
"""Manual one-shot administrator correlation operator; never run this client as root.

A timeout or interruption leaves the privileged command tree state unknown. This development tool neither establishes trust nor protection.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

# Load a private module instance so the fixed helper profile cannot affect the
# existing identity operator, even when both modules are imported in one process.
_spec = importlib.util.spec_from_file_location("_correlate_stage_identity", Path(__file__).with_name("identity-readonly.py"))
stage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage)
Refused = stage.Refused
SOURCE = Path(__file__).resolve().parent.parent / "target/release/examples/identity_correlate"
SESSION = re.compile(r"/private/var/root/tunlatch-identity-correlate\.[A-Za-z0-9]{8}\Z")
MODE = "read-one-proxy"
ACK = "READ-ONE-PROXY"
INTERPRETATION = "candidate 只是一次只读相关性观察，不证明 TUN 归属、授权或实际保护。"
# Filled only after independent review of this exact release binary.
AUDITED_BINARY_SHA256 = "cde43acff699f8adfa9e702976aade4ec4f77a1a54e34baeea9936468750c4eb"
stage.SOURCE = SOURCE


def source_bytes(expected):
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or not 0 < before.st_size <= stage.MAX_BINARY):
            raise Refused("源文件属主、类型、链接数或大小不合格")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise Refused("源文件读取不完整")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        path = os.stat(SOURCE, follow_symlinks=False)
        def fields(s):
            return (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size,
                    s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        if fields(before) != fields(after) or fields(before) != fields(path):
            raise Refused("源文件读取期间变化")
        data = b"".join(chunks)
        if hashlib.sha256(data).hexdigest() != expected:
            raise Refused("源文件不匹配已独立审阅的 SHA-256")
        return data
    finally:
        os.close(fd)


stage.source_bytes = source_bytes


def session_path(value):
    if not SESSION.fullmatch(value):
        raise Refused("不是本工具格式的私有会话路径")
    return value


def inspect_session(runner, session):
    session_path(session)
    if runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT", session) != b"0:700:Directory\n":
        raise Refused("会话目录不是 root 独占目录")
    lines = runner.root("/bin/ls", "-lde", session).splitlines()
    if len(lines) != 1 or not lines[0].startswith(b"drwx------ "):
        raise Refused("会话目录 ACL 异常")


def inspect_file(runner, path, mode, maximum):
    meta = runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT:%l:%z", path).decode().strip().split(":")
    if (len(meta) != 5 or meta[:4] != ["0", mode, "Regular File", "1"]
            or not meta[4].isdigit() or not 0 < int(meta[4]) <= maximum):
        raise Refused("受保护文件属性异常")
    listing = runner.root("/bin/ls", "-lde", path).splitlines()
    prefix = b"-r-x------ " if mode == "500" else b"-rw------- "
    if len(listing) != 1 or not listing[0].startswith(prefix):
        raise Refused("受保护文件 ACL 异常")
    return int(meta[4])


def inspect(runner, session, expected):
    inspect_session(runner, session)
    path = session + "/identity_correlate"
    size = inspect_file(runner, path, "500", stage.MAX_BINARY)
    digest = runner.root("/usr/bin/shasum", "-a", "256", path, limit=4096)
    if digest != (expected + "  " + path + "\n").encode():
        raise Refused("受保护副本 SHA-256 不匹配")
    return size

def checked_cdhash(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value) or value == "0" * 40:
        raise argparse.ArgumentTypeError("CDHash 须为非零的 40 位小写十六进制")
    return value


def manifest_bytes(expected, pid, cdhash, boot_id):
    return (json.dumps({"boot": boot_id, "mode": MODE, "sha256": expected,
                        "pid": int(pid), "cdhash": cdhash},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def check_manifest(runner, session, expected, pid, cdhash):
    path = session + "/manifest.json"
    size = inspect_file(runner, path, "600", 512)
    data = runner.root("/bin/cat", path, limit=512)
    if len(data) != size or data != manifest_bytes(expected, pid, cdhash, stage.boot(runner)):
        raise Refused("会话记录不匹配当前启动、模式、摘要或目标")


def prepare(runner, expected, pid, cdhash):
    data = source_bytes(expected)
    stage.dependencies(runner, expected)
    stage.protected_parents(runner)
    boot_id = stage.boot(runner)
    session = runner.root("/usr/bin/mktemp", "-d", "/private/var/root/tunlatch-identity-correlate.XXXXXXXX", limit=4096).decode().strip()
    session_path(session)
    print("会话已创建：" + session, file=sys.stderr, flush=True)
    inspect_session(runner, session)
    path = session + "/identity_correlate"
    if runner.root("/usr/bin/tee", path, data=data, limit=stage.MAX_BINARY) != data:
        raise Refused("暂存副本写入不完整")
    runner.root("/bin/chmod", "500", path)
    size = inspect(runner, session, expected)
    if size != len(data):
        raise Refused("受保护副本大小不匹配")
    record = manifest_bytes(expected, pid, cdhash, boot_id)
    path = session + "/manifest.json"
    if runner.root("/usr/bin/tee", path, data=record, limit=512) != record:
        raise Refused("会话记录写入不完整")
    runner.root("/bin/chmod", "600", path)
    check_manifest(runner, session, expected, pid, cdhash)
    return session, size


# Only fixed helper codes may appear in an unavailable diagnostic.
REASONS = frozenset({"invalid_input", "admin_required", "target_uid_mismatch",
                     "image_unavailable", "image_mismatch", "raw_incomplete", "process_changed",
                     "no_utun_control", "ambiguous_control", "invalid_control", "network_unavailable",
                     "interface_changed", "clock_unavailable", "timed_out"})


def validate_result(raw, pid, cdhash):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        obj = json.loads(raw, object_pairs_hook=unique)
        common = {"result", "tun_ownership", "actual_protection", "authorization"}
        if (not isinstance(obj, dict) or obj.get("tun_ownership") != "unknown"
                or obj.get("actual_protection") != "unknown" or obj.get("authorization") != "none"):
            raise ValueError("boundary")
        if obj["result"] == "unavailable":
            if set(obj) != common | {"reason"} or obj["reason"] not in REASONS:
                raise ValueError("reason")
        elif obj["result"] == "candidate":
            if set(obj) != common | {"basis", "process", "fd", "control_id", "unit", "ifname", "ifindex", "sampling_milliseconds", "matched_expected_cdhash"}:
                raise ValueError("fields")
            process = obj["process"]
            if (not isinstance(process, dict) or set(process) != {"pid", "effective_uid", "birth_seconds", "birth_microseconds"}
                    or any(type(v) is not int for v in process.values())
                    or process["pid"] != int(pid) or process["effective_uid"] != 0
                    or not 0 < process["birth_seconds"] <= 9223372036854775807
                    or not 0 <= process["birth_microseconds"] < 1000000):
                raise ValueError("process")
            for key, low, high in (("fd", 0, 2147483647), ("control_id", 1, 4294967295),
                                   ("unit", 1, 4294967295), ("ifindex", 1, 4294967295),
                                   ("sampling_milliseconds", 0, 999)):
                if type(obj[key]) is not int or not low <= obj[key] <= high:
                    raise ValueError("number")
            if (obj["basis"] != "utun_control_unit_minus_one" or obj["matched_expected_cdhash"] != cdhash
                    or obj["ifname"] != "utun" + str(obj["unit"] - 1) or len(obj["ifname"].encode()) >= 16):
                raise ValueError("candidate")
        else:
            raise ValueError("result")
        return obj
    except (ValueError, TypeError, UnicodeError, KeyError) as error:
        raise Refused("结果格式或边界不合格；保留现场，状态未知") from error


def sample(runner, session, expected, pid, cdhash):
    stage.protected_parents(runner)
    size = inspect(runner, session, expected)
    check_manifest(runner, session, expected, pid, cdhash)
    # Atomic one-shot marker remains even when the helper or controller stops.
    runner.root("/bin/mkdir", session + "/attempt")
    code, raw = runner.root(session + "/identity_correlate", "--pid", pid, "--cdhash", cdhash,
                            limit=stage.MAX_RESULT, allowed_codes=(0, 1), with_code=True)
    path = session + "/result.json"
    if runner.root("/usr/bin/tee", path, data=raw, limit=stage.MAX_RESULT) != raw:
        raise Refused("结果保存未完成")
    runner.root("/bin/chmod", "600", path)
    parsed = validate_result(raw, pid, cdhash)
    if code != (0 if parsed["result"] == "candidate" else 1):
        raise Refused("退出状态与结果不一致；保留现场，状态未知")
    return {"session": session, "sha256": expected, "size": size, "exit_code": code}, parsed


def collect(runner, expected, pid, cdhash):
    fd, path = stage.open_output(runner)
    print("诊断文件：" + path, file=sys.stderr, flush=True)
    try:
        stage.write_output(fd, {"result": "incomplete", "stage": "started", "actual_protection": "unknown", "tun_ownership": "unknown", "authorization": "none"})
        session, size = prepare(runner, expected, pid, cdhash)
        stage.write_output(fd, {"result": "incomplete", "stage": "prepared", "session": session,
                                "sha256": expected, "size": size, "actual_protection": "unknown", "tun_ownership": "unknown", "authorization": "none"})
        metadata, diagnostic = sample(runner, session, expected, pid, cdhash)
        stage.write_output(fd, {"session": metadata, "diagnostic": diagnostic})
        return metadata, diagnostic
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "collect"))
    parser.add_argument("--pid", type=stage.checked_pid)
    parser.add_argument("--cdhash", type=checked_cdhash)
    parser.add_argument("--ack")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("请以普通用户运行，勿 sudo 整个脚本")
    if args.action == "plan":
        if args.ack is not None or args.pid is not None or args.cdhash is not None:
            raise Refused("plan 不接受采样参数")
        print(json.dumps({"source": str(SOURCE), "mode": MODE, "interpretation": INTERPRETATION,
                          "steps": ["独立审阅固定构建产物并固定摘要", "同一终端先执行 sudo -v", "collect --pid PID --cdhash HEX --ack READ-ONE-PROXY 单次只读采样"],
                          "actual_protection": "unknown", "tun_ownership": "unknown", "authorization": "none",
                          "cleanup": "中断时保留现场，不自动重试或清理"}, ensure_ascii=False, indent=2))
        return
    if args.ack != ACK or args.pid is None or args.cdhash is None:
        raise Refused("collect 需要 --pid、--cdhash 和 --ack READ-ONE-PROXY")
    if AUDITED_BINARY_SHA256 is None:
        raise Refused("当前没有独立审阅二进制摘要，特权入口保持关闭")
    expected = stage.checked_digest(AUDITED_BINARY_SHA256)
    metadata, diagnostic = collect(stage.Runner(), expected, args.pid, args.cdhash)
    print(json.dumps({"session": metadata, "diagnostic": diagnostic, "interpretation": INTERPRETATION}, ensure_ascii=False))
    if diagnostic["result"] != "candidate":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, UnicodeError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留现场；特权命令及后代状态未知，不自动重试或清理。", file=sys.stderr)
        sys.exit(2)
