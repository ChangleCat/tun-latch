#!/usr/bin/env python3
"""Manual one-shot controlled utun mapping operator; never run this client as root.

A timeout or interruption leaves the privileged command tree and test interface
state unknown. This development tool neither establishes trust nor protection.
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
_spec = importlib.util.spec_from_file_location("_utun_stage_identity", Path(__file__).with_name("identity-readonly.py"))
stage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage)
Refused = stage.Refused
SOURCE = Path(__file__).resolve().parent.parent / "target/release/examples/utun_mapping"
SESSION = re.compile(r"/private/var/root/tunlatch-utun-mapping\.[A-Za-z0-9]{8}\Z")
MODE = "create-one-test-utun"
ACK = "CREATE-ONE-TEST-UTUN"
INTERPRETATION = "complete 仅表示本次映射实验观察完整，接口 present 可能异步 detach 或名称复用，不等于恢复；不能按名字清理。"
# Filled only after independent review of this exact release binary.
AUDITED_BINARY_SHA256 = "0d3fd9925c788a526de3fe4498fba8d69ae3a7aedcf23f52a30eddca361c2332"
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
    path = session + "/utun_mapping"
    size = inspect_file(runner, path, "500", stage.MAX_BINARY)
    digest = runner.root("/usr/bin/shasum", "-a", "256", path, limit=4096)
    if digest != (expected + "  " + path + "\n").encode():
        raise Refused("受保护副本 SHA-256 不匹配")
    return size


def manifest_bytes(expected, boot_id):
    return (json.dumps({"boot": boot_id, "mode": MODE, "sha256": expected},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def check_manifest(runner, session, expected):
    path = session + "/manifest.json"
    size = inspect_file(runner, path, "600", 512)
    data = runner.root("/bin/cat", path, limit=512)
    if len(data) != size or data != manifest_bytes(expected, stage.boot(runner)):
        raise Refused("会话记录不匹配当前启动、实验模式或摘要")


def prepare(runner, expected):
    data = source_bytes(expected)
    stage.dependencies(runner, expected)
    stage.protected_parents(runner)
    boot_id = stage.boot(runner)
    session = runner.root("/usr/bin/mktemp", "-d", "/private/var/root/tunlatch-utun-mapping.XXXXXXXX", limit=4096).decode().strip()
    session_path(session)
    print("会话已创建：" + session, file=sys.stderr, flush=True)
    inspect_session(runner, session)
    path = session + "/utun_mapping"
    if runner.root("/usr/bin/tee", path, data=data, limit=stage.MAX_BINARY) != data:
        raise Refused("暂存副本写入不完整")
    runner.root("/bin/chmod", "500", path)
    size = inspect(runner, session, expected)
    if size != len(data):
        raise Refused("受保护副本大小不匹配")
    record = manifest_bytes(expected, boot_id)
    path = session + "/manifest.json"
    if runner.root("/usr/bin/tee", path, data=record, limit=512) != record:
        raise Refused("会话记录写入不完整")
    runner.root("/bin/chmod", "600", path)
    check_manifest(runner, session, expected)
    return session, size


def validate_result(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        obj = json.loads(raw, object_pairs_hook=unique)
        keys = {"result", "stage", "error", "mapping", "observed_ifname", "owned_fd_released", "close_errno",
                "fd_after_close", "interface_after_close", "kernel_may_set_interface_up",
                "program_configures_addresses_routes", "system_side_effects_unknown",
                "actual_protection", "tun_ownership"}
        if not isinstance(obj, dict) or set(obj) != keys:
            raise ValueError("fields")
        if (obj["kernel_may_set_interface_up"] is not True
                or obj["program_configures_addresses_routes"] is not False
                or obj["system_side_effects_unknown"] is not True
                or obj["actual_protection"] != "unknown" or obj["tun_ownership"] != "unknown"):
            raise ValueError("boundary")
        stages = {"input", "socket", "control_lookup", "connect", "before", "between", "after", "close", "post_close"}
        errors = {"root_required", "invalid_arguments", "socket_failed", "watchdog_unavailable", "cloexec_failed", "control_unavailable",
                  "control_id_invalid", "connect_failed", "ifname_unavailable", "ifname_invalid", "peer_unavailable",
                  "name_or_peer_mismatch", "interface_unavailable", "partial_or_unreadable", "invalid_or_stale_snapshot",
                  "own_fd_missing_or_ambiguous", "control_missing_or_ambiguous", "budget_elapsed", "changed_or_disconnected",
                  "process_changed", "close_unknown", "post_observation_incomplete"}
        if obj["result"] == "complete":
            if (obj["stage"] != "complete" or obj["error"] is not None
                    or obj["owned_fd_released"] is not True or obj["close_errno"] is not None
                    or obj["fd_after_close"] != "absent" or obj["interface_after_close"] not in ("absent", "present")):
                raise ValueError("complete")
        elif obj["result"] == "incomplete":
            if obj["stage"] not in stages or obj["error"] not in errors:
                raise ValueError("incomplete")
        else:
            raise ValueError("result")
        if obj["owned_fd_released"] is not None and obj["owned_fd_released"] is not True:
            raise ValueError("release")
        errno = obj["close_errno"]
        if errno is not None and (type(errno) is not int or not 0 < errno <= 2147483647
                                  or obj["owned_fd_released"] is not None or obj["result"] != "incomplete"):
            raise ValueError("errno")
        if obj["stage"] == "close" and (errno is None or obj["error"] != "close_unknown"):
            raise ValueError("close")
        if (obj["fd_after_close"] not in ("absent", "present_or_reused", "unknown")
                or obj["interface_after_close"] not in ("absent", "present", "unknown")):
            raise ValueError("post state")
        observed = obj["observed_ifname"]
        if observed is not None:
            if (not isinstance(observed, str) or len(observed.encode()) >= 16
                    or not re.fullmatch(r"utun(?:0|[1-9][0-9]*)", observed)
                    or int(observed[4:]) > 4294967295):
                raise ValueError("observed ifname")
        if observed is None and obj["interface_after_close"] != "unknown":
            raise ValueError("interface without observed name")
        mapping = obj["mapping"]
        if mapping is None:
            if obj["result"] == "complete" or obj["fd_after_close"] != "unknown":
                raise ValueError("missing mapping")
        else:
            if (not isinstance(mapping, dict) or set(mapping) != {"fd", "ifname", "control_id", "unit", "ifindex"}
                    or obj["owned_fd_released"] is not True or obj["stage"] not in ("post_close", "complete")):
                raise ValueError("mapping")
            for key in ("fd", "control_id", "unit", "ifindex"):
                value = mapping[key]
                maximum = 2147483647 if key == "fd" else 4294967295
                if type(value) is not int or not (0 if key == "fd" else 1) <= value <= maximum:
                    raise ValueError("mapping number")
            if (mapping["ifname"] != "utun" + str(mapping["unit"] - 1)
                    or mapping["ifname"] != observed or len(mapping["ifname"].encode()) >= 16):
                raise ValueError("ifname")
        return obj
    except (ValueError, TypeError, UnicodeError, KeyError) as error:
        raise Refused("结果格式或边界不合格；保留现场，状态未知") from error


def sample(runner, session, expected):
    stage.protected_parents(runner)
    size = inspect(runner, session, expected)
    check_manifest(runner, session, expected)
    runner.root("/bin/mkdir", session + "/attempt")
    code, raw = runner.root(session + "/utun_mapping", "--run-controlled-utun-mapping",
                            limit=stage.MAX_RESULT, allowed_codes=(0, 1), with_code=True)
    path = session + "/result.json"
    if runner.root("/usr/bin/tee", path, data=raw, limit=stage.MAX_RESULT) != raw:
        raise Refused("结果保存未完成")
    runner.root("/bin/chmod", "600", path)
    parsed = validate_result(raw)
    if code != (0 if parsed["result"] == "complete" else 1):
        raise Refused("退出状态与结果不一致；保留现场，状态未知")
    return {"session": session, "sha256": expected, "size": size, "exit_code": code}, parsed


def collect(runner, expected):
    fd, path = stage.open_output(runner)
    print("诊断文件：" + path, file=sys.stderr, flush=True)
    try:
        stage.write_output(fd, {"result": "incomplete", "stage": "started", "actual_protection": "unknown"})
        session, size = prepare(runner, expected)
        stage.write_output(fd, {"result": "incomplete", "stage": "prepared", "session": session,
                                "sha256": expected, "size": size, "actual_protection": "unknown"})
        metadata, diagnostic = sample(runner, session, expected)
        stage.write_output(fd, {"session": metadata, "diagnostic": diagnostic})
        return metadata, diagnostic
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "collect"))
    parser.add_argument("--ack")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("请以普通用户运行，勿 sudo 整个脚本")
    if args.action == "plan":
        if args.ack is not None:
            raise Refused("plan 不接受确认参数")
        print(json.dumps({"source": str(SOURCE), "mode": MODE,
                          "steps": ["独立审阅二进制并固定摘要", "同一终端先执行 sudo -v",
                                    "collect --ack CREATE-ONE-TEST-UTUN 执行一次受控实验"],
                          "effect": "创建一个临时 TUN，内核可能自动将接口设为 UP；不主动设地址、路由或发包，不动现有代理或 PF。关闭后的清理可能异步，不保证全局网络无副作用。",
                          "interpretation": INTERPRETATION,
                          "watchdog": "helper 在约 6 秒预算到时请求终止自身；系统调度或不可中断调用仍可能延迟，父控制器保持 unknown、保留现场且不自动重试。",
                          "actual_protection": "unknown", "cleanup": "未知时保留现场，不自动清理"}, ensure_ascii=False, indent=2))
        return
    if args.ack != ACK:
        raise Refused("collect 需要 --ack CREATE-ONE-TEST-UTUN")
    if AUDITED_BINARY_SHA256 is None:
        raise Refused("当前没有独立审阅二进制摘要，特权入口保持关闭")
    expected = stage.checked_digest(AUDITED_BINARY_SHA256)
    metadata, diagnostic = collect(stage.Runner(), expected)
    print(json.dumps({"session": metadata, "diagnostic": diagnostic, "interpretation": INTERPRETATION}, ensure_ascii=False))
    if diagnostic["result"] != "complete":
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
