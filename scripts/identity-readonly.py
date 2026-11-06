#!/usr/bin/env python3
"""One-shot operator identity observation. Run as the normal user, never as root.

A digest is an operator assertion of independent review, not a trust decision by
this program. This manual development tool does not establish a production
authorization boundary or defend against compromise of the same user or root.
A timeout leaves privileged processes and files in an unknown state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time

ENV = {"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
ROOT = ["/usr/bin/sudo", "-n", "-u", "root", "--", "/usr/bin/env", "-i",
        "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"]
SOURCE = Path(__file__).resolve().parent.parent / "target/release/examples/identity_readonly"
OUTPUT_PARENT = "/private/tmp"
SESSION = re.compile(r"/private/var/root/tunlatch-identity\.[A-Za-z0-9]{8}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_BINARY = 32 * 1024 * 1024
MAX_RESULT = 128 * 1024
TOTAL_OUTPUT = 2 * MAX_BINARY + 2 * 1024 * 1024
DEADLINE = 120
COMMAND_TIME = 8
# Filled only after independent review of the exact build. None keeps root
# operations closed; a caller-provided digest is never an allowlist.
AUDITED_BINARY_SHA256 = "9e198b2aa38df92be2b903cfd0bfbfbc373e8808a14839b884f78b5246ac26c0"
# Holds timed-out child handles until the controller itself exits.
_CHILDREN = []


class Refused(Exception):
    pass


class Runner:
    """Bound all pipe output and waiting, without signalling an unknown process tree."""
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE
        self.remaining = TOTAL_OUTPUT
        # Keep ownership of every started child for the life of this controller.
        # A retained handle does not prove its privileged descendants have exited.
        self.children = []

    def call(self, argv, data=b"", limit=MAX_RESULT, allowed_codes=(0,), with_code=False):
        if time.monotonic() >= self.deadline:
            raise Refused("总等待预算已耗尽；保留现场，进程状态未知")
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=ENV, cwd="/", close_fds=True)
        self.children.append(p)
        _CHILDREN.append(p)
        sel = selectors.DefaultSelector()
        result = {"out": bytearray(), "err": bytearray()}
        pos = 0
        until = min(self.deadline, time.monotonic() + COMMAND_TIME)
        try:
            for stream in (p.stdin, p.stdout, p.stderr):
                os.set_blocking(stream.fileno(), False)
            if data:
                sel.register(p.stdin, selectors.EVENT_WRITE, "in")
            else:
                p.stdin.close()
            sel.register(p.stdout, selectors.EVENT_READ, "out")
            sel.register(p.stderr, selectors.EVENT_READ, "err")
            while sel.get_map():
                left = until - time.monotonic()
                if left <= 0:
                    raise Refused("命令超时；保留现场，不推断特权进程树已结束")
                for key, _ in sel.select(left):
                    if key.data == "in":
                        try:
                            n = os.write(key.fd, data[pos:pos + 65536])
                        except BrokenPipeError:
                            n = 0
                        pos += n
                        if not n or pos == len(data):
                            sel.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        self.remaining -= len(chunk)
                        if self.remaining < 0 or sum(map(len, result.values())) + len(chunk) > limit:
                            raise Refused("输出超限；保留现场，不推断特权进程树已结束")
                        result[key.data].extend(chunk)
            left = until - time.monotonic()
            if left <= 0:
                raise Refused("命令等待超时；保留现场，进程状态未知")
            try:
                code = p.wait(timeout=left)
            except subprocess.TimeoutExpired as error:
                raise Refused("命令等待超时；保留现场，进程状态未知") from error
            if code not in allowed_codes or result["err"] or pos != len(data):
                raise Refused("固定命令失败或认证不可用；保留现场。若需认证，请在本机执行 sudo -v")
            output = bytes(result["out"])
            return (code, output) if with_code else output
        finally:
            sel.close()
            for stream in (p.stdin, p.stdout, p.stderr):
                if not stream.closed:
                    stream.close()

    def root(self, *argv, data=b"", limit=MAX_RESULT, allowed_codes=(0,), with_code=False):
        return self.call(ROOT + list(argv), data, limit, allowed_codes, with_code)


def session_path(value):
    if not SESSION.fullmatch(value):
        raise Refused("不是本工具格式的私有会话路径")
    return value


def checked_digest(value):
    if not DIGEST.fullmatch(value):
        raise Refused("SHA-256 必须为 64 位小写十六进制")
    return value


def checked_pid(value):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 2147483647:
        raise argparse.ArgumentTypeError("PID 须为 1 到 2147483647 的十进制整数")
    return value


def source_bytes(expected):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(SOURCE, flags)
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode) or a.st_nlink != 1 or not 0 < a.st_size <= MAX_BINARY:
            raise Refused("源文件类型、链接数或大小不合格")
        chunks = []
        remaining = a.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise Refused("源文件读取不完整")
            chunks.append(chunk)
            remaining -= len(chunk)
        b = os.fstat(fd)
        path = os.stat(SOURCE, follow_symlinks=False)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        if fields(a) != fields(b) or fields(a) != fields(path):
            raise Refused("源文件读取期间变化")
        data = b"".join(chunks)
        if hashlib.sha256(data).hexdigest() != expected:
            raise Refused("源文件不匹配已独立审阅的 SHA-256")
        return data
    finally:
        os.close(fd)


def dependencies(runner, expected):
    # otool reads the fixed source only; hash it on both sides of the inspection.
    # The independent review of the exact digest is essential, since same-user
    # actors can race a user-writable path and this inspection is not trust.
    source_bytes(expected)
    libs = runner.call(["/usr/bin/otool", "-L", str(SOURCE)], limit=65536).decode("utf-8")
    loads = runner.call(["/usr/bin/otool", "-l", str(SOURCE)], limit=262144).decode("utf-8")
    source_bytes(expected)
    lines = libs.splitlines()
    if len(lines) < 2 or not lines[0].endswith(":"):
        raise Refused("无法解析 Mach-O 依赖")
    for line in lines[1:]:
        match = re.fullmatch(r"\s+(/\S+) \(compatibility version [^\n]+\)", line)
        if not match or not match.group(1).startswith(("/usr/lib/", "/System/Library/")):
            raise Refused("动态依赖不是受保护系统路径")
        if any(p in (".", "..") for p in match.group(1).split("/")):
            raise Refused("动态依赖路径异常")
    if re.search(r"\bcmd LC_(?:RPATH|DYLD_ENVIRONMENT)\b", loads):
        raise Refused("拒绝运行路径或动态加载器环境注入")
    linkers = re.findall(r"cmd LC_LOAD_DYLINKER\s+cmdsize \d+\s+name (\S+) \(offset \d+\)", loads)
    if linkers != ["/usr/lib/dyld"]:
        raise Refused("动态加载器不是固定系统 dyld")


def protected_parents(runner):
    for path in ("/", "/private", "/private/var", "/private/var/root"):
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Refused("系统父目录不受 root 保护")
        listing = runner.call(["/bin/ls", "-lde", path], limit=4096).splitlines()
        if len(listing) != 1 or b"+" in listing[0].split()[0]:
            raise Refused("系统父目录 ACL 未通过检查")


def inspect_session(runner, session):
    session_path(session)
    if runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT", session) != b"0:700:Directory\n":
        raise Refused("会话目录不是 root 独占目录")
    lines = runner.root("/bin/ls", "-lde", session).splitlines()
    if len(lines) != 1 or not lines[0].startswith(b"drwx------ "):
        raise Refused("会话目录 ACL 异常")


def inspect(runner, session, expected):
    inspect_session(runner, session)
    path = session + "/identity_readonly"
    meta = runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT:%l:%z", path).decode().strip().split(":")
    if (len(meta) != 5 or meta[:4] != ["0", "500", "Regular File", "1"]
            or not meta[4].isdigit() or not 0 < int(meta[4]) <= MAX_BINARY):
        raise Refused("受保护副本的属主、权限、类型、链接数或大小异常")
    lines = runner.root("/bin/ls", "-lde", path).splitlines()
    if len(lines) != 1 or not lines[0].startswith(b"-r-x------ "):
        raise Refused("受保护副本 ACL 异常")
    digest = runner.root("/usr/bin/shasum", "-a", "256", path, limit=4096)
    if digest != (expected + "  " + path + "\n").encode():
        raise Refused("受保护副本 SHA-256 不匹配")
    return int(meta[4])


def boot(runner):
    value = runner.call(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], limit=128)
    if not re.fullmatch(rb"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\n", value):
        raise Refused("无法核实当前启动会话")
    return value.decode().strip().lower()


def manifest_bytes(expected, pid, boot_id):
    return (json.dumps({"sha256": expected, "pid": int(pid), "boot": boot_id},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def read_manifest(runner, session, expected):
    path = session + "/manifest.json"
    meta = runner.root("/usr/bin/stat", "-f", "%u:%Lp:%HT:%l:%z", path).decode().strip().split(":")
    if (len(meta) != 5 or meta[:4] != ["0", "600", "Regular File", "1"]
            or not meta[4].isdigit() or not 0 < int(meta[4]) <= 512):
        raise Refused("会话记录属主、权限、类型、链接数或大小异常")
    lines = runner.root("/bin/ls", "-lde", path).splitlines()
    if len(lines) != 1 or not lines[0].startswith(b"-rw------- "):
        raise Refused("会话记录 ACL 异常")
    data = runner.root("/bin/cat", path, limit=512)
    if len(data) != int(meta[4]):
        raise Refused("会话记录长度变化")
    try:
        obj = json.loads(data)
        if not isinstance(obj, dict) or set(obj) != {"sha256", "pid", "boot"}:
            raise ValueError("fields")
        if type(obj["pid"]) is not int:
            raise ValueError("pid")
        pid = checked_pid(str(obj["pid"]))
        if obj["sha256"] != expected or obj["boot"] != boot(runner):
            raise ValueError("digest or boot")
        if data != manifest_bytes(expected, pid, obj["boot"]):
            raise ValueError("noncanonical")
    except (ValueError, TypeError, UnicodeError, argparse.ArgumentTypeError) as error:
        raise Refused("会话记录不是当前启动中经审核的固定目标") from error
    return pid


def prepare(runner, expected, pid):
    data = source_bytes(expected)
    dependencies(runner, expected)
    protected_parents(runner)
    boot_id = boot(runner)
    session = runner.root("/usr/bin/mktemp", "-d", "/private/var/root/tunlatch-identity.XXXXXXXX", limit=4096).decode().strip()
    session_path(session)
    print("会话已创建：" + session, file=sys.stderr, flush=True)
    inspect_session(runner, session)
    path = session + "/identity_readonly"
    if runner.root("/usr/bin/tee", path, data=data, limit=MAX_BINARY) != data:
        raise Refused("暂存副本写入不完整")
    runner.root("/bin/chmod", "500", path)
    size = inspect(runner, session, expected)
    if size != len(data):
        raise Refused("受保护副本大小不匹配")
    record = manifest_bytes(expected, pid, boot_id)
    record_path = session + "/manifest.json"
    if runner.root("/usr/bin/tee", record_path, data=record, limit=512) != record:
        raise Refused("会话记录写入不完整")
    runner.root("/bin/chmod", "600", record_path)
    if read_manifest(runner, session, expected) != pid:
        raise Refused("会话目标不匹配")
    return {"session": session, "sha256": expected, "size": size, "pid": int(pid), "prepared": True}


def validate_result(raw, pid):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate key")
            obj[key] = value
        return obj

    try:
        parsed = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise Refused("采样结果不是唯一键的完整 JSON") from error
    if not isinstance(parsed, dict):
        raise Refused("采样结果不是对象")
    common = {"result", "actual_protection", "tun_ownership"}
    if parsed.get("actual_protection") != "unknown" or parsed.get("tun_ownership") != "unknown":
        raise Refused("采样结果越过保护边界")
    if parsed.get("result") == "incomplete":
        if (set(parsed) != common | {"stage", "problem", "errno"}
                or not isinstance(parsed["stage"], str) or not isinstance(parsed["problem"], str)
                or not (parsed["errno"] is None or type(parsed["errno"]) is int)):
            raise Refused("不完整结果格式错误")
    elif parsed.get("result") == "complete_raw":
        if set(parsed) != common | {"process", "fds", "controls"}:
            raise Refused("完整结果格式错误")
        process = parsed["process"]
        if (not isinstance(process, dict)
                or set(process) != {"pid", "effective_uid", "birth_seconds", "birth_microseconds"}
                or any(type(v) is not int or v < 0 for v in process.values())
                or process["pid"] != int(pid) or process["birth_microseconds"] >= 1000000):
            raise Refused("进程身份结果格式错误")
        for name, keys, cap in (("fds", {"fd", "kind"}, 1024),
                                ("controls", {"fd", "name", "id", "unit"}, 64)):
            entries = parsed[name]
            if not isinstance(entries, list) or len(entries) > cap:
                raise Refused("结果列表格式或大小错误")
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != keys:
                    raise Refused("结果条目格式错误")
                for key, value in entry.items():
                    if key == "name":
                        if not isinstance(value, str) or len(value.encode()) > 96:
                            raise Refused("控制名称格式错误")
                    elif type(value) is not int or value < 0:
                        raise Refused("结果数字格式错误")
    else:
        raise Refused("采样结果状态不合格")
    return parsed


def sample(runner, session, expected, *, include_result=False):
    protected_parents(runner)
    size = inspect(runner, session, expected)
    pid = read_manifest(runner, session, expected)
    # Atomic mkdir provides an irreversible one-shot attempt marker. Never reset it.
    runner.root("/bin/mkdir", session + "/attempt")
    code, raw = runner.root(session + "/identity_readonly", "--pid", pid, limit=MAX_RESULT,
                            allowed_codes=(0, 1), with_code=True)
    # Save the exact bounded output in the root-only session before parsing it.
    if runner.root("/usr/bin/tee", session + "/result.json", data=raw, limit=MAX_RESULT) != raw:
        raise Refused("结果保存未完成")
    runner.root("/bin/chmod", "600", session + "/result.json")
    parsed = validate_result(raw, pid)
    if code != (0 if parsed["result"] == "complete_raw" else 1):
        raise Refused("采样退出状态与结果不一致，保留现场")
    metadata = {"session": session, "sha256": expected, "size": size, "pid": int(pid),
                "result": parsed["result"], "actual_protection": "unknown", "tun_ownership": "unknown"}
    return (metadata, parsed) if include_result else metadata


def open_output(runner):
    """Create a private result under the checked system temporary directory."""
    parent = os.lstat(OUTPUT_PARENT)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) != 0o1777):
        raise Refused("系统临时目录不是 root 拥有的真实 01777 目录")
    listing = runner.call(["/bin/ls", "-lde", OUTPUT_PARENT], limit=4096).splitlines()
    if len(listing) != 1 or not listing[0].startswith(b"drwxrwxrwt "):
        raise Refused("系统临时目录 ACL 或权限异常")
    directory_path = tempfile.mkdtemp(prefix="tunlatch-identity-result.", dir=OUTPUT_PARENT)
    directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        path_info = os.stat(directory_path, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise Refused("新输出目录属主、权限或身份异常")
        fd = os.open("result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise Refused("输出文件类型、属主或链接数异常")
            os.fchmod(fd, 0o600)
            return fd, directory_path + "/result.json"
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def write_output(fd, record):
    data = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode()
    if len(data) > MAX_RESULT + 4096:
        raise Refused("诊断记录超限")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    written = 0
    while written < len(data):
        count = os.write(fd, data[written:])
        if count <= 0:
            raise Refused("输出文件写入未完成")
        written += count
    os.fsync(fd)


def collect(runner, expected, pid):
    # This path remains exclusively in the unprivileged Python process: no
    # component of it is passed to sudo or a root command.
    fd, output_path = open_output(runner)
    print("诊断文件：" + output_path, file=sys.stderr, flush=True)
    try:
        write_output(fd, {"result": "incomplete", "stage": "started", "actual_protection": "unknown", "tun_ownership": "unknown"})
        prepared = prepare(runner, expected, pid)
        write_output(fd, {"result": "incomplete", "stage": "prepared", "session": prepared,
                          "actual_protection": "unknown", "tun_ownership": "unknown"})
        metadata, diagnostic = sample(runner, prepared["session"], expected, include_result=True)
        metadata["output_path"] = output_path
        write_output(fd, {"session": metadata, "diagnostic": diagnostic})
        return metadata
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "prepare", "run", "collect"))
    parser.add_argument("--session")
    parser.add_argument("--pid", type=checked_pid)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("请以普通用户运行，勿 sudo 整个脚本")
    if args.action == "plan":
        if args.session or args.pid:
            raise Refused("plan 不接受采样参数")
        print(json.dumps({"source": str(SOURCE), "steps": ["独立审阅构建产物并固定 SHA-256", "prepare --pid 固定目标并暂存受保护副本", "run --session 单次只读采样"], "actual_protection": "unknown", "tun_ownership": "unknown", "cleanup": "不自动清理 root 证据；不涉及网络恢复"}, ensure_ascii=False, indent=2))
        return
    if AUDITED_BINARY_SHA256 is None:
        raise Refused("当前没有独立审阅二进制摘要，特权入口保持关闭")
    expected = checked_digest(AUDITED_BINARY_SHA256)
    runner = Runner()
    if args.action == "prepare":
        if args.session or not args.pid:
            raise Refused("prepare 需要 --pid，且不接受 session")
        result = prepare(runner, expected, args.pid)
    elif args.action == "run":
        if not args.session or args.pid:
            raise Refused("run 仅接受 --session，PID 从受保护记录读取")
        result = sample(runner, session_path(args.session), expected)
    else:
        if args.session or not args.pid:
            raise Refused("collect 需要 --pid，不能指定 session")
        result = collect(runner, expected, args.pid)
    print(json.dumps(result, ensure_ascii=False))
    if result.get("result") == "incomplete":
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
