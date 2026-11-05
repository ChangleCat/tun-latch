#!/usr/bin/env python3
"""Operator-only, one-reference experiment. Never run this program as root.

This is a manual lab tool, not a privileged service or an automatic crash recovery
controller. Only fixed, installed system programs are elevated. Recovery requires
a present operator to take over a protected, current-boot acquisition transcript.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ENV = {"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
PREFIX = ["/usr/bin/sudo", "-n", "-u", "root", "--", "/usr/bin/env", "-i",
          "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"]
SESSION = re.compile(r"/var/root/tunlatch-pf-reference\.[A-Za-z0-9]{8}\Z")
UUID = re.compile(rb"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\n\Z")
NOTICE = "No ALTQ support in kernel\nALTQ related functions disabled\n"


class Refused(Exception):
    pass


def command(argv):
    # Manual foreground operation, without a timeout/retry controller. Python
    # and the terminal may signal the immediate child on interruption; that
    # does not prove privileged descendants are reclaimed. Interrupt => unknown.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, cwd="/", check=False)
    allowed_notice = argv[:len(PREFIX)] == PREFIX and argv[len(PREFIX):len(PREFIX)+1] == ["/sbin/pfctl"]
    if result.returncode or (result.stderr and not (allowed_notice and result.stderr == NOTICE.encode())):
        raise Refused("系统命令未成功返回；保留现场，不重试变更。\n" +
                      result.stderr.decode("utf-8", "replace"))
    return result.stdout


def root(*argv):
    return command(PREFIX + list(argv))


def transcript(data):
    if not data or len(data) > 4096:
        raise Refused("记录为空或超限")
    # Installed script(1), with /dev/null input, can echo its synthetic EOF once.
    # Do not strip arbitrary controls, whitespace, unknown lines or partial data.
    if data.startswith(b"^D\x08\x08"):
        data = data[4:]
    data = data.replace(b"\r\n", b"\n")
    if not data.endswith(b"\n") or any(c < 32 and c != 10 for c in data):
        raise Refused("记录含控制字符或不完整行")
    return data


def parse_token(data):
    data = transcript(data)
    if data.startswith(NOTICE.encode()):
        data = data[len(NOTICE):]
    if not re.fullmatch(rb"pf enabled\nToken : [1-9][0-9]{0,19}\n", data):
        raise Refused("不是唯一、完整的本次启用回执；不得从全局引用表猜 token")
    token = data.split(b"Token : ")[1].strip().decode("ascii")
    if int(token) > 2**64 - 1:
        raise Refused("token 超出范围")
    return token


def boot():
    value = command(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])
    if not UUID.fullmatch(value):
        raise Refused("无法核实当前启动身份")
    return value.lower()


def session_path(value):
    if not SESSION.fullmatch(value):
        raise Refused("只接受本工具新建的 /var/root 实验目录")
    return value


def exists(session, name):
    # test(1) exit 1 means absent; all other errors remain unknown.
    result = subprocess.run(PREFIX + ["/bin/test", "-e", session + "/" + name],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, cwd="/", check=False)
    if result.returncode not in (0, 1) or result.stderr or result.stdout:
        raise Refused("无法确定受保护记录是否存在")
    return result.returncode == 0


def protected_record(session, name):
    path = session + "/" + name
    meta = root("/usr/bin/stat", "-f", "%u:%HT:%l:%z", path).decode().strip().split(":")
    if len(meta) != 4 or meta[:3] != ["0", "Regular File", "1"]:
        raise Refused("记录不是 root 单链接普通文件")
    if not meta[3].isdigit() or not 0 < int(meta[3]) <= 4096:
        raise Refused("记录长度不合格")
    data = root("/bin/cat", path)
    if len(data) != int(meta[3]):
        raise Refused("记录读取期间发生变化")
    return data


def inspect(session):
    session_path(session)
    if root("/usr/bin/stat", "-f", "%u:%Lp:%HT", session) != b"0:700:Directory\n":
        raise Refused("实验目录必须属于 root，权限 0700，且不是符号链接")
    listing = root("/bin/ls", "-lde", session).splitlines()
    if len(listing) != 1 or not listing[0].startswith(b"drwx------ "):
        raise Refused("实验目录含额外 ACL 或无法核实权限")
    recorded = transcript(protected_record(session, "boot.txt")).lower()
    if not UUID.fullmatch(recorded) or recorded != boot():
        raise Refused("记录不属于当前启动；不能跨重启沿用 token")


def record(session, filename, executable, *args):
    # This function is called only with literal filenames/programs below.
    return root("/usr/bin/script", "-q", "-F", session + "/" + filename,
                executable, *args)


def check_capture(path):
    """Strict evidence check, not an authorization or atomic/exclusive snapshot."""
    base = Path(path)
    summary = json.loads((base / "summary.json").read_text())
    intent = json.loads((base / "collection-intent.json").read_text())
    age = time.time() - intent["started_unix"]
    if not 0 <= age <= 120 or summary["result"] != "captured_requires_review":
        raise Refused("需要刚完成的完整只读采集（开始时间距今不超过120秒）")
    n = summary["literal_anchor_count"]
    entries = summary["queries"]
    if not 0 <= n <= 16 or len(entries) != 10 + 3*n:
        raise Refused("采集数量不完整")
    queries = []
    for index, item in enumerate(entries, 1):
        filename = f"query-{index:02}.json"
        if item["file"] != filename or item["status"] != "captured":
            raise Refused("采集索引不完整")
        q = json.loads((base / filename).read_text())
        if (q["diagnostic"] != "captured" or q["truncated"] or q["capture_failed"]
                or not q["command_tree_reclaimed"] or q["reason"] != "Success"
                or q["stderr"] != NOTICE):
            raise Refused("采集存在错误或回收未知")
        for stream in ("stdout", "stderr"):
            if hashlib.sha256(q[stream].encode()).hexdigest() != q[stream+"_sha256"]:
                raise Refused("采集摘要不一致")
        queries.append(q)
    expected = ["Rules", "Nat", "Anchors"]
    names = queries[2]["stdout"].splitlines()
    names = [name.strip() for name in names]
    if len(names) != n or len(set(names)) != n:
        raise Refused("目录不完整")
    for name in names:
        if (len(name) > 128 or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", name)
                or any(c in ("", ".", "..") or c.startswith("-") for c in name.split("/"))
                or ("/" in name and name.rsplit("/", 1)[0] not in names)):
            raise Refused("目录名称不合格")
        expected.extend(f'{kind}(Literal("{name}"))' for kind in
                        ("AnchorRules", "AnchorNat", "AnchorTables"))
    expected += ["Interfaces", "Info", "References", "Rules", "Nat", "References", "Anchors"]
    if [q["query"] for q in queries] != expected:
        raise Refused("读取次序不匹配")
    if (queries[0]["stdout"] != queries[-4]["stdout"]
            or queries[1]["stdout"] != queries[-3]["stdout"]
            or queries[2]["stdout"] != queries[-1]["stdout"]):
        raise Refused("前后规则或目录不同")
    if (queries[-5]["stdout"] != "No pf starter references held\n"
            or queries[-2]["stdout"] != "No pf starter references held\n"
            or not queries[-6]["stdout"].startswith("Status: Disabled ")
            or "(skip)" in queries[-7]["stdout"]):
        raise Refused("PF不是停用/零引用前态，或接口skip未知")
    # No leaf rules or tables permitted. Calls must refer only to inventoried
    # direct children (or an empty wildcard). Do not infer safety from labels.
    call = re.compile(r'(anchor|scrub-anchor|nat-anchor|rdr-anchor) "([A-Za-z0-9_.\-/*]+)" all( fragment reassemble)?')
    for q in queries:
        kind = q["query"]
        if kind.startswith("AnchorTables(") and q["stdout"]:
            raise Refused("已有表项命名空间，不进入启用实验")
        if kind not in ("Rules", "Nat") and not kind.startswith(("AnchorRules(", "AnchorNat(")):
            continue
        parent = kind.split('Literal("', 1)[1].split('"', 1)[0] if "Literal(" in kind else ""
        for line in q["stdout"].splitlines():
            match = call.fullmatch(line)
            if not match or (match[3] and match[1] != "scrub-anchor"):
                raise Refused("发现实际规则或未知语法；不能启用现有规则集")
            target = match[2]
            target = parent + "/" + target if parent else target
            if target.endswith("/*"):
                if target[:-2] not in names:
                    raise Refused("挂接父节点未完整读取")
            elif target not in names:
                raise Refused("挂接目标未完整读取")
    return len(queries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "status", "acquire", "release"))
    parser.add_argument("session", nargs="?")
    parser.add_argument("--capture", type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("不要 sudo 整个程序；请用普通用户运行")
    if args.action == "prepare":
        if args.session or args.capture:
            raise Refused("prepare 不接受目录或采集参数")
        print("仅建立 root 私有记录目录并记录本次启动；不改变 PF。", file=sys.stderr, flush=True)
        command(["/usr/bin/sudo", "-v"])
        session = root("/usr/bin/mktemp", "-d", "/var/root/tunlatch-pf-reference.XXXXXXXX").decode().strip()
        session_path(session)
        print("恢复目录（先在第二终端保存）：" + session, file=sys.stderr, flush=True)
        record(session, "boot.txt", "/usr/sbin/sysctl", "-n", "kern.bootsessionuuid")
        inspect(session)
        print("准备通过；尚未取得 PF 引用。", file=sys.stderr)
        print(session)
        return
    if args.session is None or (args.action != "acquire" and args.capture):
        raise Refused("需要本次目录；--capture 只用于 acquire")
    session = session_path(args.session)
    command(["/usr/bin/sudo", "-v"])
    inspect(session)
    if args.action == "status":
        print("恢复入口和启动记录可读；这不是 PF 恢复已经通过的证明。")
        print("acquire-once=" + str(exists(session, "acquire-once")) +
              " release-attempt=" + str(exists(session, "release-attempt")))
        return
    if args.action == "acquire":
        if args.capture is None:
            raise Refused("acquire 需要刚完成的 --capture 目录")
        count = check_capture(args.capture)
        print(f"{count}项读取通过严格空规则检查；不是原子快照。")
        print("将仅执行一次 /sbin/pfctl -E；不加载规则。保持独占窗口，")
        print("确认第二终端 status 已通过；取得引用后立即在第二终端 release。")
        if input("同意本次启用并确认上述条件请输入 ENABLE-ONCE：") != "ENABLE-ONCE":
            raise Refused("已取消，未启用 PF")
        # Recheck freshness/bytes after the human prompt; never retry acquisition.
        check_capture(args.capture)
        root("/bin/mkdir", session + "/acquire-once")
        reply = record(session, "acquire.txt", "/sbin/pfctl", "-E")
        token = parse_token(reply)
        if parse_token(protected_record(session, "acquire.txt")) != token:
            raise Refused("系统回执与保护记录不一致；禁止自动撤销")
        print("本次引用回执已保留。现在立即去第二终端执行 release。")
        return
    if exists(session, "release-attempt"):
        raise Refused("已存在释放尝试；结果必须单独核对，不能重试 -X")
    token = parse_token(protected_record(session, "acquire.txt"))
    print("将人工接管本目录中、当前启动的唯一启用回执，仅释放该 token。")
    print("确认原 acquire 命令已返回/结束，且没有其他 PF 操作者；不确定就停止。")
    print("这不根据全局引用表挑选 token，也不清理原有规则或状态。")
    if input("同意逐项接管并释放请输入 TAKEOVER-AND-RELEASE：") != "TAKEOVER-AND-RELEASE":
        raise Refused("已取消，未释放引用")
    inspect(session)
    if parse_token(protected_record(session, "acquire.txt")) != token:
        raise Refused("接管前记录改变")
    root("/bin/mkdir", session + "/release-attempt")
    record(session, "release.txt", "/sbin/pfctl", "-X", token)
    inspect(session)
    # Protected raw audit observations. Direct queries below also keep stdout
    # separate from stderr so a zero-exit kernel diagnostic cannot be hidden.
    record(session, "after-info.txt", "/sbin/pfctl", "-s", "info")
    record(session, "after-references.txt", "/sbin/pfctl", "-s", "References")
    info = root("/sbin/pfctl", "-s", "info")
    refs = root("/sbin/pfctl", "-s", "References")
    if not info.startswith(b"Status: Disabled ") or refs != b"No pf starter references held\n":
        raise Refused("释放后未回到停用/零引用；不执行全局停用或再次释放。")
    print("本次释放正常返回，随后观察到 PF 停用、引用0。请检查原有联网。")
    print("这未验证阻断恢复、旧连接、UID 匹配或真实出口。")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留目录；系统命令是否完成未知，不自动重试或清理。", file=sys.stderr)
        sys.exit(2)
