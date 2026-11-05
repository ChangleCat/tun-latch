#!/usr/bin/env python3
"""Operator-only, unattached PF filter slot experiment; no PF enable or root reload.

The default action prints a plan. Native actions require a separately approved,
operator-present exclusive window. This is not a privileged service, automatic
crash recovery, kernel object authentication, or a leak protection mechanism.
"""
import argparse
from enum import Enum
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import NamedTuple, Optional

_spec = importlib.util.spec_from_file_location("tunlatch_reference", Path(__file__).with_name("pf-lab-reference.py"))
reference = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reference)
Refused = reference.Refused
SESSION = re.compile(r"/var/root/tunlatch-pf-rule\.([A-Za-z0-9]{8})\Z")
MAX_FILE = 65536
LOAD_NOTICE = (b"pfctl: Use of -f option, could result in flushing of rules\n"
               b"present in the main ruleset added by the system at startup.\n"
               b"See /etc/pf.conf for further details.\n\n")
ROOT_QUERIES = (("root-rules", ("-s", "rules")), ("root-nat", ("-s", "nat")),
                ("inventory", ("-v", "-s", "Anchors")))
BASE_FILES = tuple("before-" + key + ".txt" for key, _ in ROOT_QUERIES)
FILES = ("boot.txt", "candidate.pf", "empty.pf", "stage.txt", "clear.txt",
         "closed.json") + BASE_FILES
MARKERS = ("stage-once", "baseline-ready", "load-intent", "recovery-once")


class SlotState(Enum):
    ABSENT = "absent"
    EMPTY = "empty"
    RULES = "rules"


class Slot(NamedTuple):
    state: SlotState
    rules: Optional[bytes]


def profile(session):
    match = SESSION.fullmatch(session)
    if not match:
        raise Refused("需要本次新建的 /var/root/tunlatch-pf-rule.XXXXXXXX 目录")
    suffix = match[1]
    anchor = "tunlatch-lab-" + suffix  # Top-level, not under com.apple/*.
    rules = "".join(
        f'block drop out quick on lo0 {family} proto {proto} from {ip} to {ip} '
        f'port = 55000 label "tunlatch-lab:{suffix}"\n'
        for family, ip in (("inet", "127.0.0.1"), ("inet6", "::1"))
        for proto in ("tcp", "udp")
    ).encode("ascii")
    return anchor, rules


def normalize_record(data, load=False):
    """Only installed script(1)'s observed framing and the exact ALTQ notice."""
    if len(data) > MAX_FILE:
        raise Refused("系统记录超限")
    if data.startswith(b"^D\x08\x08"):
        data = data[4:]
    data = data.replace(b"\r\n", b"\n")
    if any(c < 32 and c != 10 for c in data) or (data and not data.endswith(b"\n")):
        raise Refused("系统记录不完整或含未知控制字符")
    notices = [reference.NOTICE.encode()] + ([LOAD_NOTICE] if load else [])
    # Each exact notice can appear at most once. Any extra/error remains data
    # and fails the caller's complete expected-output comparison.
    while notices:
        matched = next((notice for notice in notices if data.startswith(notice)), None)
        if matched is None:
            break
        data = data[len(matched):]
        notices.remove(matched)
    return data


def inventory(data):
    try:
        names = [line.strip() for line in data.decode("ascii").splitlines()]
    except UnicodeError as error:
        raise Refused("目录不是ASCII") from error
    if len(names) > 17 or len(set(names)) != len(names):
        raise Refused("目录超限或重复")
    for name in names:
        if (len(name) > 128 or len(name.split("/")) > 8
                or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", name)
                or any(part in ("", ".", "..") or part.startswith("-") for part in name.split("/"))
                or ("/" in name and name.rsplit("/", 1)[0] not in names)):
            raise Refused("目录含未知、穿越或缺父节点名称")
    return set(names)


def canonical(anchor, rules):
    if os.geteuid() == 0:
        raise Refused("语法检查也必须普通用户运行")
    argv = ["/sbin/pfctl", "-n", "-v", "-R", "-o", "none", "-a", anchor, "-f", "-"]
    result = subprocess.run(argv, input=rules, capture_output=True, env=reference.ENV,
                            cwd="/", timeout=5, check=False)
    if (result.returncode or result.stderr not in (b"", LOAD_NOTICE)
            or not result.stdout or len(result.stdout) > MAX_FILE):
        raise Refused("普通权限 -n 解析未完整通过；没有加载规则")
    return result.stdout


class System:
    """Fixed system-tool transport, used only by a present operator, never root Python."""
    def __init__(self, session):
        profile(session)
        self.session = session

    def path(self, name):
        if name not in FILES + MARKERS:
            raise Refused("未知实验文件")
        return self.session + "/" + name

    def inspect(self):
        if reference.root("/usr/bin/stat", "-f", "%u:%Lp:%HT", self.session) != b"0:700:Directory\n":
            raise Refused("目录不是root独占0700真实目录")
        lines = reference.root("/bin/ls", "-lde", self.session).splitlines()
        if len(lines) != 1 or not lines[0].startswith(b"drwx------ "):
            raise Refused("目录ACL或属性不能核实")
        recorded = reference.transcript(self.read("boot.txt")).lower()
        if not reference.UUID.fullmatch(recorded) or recorded != reference.boot():
            raise Refused("启动身份不同；不能接管旧启动的规则")

    def read(self, name):
        path = self.path(name)
        fields = reference.root("/usr/bin/stat", "-f", "%u:%HT:%l:%Lp:%z", path).decode().strip().split(":")
        if (len(fields) != 5 or fields[:3] != ["0", "Regular File", "1"]
                or fields[3] not in ("600", "644") or not fields[4].isdigit()
                or not 0 <= int(fields[4]) <= MAX_FILE):
            raise Refused("实验数据类型、属主、链接、权限或长度异常")
        data = reference.root("/bin/cat", path)
        if len(data) != int(fields[4]):
            raise Refused("实验数据读取时改变")
        return data

    def exists(self, name):
        self.path(name)
        return reference.exists(self.session, name)

    def mark(self, name):
        if name not in MARKERS:
            raise Refused("未知一次性标记")
        reference.root("/bin/mkdir", self.path(name))  # No -p, no replacement/retry.

    def write(self, name, data):
        if name not in ("candidate.pf", "empty.pf", "closed.json") or len(data) > MAX_FILE:
            raise Refused("未知或超限数据写入")
        if ((name == "candidate.pf" and data != profile(self.session)[1])
                or (name == "empty.pf" and data)):
            raise Refused("只允许生成的固定候选和空恢复数据")
        if self.exists(name):
            raise Refused("记录已存在，不覆盖")
        argv = reference.PREFIX + ["/usr/bin/tee", self.path(name)]
        result = subprocess.run(argv, input=data, capture_output=True, env=reference.ENV,
                                cwd="/", check=False)
        if result.returncode or result.stderr or result.stdout != data:
            raise Refused("数据暂存结果未知；保留目录")
        if self.read(name) != data:
            raise Refused("root保护数据与生成值不同")

    def baseline(self, key, args):
        if (key, args) not in ROOT_QUERIES:
            raise Refused("未知前态查询")
        name = "before-" + key + ".txt"
        if self.exists(name):
            raise Refused("前态记录已存在，不覆盖")
        live = reference.record(self.session, name, "/sbin/pfctl", *args)
        stored = self.read(name)
        if stored != live:
            raise Refused("系统前态输出与root记录不同")
        return normalize_record(stored)

    def query(self, *args):
        # The shared transport accepts only the exact known ALTQ stderr notice;
        # zero-exit kernel errors remain errors, including for an empty slot.
        anchor = profile(self.session)[0]
        allowed = tuple(query for _, query in ROOT_QUERIES) + (("-s", "info"), ("-s", "References"), ("-s", "Anchors"))
        allowed += tuple(("-a", anchor, "-s", kind) for kind in ("nat", "Tables", "Anchors", "rules"))
        if args not in allowed:
            raise Refused("只允许闭合的根/本次槽查询")
        try:
            return reference.root("/sbin/pfctl", *args)
        except Refused as error:
            raise Refused("PF读取失败 [" + " ".join(args) + "]；未将错误当空：\n" + str(error)) from error

    def submit(self, anchor, empty):
        if anchor != profile(self.session)[0] or type(empty) is not bool:
            raise Refused("只允许本次槽的固定候选或空filter")
        name = "empty.pf" if empty else "candidate.pf"
        log = "clear.txt" if empty else "stage.txt"
        if self.exists(log):
            raise Refused("提交记录已存在，不重试")
        reply = reference.record(self.session, log, "/sbin/pfctl", "-a", anchor,
                                 "-R", "-o", "none", "-f", self.path(name))
        if normalize_record(reply, load=True):
            raise Refused("提交回执含未知内容；独立核对，不自动回滚")


class Rules:
    def __init__(self, system, canonicalizer=canonical):
        self.system = system
        self.anchor, self.rules = profile(system.session)
        self.canonicalizer = canonicalizer

    def inspect(self):
        self.system.inspect()
        if self.system.read("candidate.pf") != self.rules or self.system.read("empty.pf") != b"":
            raise Refused("root保护候选不是固定回环规则或恢复文件不为空")

    def disabled(self):
        if (not self.system.query("-s", "info").startswith(b"Status: Disabled ")
                or self.system.query("-s", "References") != b"No pf starter references held\n"):
            raise Refused("本阶段要求PF停用、引用0；不改变他人引用或全局状态")

    def baseline(self):
        result = {key: normalize_record(self.system.read("before-" + key + ".txt"))
                  for key, _ in ROOT_QUERIES}
        if self.anchor in inventory(result["inventory"]):
            raise Refused("本次规则槽在前态已存在，不能认领")
        return result

    def current(self):
        before = self.baseline()
        for key, args in ROOT_QUERIES[:2]:
            if self.system.query(*args) != before[key]:
                raise Refused("根filter/NAT改变；停止自动操作")
        names = inventory(self.system.query("-v", "-s", "Anchors"))
        if names - {self.anchor} != inventory(before["inventory"]):
            raise Refused("出现外来目录或本次子目录，不能接管")
        # XNU DIOCGETRULESETS/SET on the root enumerates all top-level anchor
        # objects, including unattached ones. Cross-check the nonrecursive view
        # against the recursive view; absence is a namespace observation, NOT
        # a successful empty-filter read. We never turn a query error into empty.
        top = inventory(self.system.query("-s", "Anchors"))
        if top != {name for name in names if "/" not in name}:
            raise Refused("根目录两种列表不一致，规则槽是否存在未知")
        if self.anchor not in top:
            return Slot(SlotState.ABSENT, None)
        for kind in ("nat", "Tables", "Anchors"):
            if self.system.query("-a", self.anchor, "-s", kind):
                raise Refused("规则槽含NAT、表或子目录，拒绝清理")
        rules = self.system.query("-a", self.anchor, "-s", "rules")
        return Slot(SlotState.RULES if rules else SlotState.EMPTY, rules)

    def unsubmitted(self):
        if (not all(self.system.exists(n) for n in ("stage-once", "baseline-ready"))
                or any(self.system.exists(n) for n in
                       ("load-intent", "stage.txt", "clear.txt", "recovery-once", "closed.json"))):
            raise Refused("仅可接续有完整前态且从未记录提交意图/结果的首次提交；不重放或重置标记")

    def stage(self, capture, confirm, stop_after_submit=False, resume=False):
        self.inspect()
        if resume:
            self.unsubmitted()
        reference.check_capture(capture)
        expected = self.canonicalizer(self.anchor, self.rules)
        if not confirm():
            raise Refused("已取消，不暂存规则")
        reference.check_capture(capture)
        self.disabled()
        if not resume:
            self.system.mark("stage-once")
        before = self.baseline() if resume else None
        for index, (key, args) in enumerate(ROOT_QUERIES, 1):
            data = before[key] if resume else self.system.baseline(key, args)
            q = json.loads((Path(capture) / f"query-{index:02}.json").read_text())
            if data != q["stdout"].encode():
                raise Refused("直接系统前态与刚完成采集不一致")
        self.baseline()  # Includes absence; baseline data is never cleanup permission.
        if not resume:
            self.system.mark("baseline-ready")
        if self.current().state != SlotState.ABSENT:
            raise Refused("首次提交前规则槽已经存在；不覆盖或认领现有对象")
        self.disabled()
        if resume:
            self.unsubmitted()
        self.system.mark("load-intent")
        self.system.submit(self.anchor, False)
        if stop_after_submit:
            raise Refused("按计划在系统提交命令返回后退出：尚未查询后态，请由另一入口核对恢复；不是内核阶段故障注入")
        self.inspect()
        self.disabled()
        if self.current().rules != expected:
            raise Refused("规则后态与解析器输出不同；保留现场供独立接管")

    def recover(self, confirm):
        self.inspect()
        if (not all(self.system.exists(n) for n in ("stage-once", "baseline-ready", "load-intent"))
                or self.system.exists("recovery-once")):
            raise Refused("提交意图不完整或已有恢复尝试，不自动接管/重试")
        expected = self.canonicalizer(self.anchor, self.rules)
        self.disabled()
        current = self.current()
        if current.rules not in (None, b"", expected):
            raise Refused("槽内不是本次固定规则或空态；拒绝删除未知规则")
        # A present administrator explicitly takes over one object after confirming
        # every original writer ended and the exclusive window is still continuous.
        # Matching bytes/labels/logs alone are NOT ownership or an automatic permit.
        if not confirm():
            raise Refused("已取消，不恢复规则")
        self.inspect()
        self.disabled()
        rechecked = self.current()
        if rechecked != current:
            raise Refused("确认期间规则变化，停止")
        self.system.mark("recovery-once")
        if current.rules:
            self.system.submit(self.anchor, True)
        self.inspect()
        self.disabled()
        after = self.current()
        if after.rules:
            raise Refused("本次filter未清空，结果未知；不重试")
        result = {"payload_absent": True, "slot_state": after.state.value,
                  "filter_empty": True if after.state == SlotState.EMPTY else None,
                  "anchor_listed_in_inventory": after.state != SlotState.ABSENT,
                  "empty_anchor_metadata": "preserved; not global or parent deletion",
                  "PF_disabled_zero_references_observed": True,
                  "blocking_or_failure_safety_qualified": False}
        self.system.write("closed.json", (json.dumps(result, sort_keys=True) + "\n").encode())
        return result


def plan():
    return {"purpose": "unattached_filter_slot_manual_recovery", "execution": "operator_only_separate_approval_required",
            "anchor": "tunlatch-lab-<fresh root session suffix>", "attached_to_root": False,
            "PF_enable_disable_reference_or_state_operations": False,
            "rules": "4 fixed lo0 loopback TCP/UDP block rules, port55000; no state creation",
            "submit": ["/sbin/pfctl", "-a", "<own literal>", "-R", "-o", "none", "-f", "<root candidate.pf>"],
            "recover": ["/sbin/pfctl", "-a", "<same own literal>", "-R", "-o", "none", "-f", "<root empty.pf>"],
            "slot_observations": "absent via consistent recursive/root-child inventories; existing slots require direct content reads; query errors stay errors",
            "resume_before_submit": "existing complete baseline and no load-intent/result/recovery evidence; fresh matching capture; no marker reset or replay",
            "recover_result": "payload_absent; filter_empty is true only after a direct empty read, null if the named namespace is absent",
            "fault": "optional ordinary controller exit after system submit returns; no claim of internal kernel phase",
            "limits": ["Exclusive, operator-present manual takeover; no automatic ownership from a receipt.",
                       "No privileged descendant deadline/reclamation or power-loss atomicity.",
                       "No traffic evaluation, active block/unblock, UID or leak-protection proof.",
                       "Empty anchor metadata may remain and is preserved."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "prepare", "status", "stage", "resume-before-submit", "recover"))
    parser.add_argument("session", nargs="?")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--stop-after-submit", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("不要sudo整个程序")
    submitting = args.action in ("stage", "resume-before-submit")
    if not submitting and (args.capture or args.stop_after_submit):
        raise Refused("采集和中断参数仅用于stage")
    if args.action in ("plan", "prepare") and args.session:
        raise Refused("此动作不接受旧目录")
    if args.action == "plan":
        print(json.dumps(plan(), ensure_ascii=False, indent=2))
        return
    if args.action in ("status", "stage", "resume-before-submit", "recover"):
        if not args.session:
            raise Refused("缺少本次规则实验目录")
        profile(args.session)
        if submitting and not args.capture:
            raise Refused("需要刚完成的--capture目录")
    reference.command(["/usr/bin/sudo", "-v"])
    if args.action == "prepare":
        session = reference.root("/usr/bin/mktemp", "-d", "/var/root/tunlatch-pf-rule.XXXXXXXX").decode().strip()
        anchor, rules = profile(session)
        print("本次目录：" + session, file=sys.stderr, flush=True)
        reference.record(session, "boot.txt", "/usr/sbin/sysctl", "-n", "kern.bootsessionuuid")
        system = System(session)
        system.inspect()
        canonical(anchor, rules)
        system.write("candidate.pf", rules)
        system.write("empty.pf", b"")
        Rules(system).inspect()
        print("准备通过；没有PF变更。", file=sys.stderr)
        print(session)
        return
    if not args.session:
        raise Refused("缺少本次规则实验目录")
    system = System(args.session)
    lab = Rules(system)
    if args.action == "status":
        lab.inspect()
        print("独立入口可读；尚不证明实机规则恢复通过。")
        print(json.dumps({name: system.exists(name) for name in MARKERS}))
    elif submitting:
        if not args.capture:
            raise Refused("需要刚完成的--capture目录")
        print("只暂存到本次未挂接规则槽，不启用PF、不改根规则；确认另一终端status已通过且窗口独占。")
        resume = args.action == "resume-before-submit"
        prompt = "RESUME-FIRST-SUBMIT" if resume else "STAGE-ONLY"
        if resume:
            print("只接续尚未发生的首次提交；不删除标记，不重放已提交或未知提交。")
        lab.stage(args.capture, lambda: input("请输入 " + prompt + "：") == prompt,
                  args.stop_after_submit, resume=resume)
        print("暂存后态已核对。保持PF停用，立即在另一终端执行recover。")
    else:
        print("人工接管本次槽：先确认原提交命令及其写入者已经结束、独占窗口未中断；不确定就停止。")
        result = lab.recover(lambda: input("请输入 TAKEOVER-EMPTY-RULES：") == "TAKEOVER-EMPTY-RULES")
        print(json.dumps(result, ensure_ascii=False))
        print("本次载荷已移除：规则槽不存在或已直接读为空；PF停用、引用0。未验证阻断恢复。")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留目录；原命令及后代是否结束未知，不自动重试或清理。", file=sys.stderr)
        sys.exit(2)
