#!/usr/bin/env python3
"""Attended first-flow trial controller; the privileged entry is closed pending review."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("_first_flow_deployment", "pf-lab-sync.py")
flow = load("_first_flow_preflight", "pf-lab-flow-preflight.py")
stage = base.stage
Refused = base.Refused
DIRECTORY = "/private/var/root/tunlatch-pf-first-flow"
HELPER = DIRECTORY + "/pf-lab-first-flow"
SOURCE = Path(__file__).resolve().parent.parent / "target/pf-first-flow/release/examples/pf_lab_first_flow"
MODE = "pf-first-flow-trial"
# Both values require independent review of the entire batch and specific authorization.
AUDITED_BINARY_SHA256 = None
APPROVED_PLAN_SHA256 = None
LIMIT = 16384
COUNTER_ACTIONS = {
    "counters-before": "counters_before_recorded",
    "counters-after": "counters_after_recorded",
}
PHASES = {"prepared", "unsettled", "hook_and_filter_verified", "reference_held", "restored",
          "capture_ready", "capture_recorded", *COUNTER_ACTIONS.values()}
CONFIRMATIONS = {
    "stage": ("STAGE-PF-FIRST-FLOW", {"prepared"}, "hook_and_filter_verified"),
    "activate": ("ACTIVATE-PF-FIRST-FLOW", {"hook_and_filter_verified"}, "reference_held"),
    "recover": ("RECOVER-PF-FIRST-FLOW", {"hook_and_filter_verified", "reference_held", "unsettled"}, "restored"),
}

base.SESSION = DIRECTORY
base.HELPER = HELPER
base.MANIFEST = DIRECTORY + "/operator-manifest.json"
base.MODE = MODE
base.SOURCE = SOURCE
base.staging.SOURCE = SOURCE
stage.SOURCE = SOURCE


def approved():
    if AUDITED_BINARY_SHA256 is None or APPROVED_PLAN_SHA256 is None:
        raise Refused("构建及本次计划尚未完成独立审阅和批准；特权入口关闭")
    return stage.checked_digest(AUDITED_BINARY_SHA256), stage.checked_digest(APPROVED_PLAN_SHA256)


def frozen_input(raw, interface):
    if not re.fullmatch(r"en(?:0|[1-9][0-9]{0,4})", interface):
        raise Refused("接口须为明确的 en 编号")
    if not 0 < len(raw) <= LIMIT:
        raise Refused("计划为空或过大")
    flow.parse_plan(raw)
    document = json.loads(raw, object_pairs_hook=base.unique_fields)
    data = (json.dumps({"interface": interface, "phases": document}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()
    if len(data) > LIMIT:
        raise Refused("冻结计划超过限制")
    return data


def report(raw):
    try:
        obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=base.unique_fields)
        if (not isinstance(obj, dict)
                or set(obj) != {"scope", "phase", "anchor", "actual_protection", "plan_sha256"}
                or obj["scope"] != "first_physical_flow_batch"
                or obj["actual_protection"] != "unknown" or obj["phase"] not in PHASES
                or not isinstance(obj["anchor"], str)
                or not re.fullmatch(r"tunlatch-lab-[0-9a-f]{32}", obj["anchor"])
                or int(obj["anchor"][-32:], 16) == 0
                or not isinstance(obj["plan_sha256"], str)
                or not stage.DIGEST.fullmatch(obj["plan_sha256"])):
            raise ValueError("invalid status")
        return obj
    except (ValueError, UnicodeError, TypeError, KeyError) as error:
        raise Refused("helper 状态无效；保留现场") from error


def invoke(runner, action, data=b""):
    if action not in ("prepare", "status", *CONFIRMATIONS, *COUNTER_ACTIONS):
        raise Refused("未知动作")
    code, raw = runner.root(HELPER, action, data=data, limit=base.HELPER_OUTPUT_LIMIT,
                            allowed_codes=(0, 1), with_code=True, timeout=45)
    return base.checked_helper_output(code, raw)


def execute(runner, action, expected, plan_digest, *, data=None, boot=None, confirm=input,
            writer_started=None):
    if action == "prepare":
        if data is None or hashlib.sha256(data).hexdigest() != plan_digest:
            raise Refused("冻结计划与本次批准不符")
        base.install(runner, expected)
        if boot is None or stage.boot(runner) != boot:
            raise Refused("预检后的系统启动标识变化；保留现场")
        raw = invoke(runner, "prepare", data)
        obj = report(raw)
        if obj["phase"] != "prepared" or obj["plan_sha256"] != plan_digest:
            raise Refused("初始化回报与批准计划不符；保留现场")
        base.inspect(runner, expected)
        return raw
    if action not in ("status", *CONFIRMATIONS, *COUNTER_ACTIONS):
        raise Refused("未知动作")
    base.inspect(runner, expected)
    before = invoke(runner, "status")
    obj = report(before)
    if obj["plan_sha256"] != plan_digest:
        raise Refused("受保护计划与批准不符；保留现场")
    if action == "status":
        return before
    if action in COUNTER_ACTIONS:
        if obj["phase"] != "reference_held":
            raise Refused("只在本次 PF 引用生效时记录计数")
        raw = invoke(runner, action)
        result = report(raw)
        if (result["phase"] != COUNTER_ACTIONS[action] or result["anchor"] != obj["anchor"]
                or result["plan_sha256"] != plan_digest):
            raise Refused("计数记录与本次实验不符；保留现场")
        return raw
    ack, allowed, expected_phase = CONFIRMATIONS[action]
    if obj["phase"] not in allowed:
        raise Refused("当前阶段不允许此动作；保留现场")
    print(before.decode("utf-8", "strict"), flush=True)
    print("确认从暂存起未中断 PF 独占窗口，其他 PF 写入者已退出且恢复条件已核对。不能确认时停止。", flush=True)
    if confirm("请输入 " + ack + "：") != ack:
        raise Refused("未确认本次动作")
    base.inspect(runner, expected)
    if invoke(runner, "status") != before:
        raise Refused("确认期间状态变化；保留现场")
    if writer_started is not None:
        writer_started()
    raw = invoke(runner, action, (ack + "\n").encode())
    result = report(raw)
    if (result["phase"] != expected_phase or result["anchor"] != obj["anchor"]
            or result["plan_sha256"] != plan_digest):
        raise Refused("动作结果与现场不符；保留现场")
    base.inspect(runner, expected)
    return raw


class Capture:
    """Own the fixed capture process; failure never implies its descendants stopped."""
    def __init__(self, runner, expected, digest, anchor):
        base.inspect(runner, expected)
        self.digest, self.anchor = digest, anchor
        self.child = subprocess.Popen(stage.ROOT + [HELPER, "capture"], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=stage.ENV, cwd="/", close_fds=True)
        stage._CHILDREN.append(self.child)
        self.selector = selectors.DefaultSelector()
        self.buffers = {"out": bytearray(), "err": bytearray()}
        for name, stream in (("out", self.child.stdout), ("err", self.child.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def read_until(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while not predicate():
            left = deadline - time.monotonic()
            if left <= 0 or not self.selector.get_map():
                raise Refused("采集进程超时或提前退出；进程状态未知，保留现场")
            for key, _ in self.selector.select(left):
                chunk = os.read(key.fd, base.HELPER_OUTPUT_LIMIT + 1)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                else:
                    self.buffers[key.data].extend(chunk)
                    if sum(map(len, self.buffers.values())) > base.HELPER_OUTPUT_LIMIT:
                        raise Refused("采集输出超限；进程状态未知，保留现场")

    def check(self, raw, phase):
        obj = report(raw)
        if obj["phase"] != phase or obj["anchor"] != self.anchor or obj["plan_sha256"] != self.digest:
            raise Refused("采集回报与本次实验不符；保留现场")

    def ready(self):
        self.read_until(lambda: b"\n" in self.buffers["out"] or self.buffers["err"], 22)
        line, _, tail = self.buffers["out"].partition(b"\n")
        if self.buffers["err"] or tail:
            raise Refused("采集就绪输出异常；保留现场")
        self.check(line, "capture_ready")
        self.buffers["out"].clear()

    def finish(self):
        self.child.stdin.close()
        self.read_until(lambda: not self.selector.get_map(), 22)
        try:
            code = self.child.wait(timeout=1)
        except subprocess.TimeoutExpired as error:
            raise Refused("采集退出未确认；保留现场") from error
        self.selector.close()
        if code != 0 or self.buffers["err"] or not self.buffers["out"].endswith(b"\n"):
            raise Refused("采集未正常结束；保留现场")
        self.check(bytes(self.buffers["out"]), "capture_recorded")
        return bytes(self.buffers["out"])


def terminal_confirm(prompt):
    print(prompt, end="", flush=True)
    with selectors.DefaultSelector() as selector:
        selector.register(sys.stdin, selectors.EVENT_READ)
        if not selector.select(15):
            raise Refused("人工确认超时")
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\n")


def attended_run(runner, expected, digest, data, boot, *, confirm=terminal_confirm, windows_fd=None,
                 fresh_runner=None, peer_session=None):
    frozen = json.loads(data, object_pairs_hook=base.unique_fields)
    document = frozen["phases"]
    phase_bytes = json.dumps(document, separators=(",", ":")).encode()
    windows = {}
    evidence = {"windows": windows}
    prepared = report(execute(runner, "prepare", expected, digest, data=data, boot=boot))
    capture = None
    capture_clean = False
    capture_finishing = False
    active = False
    uncertain = False

    def action(name, **kwargs):
        current_runner = runner if fresh_runner is None else fresh_runner()
        return execute(current_runner, name, expected, digest, **kwargs)

    try:
        uncertain = True
        capture = Capture(runner, expected, digest, prepared["anchor"])
        capture.ready()
        uncertain = False

        @contextlib.contextmanager
        def manual_peer(phase, cases):
            print(f"请在对端启动 {phase} 接收批次，确认四个接收器均已就绪。", flush=True)
            if confirm(f"请输入 PEER-READY-{phase.upper()}：") != f"PEER-READY-{phase.upper()}":
                raise Refused("未确认对端就绪")

            def finish():
                print(f"请确认对端 {phase} 接收批次已经结束并保留其结果。", flush=True)
                if confirm(f"请输入 PEER-FINISHED-{phase.upper()}：") != f"PEER-FINISHED-{phase.upper()}":
                    raise Refused("未确认对端批次结束")

            yield finish

        def send(phase, required):
            current = report(action("status"))
            if current["anchor"] != prepared["anchor"] or current["phase"] != required:
                raise Refused("发送前实验状态变化；保留现场")
            if flow.preflight(phase_bytes, frozen["interface"], flow.system.Runner())["boot"] != boot:
                raise Refused("发送前本机启动标识变化")
            cases = flow.peer.select_phase(document, phase)
            with (peer_session or manual_peer)(phase, cases) as finish:
                exchange(phase, current, cases, finish)

        def exchange(phase, current, cases, finish):
            nonlocal uncertain
            if report(action("status")) != current or capture.child.poll() is not None:
                raise Refused("对端就绪后状态或采集进程变化；保留现场")
            # Any exceptional batch exit might leave a child unaccounted for.
            uncertain = True
            started = time.time_ns() // 1000
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = flow.peer.run(cases, "sender")
            uncertain = False
            raw = output.getvalue()
            if len(raw.encode()) > LIMIT:
                raise Refused("发送批次报告超限")
            sys.stdout.write(raw)
            sys.stdout.flush()
            if phase == "blocked":
                sender_report = json.loads(raw, object_pairs_hook=base.unique_fields)
                if not isinstance(sender_report, dict) or sender_report.get("role") != "sender":
                    raise Refused("发送批次报告无效")
                evidence["sender_report"] = sender_report
                if windows_fd is not None:
                    stage.write_output(windows_fd, evidence)
            finish()
            ended = time.time_ns() // 1000
            if ended <= started:
                raise Refused("系统时间回退；阶段时间不可信")
            windows[phase] = {"start_us": started, "end_us": ended}
            if windows_fd is not None:
                stage.write_output(windows_fd, evidence)
            if phase != "blocked" and result != 0:
                raise Refused(f"{phase} 对照未完成")

        def writer_started():
            nonlocal uncertain
            uncertain = True

        send("before", "prepared")
        action("stage", confirm=confirm, writer_started=writer_started)
        uncertain, active = False, True
        action("activate", confirm=confirm, writer_started=writer_started)
        uncertain = False
        action("counters-before")
        send("blocked", "reference_held")
        action("counters-after")
        action("recover", confirm=confirm, writer_started=writer_started)
        uncertain, active = False, False
        send("after", "restored")
        capture_finishing = True
        uncertain = True
        sys.stdout.buffer.write(capture.finish())
        sys.stdout.buffer.flush()
        capture_clean = True
        uncertain = False
    finally:
        if active and not uncertain:
            try:
                action("recover", confirm=confirm, writer_started=writer_started)
                uncertain = False
            except (Refused, OSError, ValueError, KeyboardInterrupt, EOFError):
                print("恢复未确认；保留现场并人工检查后使用 recover。", file=sys.stderr)
        if capture is not None and not capture_clean and not capture_finishing:
            try:
                capture.finish()
                capture_clean = True
            except (Refused, OSError, ValueError, subprocess.SubprocessError):
                uncertain = True
        if uncertain:
            print("进程或写入结果未知；保留现场，确认所有写入者已结束后人工检查恢复。", file=sys.stderr)


def main(*, peer_session=None, before_run=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan",
                        choices=("plan", "run", "prepare", "status", *CONFIRMATIONS, *COUNTER_ACTIONS))
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--interface")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("请以普通用户运行")
    if args.action == "plan":
        if args.plan is not None or args.interface is not None:
            if args.plan is None or args.interface is None:
                raise Refused("--plan 和 --interface 须同时提供")
            with args.plan.open("rb") as source:
                data = frozen_input(source.read(LIMIT + 1), args.interface)
            digest = hashlib.sha256(data).hexdigest()
        else:
            digest = None
        print(json.dumps({"directory": DIRECTORY, "helper": HELPER, "actions": (["run", "prepare", "status", *CONFIRMATIONS, *COUNTER_ACTIONS]
                                      if AUDITED_BINARY_SHA256 is not None and APPROVED_PLAN_SHA256 is not None else []),
                          "digest_reviewed": AUDITED_BINARY_SHA256 is not None,
                          "plan_approved": APPROVED_PLAN_SHA256 is not None,
                          "plan_sha256": digest, "actual_protection": "unknown",
                          "note": "仅供规划；独立审阅及本次批准完成前禁止特权操作。"}, ensure_ascii=False))
        return
    expected, digest = approved()
    data = None
    boot = None
    if args.action in ("prepare", "run"):
        if args.plan is None or args.interface is None:
            raise Refused("prepare 需要 --plan 和 --interface")
        with args.plan.open("rb") as source:
            raw = source.read(LIMIT + 1)
        data = frozen_input(raw, args.interface)
        if hashlib.sha256(data).hexdigest() != digest:
            raise Refused("冻结计划与本次批准不符")
        observed = flow.preflight(raw, args.interface, flow.system.Runner())
        boot = observed["boot"]
        if boot != stage.boot(stage.Runner()):
            raise Refused("预检后系统启动标识变化")
    elif args.plan is not None or args.interface is not None:
        raise Refused("此动作不接受计划路径或接口")
    if args.action in (*CONFIRMATIONS, "run") and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise Refused("写入及恢复必须在本机终端人工确认")
    if args.action == "run":
        runner = stage.Runner()
        if before_run is not None:
            before_run(runner, expected, digest)
        fd, output_path = stage.open_output(runner)
        print("阶段时间文件：" + output_path, file=sys.stderr, flush=True)
        try:
            stage.write_output(fd, {"windows": {}})
            attended_run(runner, expected, digest, data, boot, windows_fd=fd, fresh_runner=stage.Runner,
                         peer_session=peer_session)
        finally:
            os.close(fd)
        return
    result = execute(stage.Runner(), args.action, expected, digest, data=data, boot=boot)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, UnicodeError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留现场；特权进程和 PF 状态可能未知。", file=sys.stderr)
        sys.exit(2)
