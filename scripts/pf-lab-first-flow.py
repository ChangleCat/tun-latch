#!/usr/bin/env python3
"""Attended first-flow trial controller; the privileged entry is closed pending review."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


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
          *COUNTER_ACTIONS.values()}
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


def execute(runner, action, expected, plan_digest, *, data=None, boot=None, confirm=input):
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
    raw = invoke(runner, action, (ack + "\n").encode())
    result = report(raw)
    if (result["phase"] != expected_phase or result["anchor"] != obj["anchor"]
            or result["plan_sha256"] != plan_digest):
        raise Refused("动作结果与现场不符；保留现场")
    base.inspect(runner, expected)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan",
                        choices=("plan", "prepare", "status", *CONFIRMATIONS, *COUNTER_ACTIONS))
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
        print(json.dumps({"directory": DIRECTORY, "helper": HELPER, "actions": (["prepare", "status", *CONFIRMATIONS, *COUNTER_ACTIONS]
                                      if AUDITED_BINARY_SHA256 is not None and APPROVED_PLAN_SHA256 is not None else []),
                          "digest_reviewed": AUDITED_BINARY_SHA256 is not None,
                          "plan_approved": APPROVED_PLAN_SHA256 is not None,
                          "plan_sha256": digest, "actual_protection": "unknown",
                          "note": "仅供规划；独立审阅及本次批准完成前禁止特权操作。"}, ensure_ascii=False))
        return
    expected, digest = approved()
    data = None
    boot = None
    if args.action == "prepare":
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
    if args.action in CONFIRMATIONS and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise Refused("写入及恢复必须在本机终端人工确认")
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
