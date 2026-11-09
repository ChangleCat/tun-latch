#!/usr/bin/env python3
"""Prepare or run the fixed read-only root PF ABI check as an ordinary user."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

_spec = importlib.util.spec_from_file_location(
    "_root_hook_readonly_stage", Path(__file__).with_name("pf-lab-sync.py"))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
stage = base.stage
Refused = base.Refused

DIRECTORY = "/private/var/root/tunlatch-pf-root-hook-readonly"
HELPER = DIRECTORY + "/pf-lab-root-hook-readonly"
SOURCE = Path(__file__).resolve().parent.parent / "target/pf-root-hook-readonly/release/examples/pf_lab_root_hook_readonly"
MODE = "pf-root-hook-abi-readonly"
# Independently reviewed exact release build, for the read-only check only.
AUDITED_BINARY_SHA256 = "ee7eba787c6f9b601062e7b9411a7998e72ab94b22955ea894db8bf208902c01"

base.SESSION = DIRECTORY
base.HELPER = HELPER
base.MANIFEST = DIRECTORY + "/operator-manifest.json"
base.MODE = MODE
base.SOURCE = SOURCE
base.staging.SOURCE = SOURCE
stage.SOURCE = SOURCE


def expected_digest():
    if AUDITED_BINARY_SHA256 is None:
        raise Refused("构建尚无独立审阅摘要；特权入口关闭")
    return stage.checked_digest(AUDITED_BINARY_SHA256)


def parse_result(raw):
    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=base.unique_fields)
        if (not isinstance(result, dict)
                or set(result) != {"result", "scope", "rules", "build", "root_rules_sha256"}
                or result["result"] != "readback_matched" or result["scope"] != "root_filter_read_layout"
                or result["build"] != "25G83" or type(result["rules"]) is not int
                or not 1 <= result["rules"] <= 256
                or not isinstance(result["root_rules_sha256"], str)
                or not stage.DIGEST.fullmatch(result["root_rules_sha256"])):
            raise ValueError("unexpected result")
        return result
    except (ValueError, UnicodeError) as error:
        raise Refused("只读 ABI 回报无效；保留现场") from error


def execute(runner, action, expected):
    if action not in ("prepare", "check"):
        raise Refused("只接受固定只读操作")
    if action == "prepare":
        base.install(runner, expected)
    else:
        base.inspect(runner, expected)
    code, output = runner.root(HELPER, "check", limit=base.HELPER_OUTPUT_LIMIT,
                               allowed_codes=(0, 1), with_code=True, timeout=25)
    result = parse_result(base.checked_helper_output(code, output))
    base.inspect(runner, expected)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "prepare", "check"))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Refused("请以普通用户运行本脚本")
    if args.action == "plan":
        reviewed = AUDITED_BINARY_SHA256 is not None
        result = {"actions": ["prepare", "check"] if reviewed else [], "directory": DIRECTORY,
                  "digest_reviewed": reviewed, "pf_write_operations": 0,
                  "prepare_effects": ["install_readonly_helper", "check_root_filter_read_layout"]}
    else:
        result = execute(stage.Runner(), args.action, expected_digest())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("中断：保留现场；受保护部署或只读进程状态可能未知。", file=sys.stderr)
        sys.exit(2)
