#!/usr/bin/env python3
"""Check a frozen three-phase probe plan against local physical routes without sending traffic."""

import argparse
import hashlib
import importlib.util
import ipaddress
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


peer = load("_flow_preflight_peer", "pf-lab-peer-batch.py")
system = load("_flow_preflight_system", "identity-readonly.py")
ORDER = (("ipv4", "tcp"), ("ipv4", "udp"), ("ipv6", "tcp"), ("ipv6", "udp"))
ROUTE_REFUSAL = {"REJECT", "BLACKHOLE", "LOCAL", "BROADCAST", "MULTICAST", "LOOPBACK"}


def endpoint(value):
    host, port = value.rsplit(":", 1)
    return ipaddress.ip_address(host.strip("[]")), int(port)


def parse_plan(raw):
    document = json.loads(raw, object_pairs_hook=peer.unique_fields)
    peer.select_phase(document, "blocked")  # This validates all three phases together.
    phases = {phase: document[phase]["cases"] for phase in peer.PHASES}
    for cases in phases.values():
        cases.sort(key=lambda case: ORDER.index((case["family"], case["protocol"])))
        for case in cases:
            source, _ = endpoint(case["source"])
            dest, _ = endpoint(case["destination"])
            if source == dest or any(ip.is_loopback or ip.is_link_local for ip in (source, dest)):
                raise ValueError("物理口计划需要独立、非回环、非链路本地的端点")
    return phases


def assigned_sources(raw, interface):
    lines = raw.decode("ascii", "strict").splitlines()
    header = re.match(rf"{interface}: flags=[0-9a-f]+<([A-Z0-9_,]+)>", lines[0]) if lines else None
    if (header is None or not {"UP", "RUNNING"} <= set(header[1].split(","))
            or [line.strip() for line in lines if line.strip().startswith("status:")] != ["status: active"]
            or sum(line.strip().startswith("ether ") for line in lines) != 1):
        raise ValueError("指定接口不是活动的以太网候选")
    assigned = set()
    for line in lines[1:]:
        fields = line.split()
        if not fields or fields[0] not in ("inet", "inet6"):
            continue
        if len(fields) < 2:
            raise ValueError("接口地址记录不完整")
        if {"tentative", "duplicated", "detached", "deprecated"} & set(fields[2:]):
            continue
        raw_address, scope, _ = fields[1].partition("%")
        address = ipaddress.ip_address(raw_address)
        if scope and not address.is_link_local:
            raise ValueError("非链路本地地址带有未预期的接口范围")
        if not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast):
            assigned.add(address)
    return assigned


def require_route(raw, destination, interface):
    values = {}
    for line in raw.decode("ascii", "strict").splitlines():
        key, separator, value = line.strip().partition(":")
        if separator and key in ("route to", "interface", "flags"):
            if key in values:
                raise ValueError("路由查询含重复字段")
            values[key] = value.strip()
    flags = re.fullmatch(r"<([A-Z0-9_,]+)>", values.get("flags", ""))
    if (ipaddress.ip_address(values.get("route to", "")) != destination
            or values.get("interface") != interface or flags is None):
        raise ValueError("目的地址的路由未指向计划物理口")
    names = set(flags[1].split(","))
    if "UP" not in names or names & ROUTE_REFUSAL:
        raise ValueError("目的地址路由未就绪或为本机、拒绝、广播路由")


def capture_expression(case):
    source, sport = endpoint(case["source"])
    destination, dport = endpoint(case["destination"])
    family = "ip" if source.version == 4 else "ip6"
    return (f"({family} and {case['protocol']} and src host {source} and dst host {destination}"
            f" and src port {sport} and dst port {dport})")


def preflight(raw, interface, runner):
    if not re.fullmatch(r"en(?:0|[1-9][0-9]{0,4})", interface):
        raise ValueError("接口须为明确的 en 编号")
    if not 0 < len(raw) <= 16384:
        raise ValueError("流量计划为空或过大")
    phases = parse_plan(raw)
    blocked = phases["blocked"]
    sources = {endpoint(case["source"])[0] for case in blocked}
    destinations = {endpoint(case["destination"])[0] for case in blocked}
    boot = system.boot(runner)
    interface_query = ["/sbin/ifconfig", interface]
    before = assigned_sources(runner.call(interface_query, limit=65536, timeout=3), interface)
    if not sources <= before or before & destinations:
        raise ValueError("计划源地址未全部配置于该接口，或目的地址属于本机接口")
    for address in sorted(destinations, key=lambda value: (value.version, int(value))):
        family = "-inet" if address.version == 4 else "-inet6"
        raw_route = runner.call(["/sbin/route", "-n", "get", family, str(address)], limit=4096, timeout=3)
        require_route(raw_route, address, interface)
    after = assigned_sources(runner.call(interface_query, limit=65536, timeout=3), interface)
    if before != after or boot != system.boot(runner):
        raise ValueError("本机启动或接口地址在查询期间变化")
    expression = " or ".join(capture_expression(case) for phase in peer.PHASES for case in phases[phase])
    return {"result": "physical_plan_observed", "interface": interface, "boot": boot,
            "plan_sha256": hashlib.sha256(raw).hexdigest(), "blocked": blocked,
            "capture_expression": expression, "network_probes": 0, "pf_operations": 0,
            "actual_protection": "unknown"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--interface", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("请以普通用户运行")
    with args.plan.open("rb") as file:
        raw = file.read(16385)
    print(json.dumps(preflight(raw, args.interface, system.Runner()), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (system.Refused, OSError, ValueError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
