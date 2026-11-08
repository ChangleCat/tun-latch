#!/usr/bin/env python3
"""Run four controlled senders or receivers and emit correlated JSON lines."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

BINARY = Path(__file__).resolve().parent.parent / "target/release/examples/pf_lab_peer"
ACK = "RUN-CONTROLLED-PEER-BATCH"
LIMIT = 4096


def unique_fields(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON field")
        obj[key] = value
    return obj


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("address must be a numeric IP:port")
    match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:]+)):([0-9]+)", value)
    if not match:
        raise ValueError("address must be a numeric IP:port")
    ip = ipaddress.ip_address(match.group(1) or match.group(2))
    port = int(match.group(3))
    if (not 1 <= port <= 65535 or ip.is_unspecified or ip.is_multicast
            or (ip.version == 4 and str(ip) == "255.255.255.255")
            or (ip.version == 6 and (ip.is_link_local or ip.ipv4_mapped is not None))):
        raise ValueError("ineligible address")
    canonical = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    if canonical != value:
        raise ValueError("address must use canonical numeric form")
    return ip.version


def validate(document):
    if not isinstance(document, dict) or set(document) != {"cases"}:
        raise ValueError("expected an object containing cases")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != 4:
        raise ValueError("exactly four cases required")
    seen, nonces = set(), set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"family", "protocol", "source", "destination", "nonce"}:
            raise ValueError("invalid case fields")
        family, protocol = case["family"], case["protocol"]
        if family not in ("ipv4", "ipv6") or protocol not in ("tcp", "udp"):
            raise ValueError("invalid case family or protocol")
        version = 4 if family == "ipv4" else 6
        if (address(case["source"]) != version or address(case["destination"]) != version
                or case["source"] == case["destination"]):
            raise ValueError("invalid flow")
        nonce = case["nonce"]
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce) or int(nonce, 16) == 0:
            raise ValueError("nonce must be nonzero lowercase 32-digit hex")
        key = (family, protocol)
        if key in seen or nonce in nonces:
            raise ValueError("duplicate case or nonce")
        seen.add(key)
        nonces.add(nonce)
    return cases


def verify(raw, case, role, status):
    obj = json.loads(raw, object_pairs_hook=unique_fields)
    expected = {"role": role, "status": status, "protocol": case["protocol"],
                "source": case["source"], "destination": case["destination"],
                "nonce": list(bytes.fromhex(case["nonce"])), "effective_uid": os.geteuid(),
                "pf_verdict": "not_evaluated"}
    if (not isinstance(obj, dict) or any(obj.get(k) != v for k, v in expected.items())
            or type(obj["effective_uid"]) is not int
            or any(type(byte) is not int for byte in obj["nonce"])):
        raise ValueError("mismatched peer result")
    return obj


def outcome(state, role, code):
    case = state["case"]
    if code == 0 and not state["stderr"] and not state["stdout"] and state["completed"]:
        result = "echo_matched" if role == "sender" else "nonce_received_and_echoed"
        return {**case, "result": result}
    if code != 1 or state["stdout"] or state["completed"]:
        raise ValueError(f"invalid peer output: {case['family']}/{case['protocol']} exit={code}")
    failure = verify(state["stderr"], case, role, "unavailable")
    stage, kind, errno = failure.get("stage"), failure.get("error_kind"), failure.get("errno")
    if (not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,64}", value)
                for value in (stage, kind))
            or (errno is not None and (type(errno) is not int or not -(2**31) <= errno < 2**31))):
        raise ValueError("invalid peer failure fields")
    return {**case, "result": "unavailable", "stage": stage, "error_kind": kind, "errno": errno}


def run(cases, role):
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    children = []
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 35
    announced = role == "sender"
    try:
        for case in cases:
            args = [str(BINARY), "run", "--role", role, "--protocol", case["protocol"],
                    "--source", case["source"], "--destination", case["destination"],
                    "--nonce", case["nonce"], "--ack", "CONTROLLED-PROBE"]
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            state = {"case": case, "child": child, "stdout": bytearray(), "stderr": bytearray(),
                     "ready": False, "completed": False}
            children.append(state)
            for name in ("stdout", "stderr"):
                selector.register(getattr(child, name), selectors.EVENT_READ, (state, name))
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("batch timed out")
            for key, _ in selector.select(remaining):
                state, name = key.data
                chunk = os.read(key.fileobj.fileno(), LIMIT + 1)
                if not chunk:
                    selector.unregister(key.fileobj)
                    if name == "stdout" and not announced and not state["ready"]:
                        case = state["case"]
                        raise ValueError(f"receiver ended early: {case['family']}/{case['protocol']}")
                    continue
                buf = state[name]
                buf.extend(chunk)
                if len(buf) > LIMIT:
                    raise ValueError("oversized peer output")
                if name == "stdout":
                    while b"\n" in buf:
                        line, _, tail = buf.partition(b"\n")
                        buf[:] = tail
                        status = "ready" if role == "receiver" and not state["ready"] else "completed"
                        if state["completed"]:
                            raise ValueError("extra peer output")
                        verify(line, state["case"], role, status)
                        state[status] = True
            if not announced and all(s["ready"] for s in children):
                print(json.dumps({"status": "ready", "role": role, "helper_sha256": digest, "cases": cases,
                                  "pf_verdict": "not_evaluated"}), flush=True)
                announced = True
        results = [outcome(state, role, state["child"].wait(timeout=max(0, deadline - time.monotonic())))
                   for state in children]
        if hashlib.sha256(BINARY.read_bytes()).hexdigest() != digest:
            raise ValueError("peer binary changed during batch")
        complete = all(result["result"] != "unavailable" for result in results)
        print(json.dumps({"status": "completed" if complete else "incomplete", "role": role,
                          "helper_sha256": digest, "cases": results,
                          "pf_verdict": "not_evaluated"}), flush=True)
        return 0 if complete else 1
    finally:
        selector.close()
        for state in children:
            child = state["child"]
            if child.poll() is None:
                child.kill()
        cleanup_deadline = time.monotonic() + 1
        timed_out = False
        for state in children:
            child = state["child"]
            child.stdout.close()
            child.stderr.close()
            try:
                child.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            raise ValueError("peer exit not confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="JSON file with four explicit cases")
    parser.add_argument("--role", choices=("sender", "receiver"), required=True)
    parser.add_argument("--ack", choices=(ACK,))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("run as an ordinary user")
    with args.plan.open("rb") as source:
        data = source.read(16385)
    if len(data) > 16384:
        raise ValueError("plan too large")
    cases = validate(json.loads(data, object_pairs_hook=unique_fields))
    if args.ack is None:
        print(json.dumps({"status": "planned", "role": args.role, "cases": cases,
                          "pf_verdict": "not_evaluated"}))
        return 0
    return run(cases, args.role)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "unavailable", "detail": str(error), "pf_verdict": "not_evaluated"}), file=sys.stderr)
        sys.exit(1)
