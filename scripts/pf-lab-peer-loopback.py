#!/usr/bin/env python3
"""Run the four ordinary-user loopback exchanges for the fixed PF lab peer example."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import time

BINARY = Path(__file__).resolve().parent.parent / "target/release/examples/pf_lab_peer"
ACK = "RUN-LOOPBACK-PROBE"


def free_ports(family, kind, host):
    # Hold both reservations until both numbers are known. A later bind race is
    # a failed exchange, never a reason to adopt another listener or retry.
    with socket.socket(family, kind) as source, socket.socket(family, kind) as destination:
        source.bind((host, 0))
        destination.bind((host, 0))
        return source.getsockname()[1], destination.getsockname()[1]


def ready_line(stream):
    deadline = time.monotonic() + 4
    data = bytearray()
    while len(data) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            break
        byte = os.read(stream.fileno(), 1)
        if not byte:
            break
        data.extend(byte)
        if byte == b"\n":
            return bytes(data)
    raise ValueError("receiver did not report readiness")


def verify(raw, role, status, protocol, source, destination, nonce):
    if len(raw) > 4096:
        raise ValueError("oversized peer result")
    obj = json.loads(raw)
    expected = {"role": role, "status": status, "protocol": protocol,
                "source": source, "destination": destination,
                "nonce": list(bytes.fromhex(nonce)), "effective_uid": os.geteuid(),
                "pf_verdict": "not_evaluated"}
    if not isinstance(obj, dict) or any(obj.get(key) != value for key, value in expected.items()):
        raise ValueError("peer result does not match this exchange")


def exchange(family, host, protocol):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    ports = free_ports(family, kind, host)
    address = f"[{host}]" if family == socket.AF_INET6 else host
    source, destination = (f"{address}:{port}" for port in ports)
    nonce = secrets.token_hex(16)
    args = ["--protocol", protocol, "--source", source, "--destination", destination,
            "--nonce", nonce, "--ack", "CONTROLLED-PROBE"]
    with subprocess.Popen([BINARY, "run", "--role", "receiver", *args],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as receiver:
        try:
            ready = ready_line(receiver.stdout)
            verify(ready, "receiver", "ready", protocol, source, destination, nonce)
            sender = subprocess.run([BINARY, "run", "--role", "sender", *args],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=32, check=False)
            if sender.returncode != 0 or sender.stderr:
                raise ValueError("sender did not receive a matching echo")
            verify(sender.stdout, "sender", "completed", protocol, source, destination, nonce)
            output, errors = receiver.communicate(timeout=2)
            if receiver.returncode != 0 or errors:
                raise ValueError("receiver did not complete")
            verify(output, "receiver", "completed", protocol, source, destination, nonce)
        finally:
            if receiver.poll() is None:
                receiver.kill()
    return {"family": "ipv6" if family == socket.AF_INET6 else "ipv4", "protocol": protocol,
            "source": source, "destination": destination, "nonce": nonce, "result": "echo_matched"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ack", choices=(ACK,))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("run as an ordinary user")
    if args.ack is None:
        print(json.dumps({"result": "plan", "interfaces": ["loopback"], "cases": 4, "pf_verdict": "not_evaluated"}))
        return
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    cases = []
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        for protocol in ("tcp", "udp"):
            cases.append(exchange(family, host, protocol))
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != digest:
        raise ValueError("peer binary changed during the loopback check")
    print(json.dumps({"result": "loopback_checked", "helper_sha256": digest,
                      "cases": cases, "pf_verdict": "not_evaluated"}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("停止：" + str(error), file=sys.stderr)
        sys.exit(1)
