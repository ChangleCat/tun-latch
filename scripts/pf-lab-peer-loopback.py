#!/usr/bin/env python3
"""Run the four ordinary-user loopback exchanges for the fixed PF lab peer example."""

import argparse
import hashlib
import json
import os
import re
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


def failure_record(raw, role, protocol, source, destination, nonce):
    """Accept only a bounded, matching helper failure and expose safe fields."""
    try:
        if len(raw) > 4096:
            raise ValueError("oversized failure")
        def unique_object(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate field")
                obj[key] = value
            return obj

        obj = json.loads(raw, object_pairs_hook=unique_object)
        expected_keys = {"role", "status", "protocol", "source", "destination", "nonce",
                         "effective_uid", "pf_verdict", "detail", "stage", "error_kind", "errno"}
        if not isinstance(obj, dict) or set(obj) != expected_keys:
            raise ValueError("invalid failure record")
        verify(raw, role, "unavailable", protocol, source, destination, nonce)
        stage, kind, errno = obj["stage"], obj["error_kind"], obj["errno"]
        if not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,64}", value)
                   for value in (stage, kind)):
            raise ValueError("invalid failure fields")
        if errno is not None and (type(errno) is not int or not -(2**31) <= errno < 2**31):
            raise ValueError("invalid errno")
        return f"stage={stage} error_kind={kind} errno={errno}"
    except (ValueError, KeyError, TypeError):
        return "missing or invalid structured failure"


def available_bytes(stream):
    """Read only bytes already available, without waiting for the child."""
    os.set_blocking(stream.fileno(), False)
    data = bytearray()
    while len(data) <= 4096:
        try:
            chunk = os.read(stream.fileno(), 4097 - len(data))
        except BlockingIOError:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def child_failure(family, protocol, role, exit_code, raw, source, destination, nonce):
    return (f"{family}/{protocol} {role} exit={exit_code}: "
            + failure_record(raw, role, protocol, source, destination, nonce))


def exchange(family, host, protocol):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    ports = free_ports(family, kind, host)
    address = f"[{host}]" if family == socket.AF_INET6 else host
    source, destination = (f"{address}:{port}" for port in ports)
    nonce = secrets.token_hex(16)
    args = ["--protocol", protocol, "--source", source, "--destination", destination,
            "--nonce", nonce, "--ack", "CONTROLLED-PROBE"]
    family_name = "ipv6" if family == socket.AF_INET6 else "ipv4"
    with subprocess.Popen([BINARY, "run", "--role", "receiver", *args],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as receiver:
        try:
            def receiver_diagnostic():
                raw = available_bytes(receiver.stderr)
                exit_code = receiver.poll()
                if raw or exit_code is not None:
                    return "; " + child_failure(family_name, protocol, "receiver", exit_code,
                                                raw, source, destination, nonce)
                return ""

            try:
                ready = ready_line(receiver.stdout)
                verify(ready, "receiver", "ready", protocol, source, destination, nonce)
            except (ValueError, OSError):
                raw = available_bytes(receiver.stderr)
                raise ValueError(child_failure(family_name, protocol, "receiver", receiver.poll(),
                                               raw, source, destination, nonce)) from None
            try:
                sender = subprocess.run([BINARY, "run", "--role", "sender", *args],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=32, check=False)
            except subprocess.TimeoutExpired:
                raise ValueError(f"{family_name}/{protocol} sender timed out"
                                 + receiver_diagnostic()) from None
            if sender.returncode != 0 or sender.stderr:
                message = child_failure(family_name, protocol, "sender", sender.returncode,
                                        sender.stderr, source, destination, nonce)
                raise ValueError(message + receiver_diagnostic())
            try:
                verify(sender.stdout, "sender", "completed", protocol, source, destination, nonce)
            except ValueError:
                raise ValueError(f"{family_name}/{protocol} sender exit={sender.returncode}: invalid completion"
                                 + receiver_diagnostic()) from None
            try:
                output, errors = receiver.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                raise ValueError(f"{family_name}/{protocol} receiver timed out") from None
            if receiver.returncode != 0 or errors:
                raise ValueError(child_failure(family_name, protocol, "receiver", receiver.returncode,
                                               errors, source, destination, nonce))
            try:
                verify(output, "receiver", "completed", protocol, source, destination, nonce)
            except ValueError:
                raise ValueError(f"{family_name}/{protocol} receiver exit={receiver.returncode}: invalid completion") from None
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
