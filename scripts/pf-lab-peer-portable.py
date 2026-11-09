#!/usr/bin/env python3
"""Receive a controlled four-flow probe on a Python 3 host; no PF verdict is made."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import time

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "pf-lab-peer-batch.py"
spec = importlib.util.spec_from_file_location("peer_batch", VALIDATOR)
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)


def endpoint(value):
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("probe deadline")
    return value


def peer_matches(actual, expected):
    # IPv6 scope IDs must be zero: scoped addresses are rejected by validation.
    return (actual[1] == expected[1] and (len(actual) == 2 or actual[3] == 0)
            and ipaddress.ip_address(actual[0]) == ipaddress.ip_address(expected[0]))


def receive(case, listener, deadline):
    stage = "receive"
    try:
        listener.settimeout(remaining(deadline))
        expected = endpoint(case["source"])
        nonce = bytes.fromhex(case["nonce"])
        if case["protocol"] == "tcp":
            stage = "accept"
            conn, peer = listener.accept()
            with conn:
                stage = "peer"
                if not peer_matches(peer, expected):
                    raise ValueError("foreign probe peer")
                stage = "read"
                data = bytearray()
                while len(data) < 16:
                    conn.settimeout(remaining(deadline))
                    chunk = conn.recv(16 - len(data))
                    if not chunk:
                        raise ValueError("short probe")
                    data.extend(chunk)
                stage = "read_eof"
                conn.settimeout(remaining(deadline))
                if conn.recv(1):
                    raise ValueError("extra probe bytes")
                stage = "nonce"
                if data != nonce:
                    raise ValueError("probe nonce mismatch")
                stage = "write"
                conn.settimeout(remaining(deadline))
                conn.sendall(nonce)
                stage = "shutdown_write"
                conn.shutdown(socket.SHUT_WR)
        else:
            data, peer = listener.recvfrom(513)
            stage = "peer"
            if not peer_matches(peer, expected):
                raise ValueError("foreign UDP probe")
            stage = "nonce"
            if data != nonce:
                raise ValueError("probe nonce mismatch")
            stage = "send"
            listener.settimeout(remaining(deadline))
            if listener.sendto(nonce, peer) != len(nonce):
                raise OSError("short datagram")
        remaining(deadline)
        return {**case, "result": "nonce_received_and_echoed"}
    except (OSError, ValueError) as error:
        return {**case, "result": "unavailable", "stage": stage,
                "error_kind": type(error).__name__, "errno": getattr(error, "errno", None)}


def run(cases, budget=30):
    sockets = []
    identity = {"role": "receiver", "pf_verdict": "not_evaluated",
                "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "validator_sha256": hashlib.sha256(VALIDATOR.read_bytes()).hexdigest()}
    try:
        for case in cases:
            family = socket.AF_INET if case["family"] == "ipv4" else socket.AF_INET6
            kind = socket.SOCK_STREAM if case["protocol"] == "tcp" else socket.SOCK_DGRAM
            listener = socket.socket(family, kind)
            sockets.append(listener)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(endpoint(case["destination"]))
            if kind == socket.SOCK_STREAM:
                listener.listen(1)
        deadline = time.monotonic() + budget
        print(json.dumps({**identity, "status": "ready", "cases": cases}), flush=True)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(receive, case, listener, deadline)
                       for case, listener in zip(cases, sockets)]
            results = [future.result() for future in futures]
        complete = all(result["result"] != "unavailable" for result in results)
        print(json.dumps({**identity, "status": "completed" if complete else "incomplete",
                          "cases": results}), flush=True)
        return 0 if complete else 1
    finally:
        for listener in sockets:
            listener.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--phase", choices=batch.PHASES)
    parser.add_argument("--ack", choices=(batch.ACK,))
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("run as an ordinary user")
    with args.plan.open("rb") as source:
        data = source.read(16385)
    if len(data) > 16384:
        raise ValueError("plan too large")
    cases = batch.select_phase(json.loads(data, object_pairs_hook=batch.unique_fields), args.phase)
    if args.ack is None:
        print(json.dumps({"status": "planned", "role": "receiver", "cases": cases,
                          "pf_verdict": "not_evaluated"}))
        return 0
    return run(cases)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "unavailable", "detail": str(error),
                          "pf_verdict": "not_evaluated"}), file=sys.stderr)
        sys.exit(1)
