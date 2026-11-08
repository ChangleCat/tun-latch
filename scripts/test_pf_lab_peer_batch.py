"""Focused validation and loopback checks for the ordinary-user batch peer."""

import importlib.util
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("peer_batch", Path(__file__).with_name("pf-lab-peer-batch.py"))
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


def cases():
    out = []
    for family, host, kind in (("ipv4", "127.0.0.1", socket.AF_INET), ("ipv6", "::1", socket.AF_INET6)):
        for protocol, socktype in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
            with socket.socket(kind, socktype) as a, socket.socket(kind, socktype) as b:
                a.bind((host, 0))
                b.bind((host, 0))
                source, destination = a.getsockname()[1], b.getsockname()[1]
            host_part = f"[{host}]" if kind == socket.AF_INET6 else host
            out.append({"family": family, "protocol": protocol, "source": f"{host_part}:{source}",
                        "destination": f"{host_part}:{destination}", "nonce": f"{len(out) + 1:032x}"})
    return out


class Batch(unittest.TestCase):
    def test_validation_rejects_duplicate_nonce_and_wildcard(self):
        data = cases()
        self.assertEqual(peer.validate({"cases": data}), data)
        duplicate = [dict(c) for c in data]
        duplicate[1]["nonce"] = duplicate[0]["nonce"]
        with self.assertRaises(ValueError):
            peer.validate({"cases": duplicate})
        data[0]["destination"] = "0.0.0.0:1234"
        with self.assertRaises(ValueError):
            peer.validate({"cases": data})

    def test_matching_results_reject_wrong_nonce_and_duplicate_fields(self):
        case = cases()[0]
        result = {"role": "receiver", "status": "ready", "protocol": case["protocol"],
                  "source": case["source"], "destination": case["destination"],
                  "nonce": list(bytes.fromhex(case["nonce"])), "effective_uid": os.geteuid(),
                  "pf_verdict": "not_evaluated"}
        peer.verify(json.dumps(result), case, "receiver", "ready")
        result["nonce"][0] ^= 1
        with self.assertRaises(ValueError):
            peer.verify(json.dumps(result), case, "receiver", "ready")
        with self.assertRaises(ValueError):
            peer.verify('{"role":"receiver","role":"receiver"}', case, "receiver", "ready")

    def test_sender_failure_keeps_native_diagnostic_without_a_pf_verdict(self):
        case = cases()[0]
        report = {"role": "sender", "status": "unavailable", "protocol": case["protocol"],
                  "source": case["source"], "destination": case["destination"],
                  "nonce": list(bytes.fromhex(case["nonce"])), "effective_uid": os.geteuid(),
                  "pf_verdict": "not_evaluated", "stage": "connect", "error_kind": "TimedOut",
                  "errno": None}
        state = {"case": case, "completed": False, "stdout": b"", "stderr": json.dumps(report)}
        self.assertEqual(peer.outcome(state, "sender", 1), {
            **case, "result": "unavailable", "stage": "connect", "error_kind": "TimedOut", "errno": None,
        })
        with self.assertRaises(ValueError):
            peer.outcome(state, "receiver", 1)

    @unittest.skipUnless(peer.BINARY.is_file() and os.geteuid() != 0, "requires built ordinary-user peer")
    def test_bind_failure_stops_batch_without_waiting_for_other_receivers(self):
        data = cases()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied, tempfile.TemporaryDirectory() as tmp:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            data[0]["destination"] = f"127.0.0.1:{occupied.getsockname()[1]}"
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps({"cases": data}))
            result = subprocess.run(["/usr/bin/python3", str(Path(peer.__file__)), str(plan),
                                     "--role", "receiver", "--ack", peer.ACK],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stderr)["status"], "unavailable")
            self.assertEqual(result.stdout, "")

    @unittest.skipUnless(peer.BINARY.is_file() and os.geteuid() != 0, "requires built ordinary-user peer")
    def test_four_loopback_receivers_and_senders(self):
        data = cases()
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps({"cases": data}))
            args = ["/usr/bin/python3", peer.__file__, str(plan), "--ack", peer.ACK, "--role"]
            batch = subprocess.Popen([*args, "receiver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(batch.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "receiver batch did not report readiness")
                    ready = json.loads(batch.stdout.readline(peer.LIMIT + 1))
                self.assertEqual(ready["status"], "ready")
                sent = subprocess.run([*args, "sender"], capture_output=True, timeout=37)
                self.assertEqual(sent.returncode, 0, sent.stderr)
                send_result = json.loads(sent.stdout)
                self.assertEqual(send_result["status"], "completed")
                self.assertEqual(send_result["cases"], [{**case, "result": "echo_matched"} for case in data])
                stdout, stderr = batch.communicate(timeout=5)
                self.assertEqual(batch.returncode, 0, stderr)
                completed = json.loads(stdout)
                self.assertEqual(completed["status"], "completed")
                self.assertEqual(completed["cases"], [{**case, "result": "nonce_received_and_echoed"} for case in data])
                self.assertEqual(completed["pf_verdict"], "not_evaluated")
            finally:
                batch.communicate(timeout=37)


if __name__ == "__main__":
    unittest.main()
