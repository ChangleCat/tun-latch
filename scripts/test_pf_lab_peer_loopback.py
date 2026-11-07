"""Offline tests for loopback helper failure reporting; no sockets are opened."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("peer_loopback", Path(__file__).with_name("pf-lab-peer-loopback.py"))
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)

NONCE = "01" * 16
SOURCE = "127.0.0.1:1001"
DESTINATION = "127.0.0.1:1002"


def record(role, status="unavailable"):
    return {"role": role, "status": status, "protocol": "tcp", "source": SOURCE,
            "destination": DESTINATION, "nonce": list(bytes.fromhex(NONCE)),
            "effective_uid": os.geteuid(), "pf_verdict": "not_evaluated",
            "detail": "generic", "stage": "connect", "error_kind": "ConnectionRefused",
            "errno": 61}


class Failures(unittest.TestCase):
    def test_bounded_and_validated_fields_do_not_leak(self):
        raw = json.dumps(record("sender")).encode()
        result = peer.failure_record(raw, "sender", "tcp", SOURCE, DESTINATION, NONCE)
        self.assertEqual(result, "stage=connect error_kind=ConnectionRefused errno=61")
        for invalid in (b"secret", raw + b" " * 4097,
                        json.dumps({**record("sender"), "stage": "secret\nmore"}).encode(),
                        json.dumps({**record("sender"), "errno": True}).encode(),
                        json.dumps(record("receiver")).encode()):
            self.assertEqual(peer.failure_record(invalid, "sender", "tcp", SOURCE, DESTINATION, NONCE),
                             "missing or invalid structured failure")

    def test_receiver_readiness_failure_is_reported_and_live_child_killed(self):
        ready_r, ready_w = os.pipe()
        error_r, error_w = os.pipe()
        os.close(ready_w)
        os.write(error_w, json.dumps(record("receiver")).encode())
        os.close(error_w)

        class Receiver:
            stdout = os.fdopen(ready_r, "rb")
            stderr = os.fdopen(error_r, "rb")
            killed = False
            def __enter__(self): return self
            def __exit__(self, *args):
                self.stdout.close()
                self.stderr.close()
            def poll(self): return None
            def kill(self): self.killed = True

        receiver = Receiver()
        with patch.object(peer, "free_ports", return_value=(1001, 1002)), \
             patch.object(peer.secrets, "token_hex", return_value=NONCE), \
             patch.object(peer.subprocess, "Popen", return_value=receiver), \
             patch.object(peer.subprocess, "run") as sender:
            with self.assertRaises(ValueError) as error:
                peer.exchange(socket.AF_INET, "127.0.0.1", "tcp")
        self.assertIn("ipv4/tcp receiver exit=None: stage=connect", str(error.exception))
        self.assertTrue(receiver.killed)
        sender.assert_not_called()

    def test_sender_failure_includes_already_available_receiver_failure(self):
        # Pipes simulate helper output and do not create network traffic.
        ready_r, ready_w = os.pipe()
        error_r, error_w = os.pipe()
        os.write(ready_w, (json.dumps(record("receiver", "ready")) + "\n").encode())
        os.close(ready_w)
        os.write(error_w, json.dumps(record("receiver")).encode())
        os.close(error_w)

        class Receiver:
            stdout = os.fdopen(ready_r, "rb")
            stderr = os.fdopen(error_r, "rb")
            returncode = 1
            def __enter__(self): return self
            def __exit__(self, *args):
                self.stdout.close()
                self.stderr.close()
            def poll(self): return 1
            def kill(self): raise AssertionError("exited child must not be killed")

        sender = subprocess.CompletedProcess([], 1, b"", json.dumps(record("sender")).encode())
        with patch.object(peer, "free_ports", return_value=(1001, 1002)), \
             patch.object(peer.secrets, "token_hex", return_value=NONCE), \
             patch.object(peer.subprocess, "Popen", return_value=Receiver()), \
             patch.object(peer.subprocess, "run", return_value=sender):
            with self.assertRaises(ValueError) as error:
                peer.exchange(socket.AF_INET, "127.0.0.1", "tcp")
        message = str(error.exception)
        self.assertIn("ipv4/tcp sender exit=1: stage=connect", message)
        self.assertIn("ipv4/tcp receiver exit=1: stage=connect", message)
        self.assertNotIn(NONCE, message)


if __name__ == "__main__":
    unittest.main()
