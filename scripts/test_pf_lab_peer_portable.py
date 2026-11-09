"""Loopback-only tests for the portable controlled probe receiver."""

import importlib.util
import json
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("portable", HERE / "pf-lab-peer-portable.py")
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)
BINARY = HERE.parent / "target/release/examples/pf_lab_peer"


def free_port(family, kind):
    with socket.socket(family, kind) as s:
        s.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        return s.getsockname()[1]


class PortableReceiverTests(unittest.TestCase):
    def test_peer_tuple_and_scope_are_checked(self):
        self.assertTrue(portable.peer_matches(("::1", 20, 0, 0), ("::1", 20)))
        self.assertTrue(portable.peer_matches(("2001:0db8::1", 20, 0, 0), ("2001:db8::1", 20)))
        self.assertFalse(portable.peer_matches(("::1", 20, 0, 1), ("::1", 20)))
        self.assertFalse(portable.peer_matches(("127.0.0.1", 21), ("127.0.0.1", 20)))

    def test_tcp_rejects_extra_bytes_and_wrong_nonce(self):
        case = {"protocol": "tcp", "source": "127.0.0.1:1234", "nonce": "01" * 16}
        for payload, stage in ((bytes.fromhex(case["nonce"]) + b"x", "read_eof"),
                               (b"x" * 16, "nonce")):
            with self.subTest(stage=stage):
                server, client = socket.socketpair()
                class Listener:
                    def settimeout(self, _timeout): pass
                    def accept(self): return server, ("127.0.0.1", 1234)
                with client:
                    client.sendall(payload)
                    client.shutdown(socket.SHUT_WR)
                    result = portable.receive(case, Listener(), time.monotonic() + 1)
                self.assertEqual((result["result"], result["stage"]), ("unavailable", stage))

    @unittest.skipUnless(BINARY.is_file(), "build release pf_lab_peer example to test interoperability")
    def test_four_actual_senders_exchange_on_loopback(self):
        cases = []
        used = set()
        for number, (family, protocol) in enumerate((("ipv4", "tcp"), ("ipv4", "udp"),
                                                     ("ipv6", "tcp"), ("ipv6", "udp")), 1):
            af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
            kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
            ports = []
            while len(ports) < 2:
                port = free_port(af, kind)
                if port not in used:
                    ports.append(port)
                    used.add(port)
            host = "127.0.0.1" if family == "ipv4" else "[::1]"
            cases.append({"family": family, "protocol": protocol, "source": f"{host}:{ports[0]}",
                          "destination": f"{host}:{ports[1]}", "nonce": f"{number:032x}"})
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps({"cases": cases}))
            with subprocess.Popen([sys.executable, str(HERE / "pf-lab-peer-portable.py"), str(plan),
                                   "--ack", portable.batch.ACK], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as receiver:
                with selectors.DefaultSelector() as selector:
                    selector.register(receiver.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "portable receiver did not report readiness")
                    ready = json.loads(receiver.stdout.readline(portable.batch.LIMIT + 1))
                self.assertEqual(ready["status"], "ready")
                senders = [subprocess.Popen([str(BINARY), "run", "--role", "sender", "--protocol",
                                              case["protocol"], "--source", case["source"],
                                              "--destination", case["destination"], "--nonce", case["nonce"],
                                              "--ack", "CONTROLLED-PROBE"], stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True) for case in cases]
                for sender in senders:
                    out, err = sender.communicate(timeout=10)
                    self.assertEqual(sender.returncode, 0, (out, err))
                out, err = receiver.communicate(timeout=10)
                self.assertEqual(receiver.returncode, 0, (out, err))
                result = json.loads(out)
                self.assertEqual(result["status"], "completed")
                self.assertTrue(all(c["result"] == "nonce_received_and_echoed" for c in result["cases"]))
                self.assertEqual(result["pf_verdict"], "not_evaluated")
                self.assertEqual(ready["validator_sha256"], result["validator_sha256"])


if __name__ == "__main__":
    unittest.main()
