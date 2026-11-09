import importlib.util
import json
from pathlib import Path
import unittest

_spec = importlib.util.spec_from_file_location(
    "flow_preflight", Path(__file__).with_name("pf-lab-flow-preflight.py"))
op = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(op)

BOOT = b"12345678-abcd-1234-abcd-123456789abc\n"
V4 = b"\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255\n"
V6 = b"\tinet6 2001:db8::1 prefixlen 64\n"
IFCONFIG = (b"en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            b"\tether 02:00:00:00:00:01\n" + V4 + V6 + b"\tstatus: active\n")


def plan():
    cases = []
    for number, (family, protocol) in enumerate(reversed(op.ORDER), 1):
        source, destination = ("192.0.2.1", "192.0.2.2") if family == "ipv4" else ("[2001:db8::1]", "[2001:db8::2]")
        cases.append({"family": family, "protocol": protocol, "source": f"{source}:{56000 + number}",
                      "destination": f"{destination}:55000"})
    return json.dumps(op.peer.generate_controls({"cases": cases})).encode()


class FakeRunner:
    def __init__(self, *, before=IFCONFIG, after=IFCONFIG, routed="en0", flags="UP,HOST,DONE"):
        self.before = before
        self.after = after
        self.routed = routed
        self.flags = flags
        self.calls = []

    def call(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv == ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]:
            return BOOT
        if argv == ["/sbin/ifconfig", "en0"]:
            return self.before if self.calls.count(tuple(argv)) == 1 else self.after
        if argv[:3] == ["/sbin/route", "-n", "get"] and len(argv) == 5:
            return f"  route to: {argv[-1]}\n  interface: {self.routed}\n  flags: <{self.flags}>\n".encode()
        raise AssertionError(f"unexpected command {argv}")


class FlowPreflight(unittest.TestCase):
    def test_preflight_binds_plan_to_interface_boot_and_exact_capture_scope(self):
        runner = FakeRunner()
        result = op.preflight(plan(), "en0", runner)
        self.assertEqual(result["result"], "physical_plan_observed")
        self.assertEqual(result["boot"], BOOT.decode().strip())
        self.assertEqual([(c["family"], c["protocol"]) for c in result["blocked"]], list(op.ORDER))
        self.assertEqual(result["capture_expression"].count(" or "), 11)
        self.assertIn("ip6 and tcp and src host 2001:db8::1 and dst host 2001:db8::2",
                      result["capture_expression"])
        self.assertEqual(result["pf_operations"], 0)
        self.assertEqual(result["network_probes"], 0)
        self.assertEqual(result["actual_protection"], "unknown")
        self.assertEqual(len(runner.calls), 6)

    def test_missing_ipv6_wrong_route_or_address_change_fails_closed(self):
        raw = plan()
        for runner in (FakeRunner(before=IFCONFIG.replace(V6, b"")),
                       FakeRunner(before=IFCONFIG.replace(V6, V6.rstrip() + b" tentative\n")),
                       FakeRunner(routed="utun4"), FakeRunner(flags="UP,REJECT"),
                       FakeRunner(after=IFCONFIG.replace(V6, b""))):
            with self.subTest(runner=runner), self.assertRaises(ValueError):
                op.preflight(raw, "en0", runner)
        fake = FakeRunner()
        with self.assertRaises(ValueError):
            op.preflight(raw, "en0;-bad", fake)
        self.assertEqual(fake.calls, [])

    def test_local_or_repeated_route_fields_never_qualify(self):
        destination = op.ipaddress.ip_address("192.0.2.2")
        for report in (b"route to: 192.0.2.2\ninterface: en0\nflags: <UP,LOCAL>\n",
                       b"route to: 192.0.2.2\ninterface: en0\ninterface: en0\nflags: <UP>\n"):
            with self.assertRaises(ValueError):
                op.require_route(report, destination, "en0")
