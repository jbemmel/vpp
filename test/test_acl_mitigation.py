#!/usr/bin/env python3
"""Native ACL mitigation: parity, precedence, scope and lifecycle."""

import unittest
import os
import socket
import struct
import time
import math
from config import config
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.packet import Raw

DST_PREFIX = 1 << 0
SRC_PREFIX = 1 << 1
PROTO = 1 << 2
DST_PORT = 1 << 3
SRC_PORT = 1 << 4
EITHER_PORT = 1 << 5
ICMP_TYPE = 1 << 6
ICMP_CODE = 1 << 7
TCP_FLAGS = 1 << 8
LENGTH = 1 << 9
DSCP = 1 << 10
FRAGMENT = 1 << 11
INVALID = 0xFFFFFFFF


@unittest.skipIf("acl" in config.excluded_plugins, "ACL plugin excluded")
class TestAclMitigation(VppTestCase):
    """FastACL match model using the native ACL classifier."""

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(2))
        for p in self.pg_interfaces:
            p.admin_up()
            p.config_ip4()
            p.config_ip6()
            p.resolve_arp()
            p.resolve_ndp()
        self.acl_index = INVALID

    def tearDown(self):
        if self.acl_index != INVALID:
            self.vapi.acl_mitigation_interface_set(
                sw_if_index=self.pg0.sw_if_index, acl_index=INVALID
            )
            self.vapi.acl_del(acl_index=self.acl_index)
        for p in self.pg_interfaces:
            self.vapi.sw_interface_set_l2_xconnect(
                rx_sw_if_index=p.sw_if_index,
                tx_sw_if_index=p.sw_if_index,
                enable=False,
            )
            p.unconfig_ip4()
            p.unconfig_ip6()
            p.admin_down()
        self.vapi.acl_mitigation_config(per_rule_counters=True, psample_enable=False)
        super().tearDown()

    @staticmethod
    def rule(flags=0, **fields):
        r = dict(flags=flags, order=10, family=2, action=0)
        r.update(fields)
        return r

    def replace(self, rules):
        reply = self.vapi.acl_mitigation_add_replace(
            acl_index=self.acl_index, tag="mitigation-test", count=len(rules), r=rules
        )
        self.acl_index = reply.acl_index
        self.vapi.acl_mitigation_interface_set(
            sw_if_index=self.pg0.sw_if_index, acl_index=self.acl_index
        )

    def packet(self, ip6=False, transport=None, **ip_fields):
        ip = (
            IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6, **ip_fields)
            if ip6
            else IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, **ip_fields)
        )
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / ip
            / (transport if transport is not None else UDP(sport=1234, dport=53))
            / Raw(b"x" * 32)
        )

    def drop(self, p):
        self.send_and_assert_no_replies(self.pg0, [p] * 7)

    def forward(self, p):
        self.send_and_expect(self.pg0, [p] * 7, self.pg1)

    def modes(self):
        for enabled in (True, False):
            self.vapi.acl_plugin_use_hash_lookup_set(enable=enabled)
            yield enabled

    def test_dscp_length_fallthrough(self):
        """A failed residual check must continue to a later candidate."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                # All three entries share the same coarse hash key.
                self.replace(
                    [
                        self.rule(
                            DSCP | LENGTH,
                            dscp=10,
                            packet_length_first=60,
                            packet_length_last=60,
                            order=1,
                        ),
                        self.rule(DSCP, dscp=10, action=1, order=2),
                        self.rule(order=3),
                    ]
                )
                self.drop(self.packet(tos=10 << 2))  # IP length 60
                self.forward(self.packet(tos=10 << 2, transport=TCP(dport=53)))
                self.drop(self.packet(tos=11 << 2))
                self.forward(self.packet(ip6=True, tc=10 << 2))

    def test_either_port_and_dual_stack(self):
        """Protocol-free ports match TCP/UDP in both families."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace(
                    [self.rule(EITHER_PORT, either_port_first=53, either_port_last=54)]
                )
                for ip6 in (False, True):
                    self.drop(self.packet(ip6=ip6))
                    self.drop(self.packet(ip6=ip6, transport=TCP(sport=54, dport=999)))
                    self.forward(
                        self.packet(ip6=ip6, transport=UDP(sport=55, dport=999))
                    )

    def test_ports_flags_icmp(self):
        """Independent transport predicates, including no explicit protocol."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace(
                    [
                        self.rule(
                            SRC_PORT | DST_PORT | TCP_FLAGS,
                            src_port_first=100,
                            src_port_last=200,
                            dst_port_first=80,
                            dst_port_last=80,
                            tcp_flags_value=2,
                            tcp_flags_mask=2,
                        ),
                        self.rule(ICMP_TYPE | ICMP_CODE, icmp_type=8, icmp_code=0),
                    ]
                )
                self.drop(self.packet(transport=TCP(sport=150, dport=80, flags="S")))
                self.forward(self.packet(transport=TCP(sport=150, dport=80, flags="A")))
                self.forward(self.packet(transport=UDP(sport=150, dport=80)))
                self.drop(self.packet(transport=ICMP(type=8, code=0)))
                self.forward(self.packet(transport=ICMP(type=8, code=1)))

    def test_protocol_without_transport(self):
        """Protocol-only rules must not require valid transport fields."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace([self.rule(PROTO, proto=47)])
                self.drop(self.packet(proto=47, transport=Raw(b"GRE")))
                self.drop(self.packet(ip6=True, nh=47, transport=Raw(b"GRE")))

    def test_fragments(self):
        """Noninitial fragments cannot satisfy a port predicate."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace(
                    [
                        self.rule(DST_PORT, dst_port_first=53, dst_port_last=53),
                        self.rule(FRAGMENT, fragment_value=8, fragment_mask=8),
                    ]
                )
                self.drop(self.packet(frag=1, transport=Raw(b"fragment")))
                # First fragment with a different port is not a last fragment.
                self.forward(self.packet(flags="MF", transport=UDP(dport=99)))
                self.drop(
                    self.packet(
                        ip6=True,
                        transport=IPv6ExtHdrFragment(nh=17, offset=1, m=0)
                        / Raw(b"fragment"),
                    )
                )

    def test_ipv6_extension_headers(self):
        """Resolve transport after IPv6 extension headers."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace(
                    [
                        self.rule(
                            PROTO | DST_PORT,
                            proto=17,
                            dst_port_first=53,
                            dst_port_last=53,
                        )
                    ]
                )
                self.drop(
                    self.packet(
                        ip6=True, transport=IPv6ExtHdrHopByHop() / UDP(dport=53)
                    )
                )
                self.forward(
                    self.packet(
                        ip6=True, transport=IPv6ExtHdrHopByHop() / UDP(dport=99)
                    )
                )

    def test_prefix_order_and_counters(self):
        """Component specificity wins ties and counters retain logical IDs."""
        for mode in self.modes():
            with self.subTest(hash=mode):
                self.replace(
                    [
                        self.rule(
                            DST_PREFIX,
                            family=0,
                            dst_prefix=self.pg1.remote_ip4 + "/24",
                            action=1,
                        ),
                        self.rule(
                            DST_PREFIX, family=0, dst_prefix=self.pg1.remote_ip4 + "/32"
                        ),
                    ]
                )
                self.drop(self.packet())
                self.forward(self.packet(ip6=True))
                details = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)
                self.assertEqual([d.rule_index for d in details], [0, 1])
                self.assertEqual(details[0].packets, 0)
                self.assertEqual(details[1].packets, 7)
                self.assertEqual(details[1].bytes, 7 * 60)

    def test_dual_stack_counter_aggregation_and_replace(self):
        """Expanded families share logical counters; replacement resets them."""
        self.replace([self.rule()])
        self.drop(self.packet())
        self.drop(self.packet(ip6=True))
        details = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0].packets, 14)
        self.assertEqual(details[0].bytes, 7 * (60 + 80))
        self.replace([])
        self.forward(self.packet())
        self.assertEqual(self.vapi.acl_mitigation_dump(acl_index=self.acl_index), [])

    def test_invalid_batch_is_atomic(self):
        """Invalid entries leave the previously published ACL intact."""
        self.replace([self.rule()])
        with self.vapi.assert_negative_api_retval():
            self.vapi.acl_mitigation_add_replace(
                acl_index=self.acl_index,
                tag="bad",
                count=2,
                r=[self.rule(action=1), self.rule(DSCP, dscp=64)],
            )
        self.drop(self.packet())
        self.assertEqual(
            len(self.vapi.acl_mitigation_dump(acl_index=self.acl_index)), 1
        )

    def test_bridged_path(self):
        """The same binding filters bridged IPv4 and IPv6."""
        self.replace([self.rule(DST_PORT, dst_port_first=53, dst_port_last=53)])
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=self.pg0.sw_if_index,
            tx_sw_if_index=self.pg1.sw_if_index,
            enable=True,
        )
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=self.pg1.sw_if_index,
            tx_sw_if_index=self.pg0.sw_if_index,
            enable=True,
        )
        for ip6 in (False, True):
            self.drop(self.packet(ip6=ip6))
            self.forward(self.packet(ip6=ip6, transport=UDP(dport=99)))

    def test_legacy_bind_rejected(self):
        """Legacy session nodes cannot silently consume extended rules."""
        self.replace([self.rule()])
        with self.vapi.assert_negative_api_retval():
            self.vapi.acl_interface_set_acl_list(
                sw_if_index=self.pg0.sw_if_index,
                count=1,
                n_input=1,
                acls=[self.acl_index],
            )

    def test_sampling_before_drop_and_permit(self):
        """Every Nth match selects a sample even when the action drops it."""
        try:
            self.vapi.acl_mitigation_config(per_rule_counters=True, psample_enable=True)
        except Exception:
            self.skipTest("Linux psample kernel family unavailable")
        for action in (0, 1):
            self.replace([self.rule(action=action, sample_ratio=3, sample_group=7)])
            if action:
                self.forward(self.packet())
            else:
                self.drop(self.packet())
            details = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)
            self.assertEqual(details[0].sampled + details[0].sample_failed, 2)
            self.assertEqual(details[0].packets, 7)
            # Credits persist across family expansion of one logical rule.
            if action:
                self.forward(self.packet(ip6=True))
            else:
                self.drop(self.packet(ip6=True))
            details = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)
            self.assertEqual(details[0].sampled + details[0].sample_failed, 4)

    @unittest.skipUnless(os.geteuid() == 0, "psample multicast needs CAP_NET_ADMIN")
    def test_psample_delivery(self):
        """A real psample consumer receives packet bytes before drop/permit."""

        def attrs(data):
            result = {}
            while len(data) >= 4:
                length, kind = struct.unpack_from("HH", data)
                if length < 4 or length > len(data):
                    break
                result[kind & 0x3FFF] = data[4:length]
                data = data[(length + 3) & ~3 :]
            return result

        try:
            self.vapi.acl_mitigation_config(per_rule_counters=True, psample_enable=True)
        except Exception:
            self.skipTest("Linux psample kernel family unavailable")
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16) as consumer:
            consumer.settimeout(2)
            consumer.bind((0, 0))
            name = b"psample\0"
            attr = struct.pack("HH", 4 + len(name), 2) + name
            attr += b"\0" * (-len(attr) % 4)
            request = struct.pack("IHHII", 20 + len(attr), 16, 1, 1, 0)
            request += struct.pack("BBH", 3, 1, 0) + attr
            consumer.sendto(request, (0, 0))
            reply = attrs(consumer.recv(8192)[20:])
            group = None
            for entry in attrs(reply[7]).values():
                fields = attrs(entry)
                if fields.get(1, b"").rstrip(b"\0") == b"packets":
                    group = struct.unpack("I", fields[2])[0]
            self.assertIsNotNone(group)
            consumer.setsockopt(270, 1, struct.pack("I", group))
            for action in (0, 1):
                sample_group = 0xA001
                self.replace(
                    [
                        self.rule(
                            action=action, sample_ratio=3, sample_group=sample_group
                        )
                    ]
                )
                packet = self.packet()
                if action:
                    self.forward(packet)
                else:
                    self.drop(packet)
                samples = []
                while len(samples) < 2:
                    fields = attrs(consumer.recv(8192)[20:])
                    if struct.unpack("I", fields[3])[0] == sample_group:
                        samples.append(fields)
                for fields in samples:
                    self.assertEqual(struct.unpack("I", fields[5])[0], 3)
                    self.assertIn(bytes(packet[UDP]), fields[6])
                    self.assertEqual(
                        struct.unpack("I", fields[15])[0], self.pg0.sw_if_index
                    )
                details = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)
                self.assertEqual(details[0].sampled, 2)
                self.assertEqual(details[0].sample_failed, 0)

    def test_counters_disable_preserves_aggregate(self):
        """Per-rule accounting can be disabled without losing aggregate totals."""
        self.replace([self.rule()])
        self.vapi.acl_mitigation_config(per_rule_counters=False, psample_enable=False)
        before = self.vapi.acl_mitigation_stats_get()
        self.drop(self.packet())
        after = self.vapi.acl_mitigation_stats_get()
        self.assertEqual(after.dropped_packets - before.dropped_packets, 7)
        self.assertEqual(after.dropped_bytes - before.dropped_bytes, 7 * 60)
        self.assertEqual(
            self.vapi.acl_mitigation_dump(acl_index=self.acl_index)[0].packets, 0
        )

    def test_rule_rates(self):
        """L3 and estimated L1 rates use per-rule IP counters."""
        self.replace([self.rule()])
        self.drop(self.packet())
        time.sleep(0.6)
        rule = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)[0]
        self.assertTrue(math.isfinite(rule.pps))
        self.assertGreater(rule.pps, 0)
        self.assertAlmostEqual(rule.l3_bps, rule.pps * 60 * 8)
        self.assertAlmostEqual(rule.l1_bps, rule.pps * (60 + 38) * 8)
        time.sleep(0.6)
        rule = self.vapi.acl_mitigation_dump(acl_index=self.acl_index)[0]
        self.assertEqual(rule.pps, 0)
        self.assertEqual(rule.l3_bps, 0)
        self.assertEqual(rule.l1_bps, 0)

    def test_invalid_rule_shapes(self):
        """Reject invalid flags, masks, ranges, families, and actions atomically."""
        self.replace([self.rule(action=1)])
        invalid = [
            self.rule(1 << 12),
            self.rule(SRC_PREFIX, family=2, src_prefix=self.pg0.remote_ip4 + "/32"),
            self.rule(action=2),
            self.rule(DST_PORT, dst_port_first=54, dst_port_last=53),
            self.rule(TCP_FLAGS, tcp_flags_value=2, tcp_flags_mask=1),
            self.rule(FRAGMENT, fragment_value=2, fragment_mask=0),
            self.rule(DSCP, dscp=64),
        ]
        for rule in invalid:
            with self.subTest(rule=rule):
                with self.vapi.assert_negative_api_retval():
                    self.vapi.acl_mitigation_add_replace(
                        acl_index=self.acl_index, tag="invalid", count=1, r=[rule]
                    )
        self.forward(self.packet())

    def test_cli_rule_add(self):
        """CLI fields install a native rule with the requested predicates."""
        output = self.vapi.cli(
            "acl mitigation rule add order 5 proto 17 "
            "dst-port 53 dscp 10 packet-length 60-60 action drop"
        )
        self.acl_index = int(output.strip().split()[-1])
        self.vapi.acl_mitigation_interface_set(
            sw_if_index=self.pg0.sw_if_index, acl_index=self.acl_index
        )
        self.drop(self.packet(tos=10 << 2))
        self.forward(self.packet(tos=11 << 2))
        self.vapi.cli(
            f"acl mitigation rule add acl {self.acl_index} order 1 "
            f"src4 {self.pg0.remote_ip4}/32 action permit"
        )
        self.forward(self.packet(tos=10 << 2))

    def test_single_rule_lifecycle(self):
        """Single-rule API and CLI deletion update an attached context."""
        reply = self.vapi.acl_mitigation_rule_add_del(
            acl_index=INVALID,
            is_add=True,
            rule=self.rule(DST_PORT, dst_port_first=53, dst_port_last=53),
        )
        self.acl_index = reply.acl_index
        self.assertEqual(reply.rule_index, 0)
        self.vapi.acl_mitigation_interface_set(
            sw_if_index=self.pg0.sw_if_index, acl_index=self.acl_index
        )
        bindings = self.vapi.acl_mitigation_interface_dump()
        self.assertTrue(
            any(
                b.sw_if_index == self.pg0.sw_if_index and b.acl_index == self.acl_index
                for b in bindings
            )
        )
        self.drop(self.packet())
        self.vapi.cli(f"acl mitigation rule del acl {self.acl_index} rule 0")
        self.forward(self.packet())
        with self.vapi.assert_negative_api_retval():
            self.vapi.acl_mitigation_rule_add_del(
                acl_index=self.acl_index, is_add=False, rule_index=0
            )

    def test_source_scope(self):
        """An address component scopes the rule to its address family."""
        for mode in self.modes():
            self.replace(
                [
                    self.rule(
                        SRC_PREFIX, family=0, src_prefix=self.pg0.remote_ip4 + "/32"
                    )
                ]
            )
            self.drop(self.packet())
            self.forward(self.packet(ip6=True))

    def test_malformed_lengths_fail_closed(self):
        """Truncated IP and transport headers never manufacture a match."""
        self.replace([self.rule(DST_PORT, dst_port_first=53, dst_port_last=53)])
        # A header claiming unavailable payload is malformed, regardless of rules.
        self.drop(self.packet(len=500))
        self.drop(self.packet(ip6=True, plen=500))

    def test_interface_deletion_releases_context(self):
        """Deleting a bound interface releases its mitigation lookup context."""
        self.replace([self.rule()])
        interface = self.vapi.create_loopback().sw_if_index
        self.vapi.acl_mitigation_interface_set(
            sw_if_index=interface, acl_index=self.acl_index
        )
        self.vapi.delete_loopback(sw_if_index=interface)
        bindings = self.vapi.acl_mitigation_interface_dump()
        self.assertFalse(any(b.sw_if_index == interface for b in bindings))
        self.drop(self.packet())

    def test_legacy_replace_rejected(self):
        """The old API cannot erase mitigation match metadata."""
        self.replace([self.rule()])
        with self.vapi.assert_negative_api_retval():
            self.vapi.acl_add_replace(
                acl_index=self.acl_index, tag="legacy-api", count=0, r=[]
            )
        self.drop(self.packet())

    def test_cli_requires_explicit_action(self):
        """A sample-only rule must explicitly permit traffic."""
        with self.assertRaises(Exception):
            self.vapi.cli("acl mitigation rule add proto 17 sample 100")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
