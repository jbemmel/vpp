Native ACL mitigation
=====================

The ACL plugin provides a stateless ingress mitigation path using its native
lookup contexts and TupleMerge classifier. It supports the FastACL Community
fixed-field match model without loading a second classifier plugin. Members-only
admission is not included.

Match model
-----------

Each logical rule has component presence bits, an order, an address family,
an explicit drop/permit action, and optional sampling. The match bits are:

.. list-table::
   :header-rows: 1

   * - Bit
     - Component
   * - 0, 1
     - Destination/source prefix
   * - 2
     - IP protocol (including explicitly matching protocol zero)
   * - 3, 4, 5
     - Destination/source/either transport port, inclusive ranges
   * - 6, 7
     - ICMP type/code, exact values
   * - 8
     - TCP flags, value and mask
   * - 9
     - IP packet length, inclusive range
   * - 10
     - DSCP, exact value (0..63)
   * - 11
     - Fragment flags, value and mask

Fragment bits are DF=1 (IPv4), is-fragment=2, first-fragment=4, and
last-fragment=8. A last fragment has a nonzero offset and no more-fragments bit.
An IPv6 atomic fragment does not set these fragment bits. IPv6 DF is always zero.

All present components are ANDed; either-port tests source OR destination within
that component. Ports without a protocol component match TCP and UDP. ICMP
components select the appropriate IPv4/IPv6 ICMP protocol. TCP flags require
available TCP flags. Transport predicates never match noninitial fragments,
regardless of the legacy ACL fragment-compatibility setting. A protocol-only
rule does not require transport bytes. IPv6 options, routing, fragment and AH
headers are walked with bounds checks.

Family values are IPv4=0, IPv6=1, both=2. Both is valid only without address
components. Such a logical rule compiles into two native ACEs. Its counters and
sampling credits retain one logical identity across the two families.

Smaller ``order`` wins, then FastACL-style component precedence (prefix
specificity and component values), then the input rule index. This is the
supported fixed-field ordering model; it is not a BGP FlowSpec NLRI decoder or
an implementation of arbitrary numeric/bitmask expressions, IPv6 prefix offsets,
flow labels, routing validation, policing or redirect actions.

Placement and legacy compatibility
----------------------------------

``acl-mitigation-ip`` runs on ``ip4-unicast`` and ``ip6-unicast`` before the
existing session ACL nodes. ``acl-mitigation-l2`` runs on ``l2-input-ip4`` and
``l2-input-ip6``. An interface binding enables all four paths using VPP's
L2-aware feature API. Multiple interfaces may share the same mitigation ACL.
A permit or miss continues through subsequent features, including ordinary
ACLs; it does not override their decisions. This path does not create sessions,
so existing reflected sessions cannot bypass mitigation.

The existing ACL binary messages, exported vtable and 48-byte tuple/session-key
layout remain unchanged. Mitigation rule metadata is checked inside both native
linear and hash candidate selection. A failed residual predicate can therefore
fall through to a later candidate. Prefix and protocol accelerate hash lookup;
other components are verified in native collision vectors. Noninitial fragments
use the existing linear fallback. Mitigation ACLs cannot be attached to the
legacy session nodes or overwritten through ``acl_add_replace``.

Other lookup-context users can call ``acl_plugin_match_5tuple_inline_extended``
or load the optional ``acl_plugin_match_5tuple_extended`` symbol, supplying
``acl_mitigation_packet_t`` alongside the legacy tuple. The checked parser is
available in ``mitigation_packet.h``. Legacy calls without sidecar metadata never
match mitigation ACEs. Internal ACL rule structures have grown; plugins using
the inline headers must be rebuilt together with the ACL plugin.

Packet length and per-rule bytes refer to declared IP length, excluding
Ethernet headers and padding. Claimed IP lengths exceeding the buffer chain,
invalid IPv4 header lengths, and truncated IPv6 extension chains are dropped
on the mitigation path. Transport headers split across buffers are unavailable
to transport predicates. These parsing decisions do not change legacy ACL
processing. IPv6 jumbogram length options are not supported.

Configuration
-------------

Create a mitigation ACL and note the returned native ACL index::

    acl mitigation rule add order 10 dst4 10.0.0.0/24 proto 17 dst-port 53 action drop
    acl mitigation rule add acl 0 order 20 dscp 46 packet-length 60-1500 action permit sample 1000
    acl mitigation rule add acl 0 order 30 dst6 2001:db8::/32 tcp-flags 02 02 action drop sample 100
    set interface acl-mitigation TenGigabitEthernet0/0/0 acl 0
    show acl mitigation 0

Use the actual returned index instead of ``0``. An action is mandatory in the
CLI. A packet-observation rule should explicitly use ``action permit``.
``tcp-flags`` and ``fragment`` values/masks are hexadecimal; other scalars are
decimal. Prefix tokens select their family explicitly: src4, dst4, src6, dst6.
Address-free CLI rules select both families.

Deletion and detachment::

    acl mitigation rule del acl 0 rule 1
    set interface acl-mitigation TenGigabitEthernet0/0/0 disable
    delete acl-plugin acl index 0

Logical IDs are input indices. Deleting a rule renumbers subsequent IDs.
Deletion of an ACL still used by a lookup context is rejected. Interface deletion
releases its binding. Single-rule mutations and replacements reset that ACL's
per-rule counters, rate snapshots and sampling credits.

The ``mitigation.api`` binary interface provides:

* ``acl_mitigation_add_replace``: create or atomically replace an entire batch.
  Every rule is validated before publication; errors leave the active ACL intact.
  An empty batch installs a default-pass mitigation ACL.
* ``acl_mitigation_rule_add_del``: append one logical rule or delete an input ID.
* ``acl_mitigation_interface_set`` / ``acl_mitigation_interface_dump``: bind,
  detach, and inspect interfaces. An ACL index of ``0xffffffff`` detaches.
* ``acl_mitigation_config``: per-rule counter and psample enable switches.
* ``acl_mitigation_dump``: logical rules, exact packet/byte counters, sampling
  successes/failures and rate estimates. Index ``0xffffffff`` dumps all.
* ``acl_mitigation_stats_get``: aggregate processed/dropped totals and rates.

``acl_del`` deletes a detached ACL. Existing generic native diagnostics such as
``show acl-plugin tables`` remain available for inspecting masks and collisions.
Use the mitigation dump for complete rule semantics; the legacy ACL dump only
represents the coarse native prefix/protocol fields.

Sampling and counters
---------------------

On Linux, load the kernel psample module and enable export::

    acl mitigation config counters 1 psample 1

Enabling resolves the kernel family/group before publication and opens one
nonblocking generic-netlink socket per worker. All sockets must open successfully.
Unavailable psample does not disable the filter. Export requires privileges to
send generic-netlink multicast, normally CAP_NET_ADMIN. Disable with
``acl mitigation config counters 1 psample 0``.

Sampling selects every Nth matched packet per worker and logical rule, before
its action. It is deterministic, not statistical, and not a single globally
ordered sequence across workers. A credit spans IPv4 and IPv6 matches of the
same logical rule. Socket backpressure or permission failures count as failed
samples and never block packet processing. Selection restarts on rule updates;
disabling export pauses credits. No sample message allocation occurs in the
packet path.

Samples contain up to 256 bytes starting at the node's current buffer position
(IP on the routed path, Ethernet on the bridged path), with original captured
buffer-chain size and configured sample group/rate. The VPP ingress interface
index is a native-endian u32 ``PSAMPLE_ATTR_USER_COOKIE``, not a Linux ifindex.
Sequence numbers are per worker; multicast group IDs above 32 are unsupported.

Per-rule counters are enabled by default and use VPP's existing combined
counters at ``/acl/<index>/matches`` for the compiled ACEs. The logical dump sums
both families. ``counters 0`` removes per-rule counter writes; aggregate
accounting remains active at ``/acl/mitigation/aggregate`` (index 0 processed,
index 1 dropped). Malformed packets contribute packet counts but zero L3 bytes.

Rates are counter deltas between reads at least 0.5 seconds apart. PPS and L3
bps are derived from exact counters; L1 bps estimates add 38 bytes per IP packet
for untagged Ethernet framing, preamble and interpacket gap. This estimate does
not include minimum-frame padding, VLAN tags, tunnels or other encapsulation.
Concurrent reads are snapshots, not cross-worker transactional totals.

Performance and updates
-----------------------

This implementation retains native TupleMerge and its 48-byte bihash keys; it
does not reproduce FastACL's compact-key tables or claim equivalent throughput.
Cost depends on active masks and candidate-vector lengths. Rules differing only
in residual predicates may share a coarse key, so count collisions as well as
rules. Table publication uses worker barriers. Single-rule operations currently
recompile/reapply the entire ACL; batch operations avoid repeated publication.
Large or frequent updates must be benchmarked for worker pause time before
production use. No hardware throughput benchmark is included in this change.

Validation
----------

``test/test_acl_mitigation.py`` covers routed/bridged IPv4/IPv6, both native lookup
modes, residual fallthrough, port/ICMP/TCP predicates, fragment semantics, IPv6
extension headers, address scoping, precedence, atomic validation, accounting,
lifecycle and legacy attachment rejection. Sampling selection tests run when
the psample family is available. The real multicast-delivery test requires root
and the psample module, and verifies exported bytes before drop and permit.
