# Load balancer hashing

The LB plugin selects an application server (AS) for each new flow through a
weighted Maglev-style table. Packet lookup is O(1): mask the flow fingerprint,
read a table entry, then cache the assignment in the current worker's sticky
cache. Backend index zero represents no available server.

## Table construction

`maglev.h` builds the table from canonical backend identities, not pool indexes
or configuration insertion order. Address words are decoded from network byte
order and sorted numerically. Consequently, instances with the same addresses,
weights, and table size select the same backend identities even when their pool
indexes differ.

For table size M, backend weight w, and total weight W, each backend first
receives `floor(M*w/W)` buckets. Remaining buckets go to the largest fractional
remainders; address order breaks ties. Each allocation differs from its ideal
share by less than one bucket. For example, M=1024 with weights 100:50 produces
683:341 buckets. Multiplying all weights by the same factor preserves the table.
Weights of zero receive no buckets. If every weight is zero, the table contains
only the no-server entry. A backend can receive zero buckets when M is too small
to represent its share; choose M accordingly.

Each physical backend has one permutation. Ordered address hashing and separate
offset/stride domains avoid the address-XOR-replica collisions of weight-expanded
replicas. A smooth weighted schedule chooses which backend places the next
bucket, subject to its quota. Placement follows that backend's permutation until
an unused bucket is found. M remains a power of two: an odd stride traverses all
M buckets, allowing masking rather than division in packet lookup. M=1 is also
supported.

Builder scheduling costs O(M*N) for N live backends, plus permutation probes and
O(N log N) sorting. Scratch storage is O(M+N), independent of the sum of weights.
Configuration writers stop workers through VPP's recursive worker barrier before
mutating pools or caches, rebuilding/publishing tables, and freeing old tables.
This favors straightforward lifetime correctness; large updates pause packet
processing for the duration of the rebuild.

## Flow fingerprints and affinity

`lb_hash_words(a, b, c, d, e)` uses the same seeded chain of five
`clib_xxhash()` calls on every CPU. It consumes the words in reverse argument
order, `e, d, c, b, a`, so callers' constant trailing arguments are processed
first and can be evaluated at compile time after inlining.

| Caller | Constant initial rounds | Runtime rounds |
| --- | ---: | ---: |
| IPv4 source-IP-sticky | 4 | 1 |
| Ordinary IPv4 TCP/UDP | 2 | 3 |
| IPv6 source-IP-sticky | 1 | 4 |
| Ordinary IPv6 TCP/UDP | 0 | 5 |
| Backend permutation offset or stride | 3 | 2 |

These counts assume an optimizing compiler. Inspection of Clang `-O3` x86-64
assembly confirmed 6 multiply instructions for IPv4 source-IP-sticky hashing,
18 for ordinary IPv4, and 30 with five variable words. One standalone
`clib_xxhash()` call also uses 6 multiplies. Debug builds need not fold the
constant rounds.

Reordering saves runtime work through constant folding; each remaining round
still depends on the previous result. It does not introduce independent lanes
within one fingerprint. Independent packet hashes can overlap when callers
process a batch. No CRC/SIMD-specific hash path or extra multiword hash
implementation is used.

Packet address and TCP/UDP port words are explicitly decoded from network byte
order. Ordinary flow fingerprints include addresses, ports, and IP protocol.
The source-IP-sticky mode omits ports and protocol and retains the destination
address, preserving its existing affinity scope. Other protocols currently use
zero port words; packet parsing of IPv4 options, fragments, and IPv6 extension
headers is not extended by this change.

Sticky entries match a 32-bit fingerprint and VIP index. The packet path uses
the low 32 bits of the ordered 64-bit mixer; backend permutation construction
continues to use the mixer directly. Fingerprint matching is not full tuple
verification: two flows with the same fingerprint and VIP share an assignment. Every one of the four ways in a bucket
is searched. A deadline equal to the current time is expired; signed modular
subtraction handles timer wrap for timeouts below 2^31 ticks. Successful lookups
refresh the deadline. Configuration rejects timeouts of 2^31 ticks or more.
Capacity reporting counts all four ways per bucket.

A bucket retains the original 64-byte payload: four 32-bit fingerprints, four
deadlines, four VIP indexes, and four backend indexes. With 64-byte cache lines,
each aligned bucket occupies one cache line. Lookup uses one portable scalar
implementation so match and expiry semantics do not depend on SIMD availability.
Hashing throughput still requires benchmarking on the target deployment; no
packet-rate performance claim is made here.

Weight zero is a graceful drain: existing cached assignments continue until
expiry. A flush removes those assignments and expires their slots for immediate
reuse, so subsequent packets select through the current table. Flushing a backend at nonzero weight can select that same
backend again. Changing weights redistributes new flows, not existing cached
sessions. If all four cache ways are occupied, packets use the table without
being tracked; a later table update can move those connections. Idle expiration
or moving a flow to another worker can likewise expose the current mapping.

## Remapping guarantees and tradeoffs

Construction is deterministic for a backend configuration and independent of the
previous table. It does not guarantee minimal movement on membership or weight
changes. Exact quotas and schedule changes can move buckets between surviving
backends as well as away from removed backends. Increasing M improves weight
resolution but does not itself establish a movement bound.

`test lb hashing` reports total changed buckets and excess movement between
surviving backends for removals and additions, plus movement during a small
weight change. The unavoidable removal baseline is the removed backend's previous bucket count.
Compare backend identities rather than local pool indexes across instances.

Weighted rendezvous hashing remains an alternative when minimal movement is more
important than exact bucket quotas. It can also build an O(1) lookup table, with
O(M*N) scoring work, but its bucket shares are statistical. This implementation
retains permutation placement and exact quotas; it does not introduce a second
algorithm or a compatibility mode. The new table construction and fingerprint
algorithm change mappings relative to older builds; mixed builds should not be
assumed to agree on flow placement.

## Validation

Build the plugin from the VPP repository root:

```sh
cmake --build build-root/build-vpp_debug-native/vpp --target lb_plugin -j 6
```

In a VPP instance loading this plugin:

```text
test lb hashing
```

The regression command exercises exact quotas, common-factor weight scaling,
zero weights, tiny tables, insertion-order and pool-index independence,
removal/addition movement, small weight changes, all four sticky-cache ways, VIP
isolation,
32-bit fingerprint distinctions, single-cache-line bucket size, capacity,
deadline equality, and timer wrap.
The Python LB suite invokes this command and verifies weighted API bucket counts,
draining, and packet forwarding:

```sh
make test-debug TEST=test_lb
```

Run the same suite with workers enabled to exercise configuration barriers:

```sh
make test-debug TEST=test_lb VPP_WORKER_COUNT=2
```

The debug build and all 23 LB tests passed with no workers. A rerun with two
workers also passed all 23 tests. An earlier two-worker run aborted during
interface setup with a worker-barrier deadlock before any LB test executed;
that failure did not reproduce on the rerun, and its cause remains undiagnosed.
The assembly check above verifies constant folding, not packet throughput.
