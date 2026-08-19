# IPv4/IPv6 fragmentation, reassembly, and PMTU (implementation plan)

Started 2026-08-19 and finalized 2026-08-20. This is the required design
round for the fragmentation work approved in
`networking-remaining-steps.md`. It follows a fresh trace of the deployed
sys-io feature closure and the relevant paths through moto-netstack,
sys-io, moto-io, moto-rt, and rt.vdso. The review decisions are resolved;
implementation proceeds in the incremental sequence below.

## Outcome and scope

Implement bounded, overlap-safe IPv4 and IPv6 host reassembly; IPv4 and
IPv6 source fragmentation for accepted UDP datagrams; and the minimum
PMTU discovery needed to stop smaller downstream MTUs from black-holing
TCP or UDP. A send that sys-io accepts solely because Motor advertises
large-UDP support must no longer be discarded inside interface dispatch
while the application sees success.

This is host behavior, not forwarding/router behavior. Motor still does
not forward IP packets. The production IPv6 parser continues to support
the base header and its existing single Hop-by-Hop header only; Routing,
Destination Options, AH/ESP, jumbograms, and a general extension-header
walker remain out of scope. Raw sockets, multicast, SLAAC, DHCP, and
6LoWPAN are not enabled in sys-io and are not enabled by this series.

Incoming ICMP errors other than IPv4 Fragmentation Needed and IPv6
Packet Too Big remain raw-ICMP-only. In particular, this series does not
add connected-UDP asynchronous errors, `SO_ERROR`, or ERROR readiness.
Those semantics remain a separate item in the parent plan.

## Audit corrections and dormant-code hazards

The parent plan identifies the deployed symptom correctly, but the
implementation cannot safely be obtained by only turning on the two
features:

- sys-io omits `proto-ipv4-fragmentation` and
  `proto-ipv6-fragmentation`. With the former off, `Ipv4Repr::parse`
  rejects every fragment. IPv6 has a wire representation for the
  Fragment header but no interface ingress or egress implementation.
- Oversized IPv4 and IPv6 dispatch currently log and return `Ok(())`.
  `udp::Socket::dispatch` therefore commits its transactional dequeue,
  wakes the sender, and loses the datagram. This is the successful
  silent drop being fixed.
- The dormant IPv4 reassembler accepts overlapping bytes with
  last-arrival-wins semantics. Its unit test explicitly expects
  `RRust` from two overlapping copies of `Rust`. It neither rejects an
  overlap nor tombstones a poisoned key.
- `REASSEMBLY_BUFFER_SIZE` is generated but unused. Each count-bounded
  assembler owns a dynamically growing `Vec` and resizes to a received
  end offset or claimed final size. The current feature is therefore a
  count setting, not the byte bound its name promises.
- `Assembler::add` can reject a fragment after 32 disjoint ranges, but
  `PacketAssembler::add` ignores that result. The bytes are copied but
  uncounted, so the assembly can silently remain incomplete and hold its
  slot until expiry unless a later accepted fragment covers or bridges
  the missing range.
- The one interface-wide IPv4 egress staging buffer can be overwritten.
  `poll_egress` emits one pending fragment and then immediately services
  sockets; another oversized packet can replace the still-active packet.
  Ingress-generated replies can collide with it for the same reason.
- `FRAGMENTATION_BUFFER_SIZE` is 1,500 in an unconfigured production
  build and 4,096 under `cfg(test)`, neither sufficient for Motor's
  advertised large UDP datagrams. The test configuration is hardcoded
  and ignores build-script configuration features.
- The focused and full gate scripts call their netstack feature list
  the exact sys-io closure, but omit sys-io's
  `assembler-max-segment-count-32` and
  `iface-neighbor-cache-count-64` configuration features. (Omitting
  fragmentation matches sys-io today rather than diverging from it.)
  The mismatch happens to be inert because `cargo test` compiles the
  hardcoded `cfg(test)` config module and count/size cargo features
  never reach it; the fix is honest test constants plus const pins,
  not the feature list alone.
- Motor's actual `MAX_UDP_PAYLOAD` is 65,493, not the 65,507 stated in
  the parent diagnosis. The moto-rt comment records only that the old
  netstack refused anything larger; the value is consistent with an
  Ethernet header wrongly subtracted from the IPv4 maximum. Once the
  IP/link-layer accounting is fixed, the common IPv4/IPv6 API limit can
  be the real IPv4 maximum: 65,535 - 20 - 8 = 65,507. Only in-tree
  crates (rt.vdso, moto-io, moto-io-internal, and systest) read the
  constant; the toolchain std never compiles it in, so raising it needs
  no toolchain rebuild, and a moto-rt publish only keeps the published
  constant honest for out-of-tree readers.
- ICMPv6 already parses Packet Too Big and its 32-bit MTU, but the v6
  ICMP-socket filter has no Packet Too Big arm, so today it reaches
  nothing. ICMPv4 knows destination-unreachable code 4 but treats its
  next-hop-MTU field as unused, so its representation cannot implement
  RFC 1191 yet. Other ICMP errors are delivered only to ICMP sockets,
  which sys-io binds solely for ping.
- ICMPv4 error emission never writes that unused field, and sys-io
  transmits from recycled, non-zeroed pool buffers, so every emitted
  ICMPv4 error (for example protocol-unreachable) discloses four bytes
  of stale sys-io memory on the wire today. Step 1 closes this leak,
  and the fix is live immediately, independent of the fragmentation
  features.
- TCP derives every outgoing segment limit from the interface MTU. It
  has no destination-MTU lookup. TSO is not an obstacle: `tso_seg_size`
  is only set on super-segments and equals the effective payload MSS,
  and nothing revalidates it against the physical MTU, so feeding PMTU
  into the effective-MSS computations lowers plain segments and TSO
  wire packets together.
- Normal emitted IPv4 packets set DF. After a validated smaller PMTU,
  TCP should resegment and UDP should source-fragment with DF clear.
  IPv6 must resegment or source-fragment; a router cannot fragment it.
- sys-io deliberately computes UDP checksums in software. That is the
  right production contract for fragments because only the first
  fragment contains the UDP header; virtio `NEEDS_CSUM` cannot describe
  the remaining fragments.

## Resource and admission policy

The bounds are per interface, shared by IPv4 and IPv6:

- Four simultaneous reassembly slots.
- At most 65,535 fragmentable bytes in one slot, with all IP-version
  length rules applied before growth.
- At most 32 disjoint received ranges per slot, reusing the deployed
  `ASSEMBLER_MAX_SEGMENT_COUNT` bound. Exceeding it poisons the whole
  assembly rather than losing only one range. A maximum datagram needs
  45 full-sized fragments at IPv4 MTU 1,500 and 54 at IPv6 MTU 1,280;
  their maximum alternating-arrival range counts are 23 and 27, so the
  bound covers those normal cases. Low-MTU IPv4 is different: MTU 576
  needs 119 fragments and the permitted MTU 68 needs about 1,365, so
  sufficiently reordered legitimate traffic can exceed 32 ranges and
  be dropped. A standards-compliant sender choosing smaller-than-needed
  fragments can likewise exceed the bound at any MTU. Keeping 32 is an
  explicit memory/DoS tradeoff, not a claim of complete reordering
  tolerance; the poison is counted and UDP remains lossy by contract.
- One egress staging slot of 65,536 bytes. It stores only the
  fragmentable payload, not an Ethernet or IP header, so it is large
  enough for either IP version without repeating the old link-header
  accounting error.
- A 60-second reassembly lifetime, fixed when the key is first admitted;
  later fragments do not extend it.

Linux instead admits a dynamic number of queues under memory thresholds,
separately for IPv4 and IPv6 in each network namespace, and defaults to a
30-second IPv4 timeout and 60-second IPv6 timeout. Motor deliberately
uses four slots shared across both versions and one 60-second timeout: it
is a simple deterministic per-interface memory bound, not a claim to
copy Linux's scale or policy.

The maximum retained fragment payload is therefore 4 * 65,536 bytes
for ingress plus 65,536 bytes for egress: 320 KiB per interface, plus
small keys/range metadata. Ingress buffers remain lazy `Vec`s. Growth
uses a checked protocol end offset and a fallible exact reserve before
resize; allocation failure poisons that assembly. Buffers retain their
bounded capacity for reuse, avoiding allocator churn under repeated
traffic. The egress slot is fixed storage so a UDP datagram already
accepted into sys-io cannot become a silent allocation-failure drop on
its way to the device. This adds 64 KiB of zeroed interface state at
construction, but no task, timer, or continuing boot work.

Slots are first-free and non-evicting. Once all four are live, a new key
is dropped and counted until a slot completes or expires. This protects
an in-progress legitimate datagram from churn; an attacker can still
occupy all four slots for at most 60 seconds. Per-source caps do not
materially improve that property because source addresses are spoofable,
while they reject ordinary parallel fragments from one real host.

Expired slots are reclaimed only at existing ingress/maintenance poll
edges. No periodic task or boot-time timer is added. Initial expiry is a
silent drop with a reason-specific counter. Linux can send Time Exceeded
when the first fragment was received; Motor deliberately defers that
response until the separate ICMP-error rate limiter lands. Adding an
unbounded reflector while fixing reassembly would be a security
regression.

The Cargo configuration becomes real and identical in production and
tests: `fragmentation-buffer-size-65536`,
`reassembly-buffer-size-65536`, and `reassembly-buffer-count-4` are
selected by sys-io and by both gate scripts, and the hardcoded test
constants match. Code enforces the byte setting rather than merely
publishing it.

## Reassembly validation and overlap policy

IPv4 uses the existing RFC key `(source, destination, protocol,
identification)`. IPv6 uses `(source, destination, 32-bit
identification)` and records the Fragment header's Next Header value;
a later mismatch poisons the key. Both versions require a checked base
header and the existing destination/source admission checks before
allocating state.

After all structural and final-size checks, a range wholly contained in
already received coverage is an ignored duplicate. The incoming bytes
are not compared or copied; first arrival wins and the original assembly
continues unchanged. Any intersection that also extends into previously
uncovered space is a true overlap and poisons the entire assembly. This
follows current Linux IPv6's duplicate/overlap distinction and applies it
consistently to Motor IPv4 and IPv6.

A truly overlapping key remains as a no-buffer tombstone until its
original expiry, so later fragments cannot reopen the same identification
and assemble a packet from the suffix of the rejected one. Linux IPv6
discards the current assembly without this tombstone; retaining it is
Motor's stricter bounded defense against suffix-based reopening. The
tombstone is
the slot itself — the key and expiry stay, the fragment data does not —
so tombstones never exceed the four slots. Every fragment matching a
tombstone is discarded. Rejection creates no state for a key that holds
no received bytes: such a fragment is dropped and counted, never
tombstoned, because invalid traffic should not receive state before any
valid bytes. This avoids one cheap admission path but does not prevent an
attacker from occupying all four slots with syntactically valid minimal
fragments.

Before copying, reject the fragment, and poison the key if it already
holds received bytes:

- a zero-length non-final fragment;
- a non-final payload whose length is not a multiple of eight;
- a byte offset/end overflow or an end beyond the IP version's maximum;
- a final size inconsistent with an earlier final fragment;
- a received range extending beyond a known final size, or a later final
  size ending before already received data;
- any intersection with received coverage that is not wholly contained
  in that coverage;
- an IPv4 packet combining DF with MF or a nonzero offset, or setting
  the reserved flag;
- nonzero IPv6 Fragment reserved fields, nested Fragment headers, or a
  Fragment header outside the supported base-header / one-Hop-by-Hop
  chain;
- a first fragment too small to contain the complete fixed upper-layer
  header the declared protocol requires (UDP 8 bytes, TCP's checked data
  offset with a 20-byte minimum, ICMP 8 bytes). This closes the classic
  tiny-first-fragment ambiguity and satisfies the relevant IPv6
  first-fragment rule within Motor's supported header chain.

IPv4 stores the offset-zero header representation and delivers only
with that representation; arrival order cannot make the last fragment's
TTL/header stand in for the first. IPv4 options remain unsupported on
egress and are not exposed through production raw sockets, but a checked
incoming IHL is included when enforcing the 65,535-byte total-length
limit.

IPv6 accepts a Fragment header immediately after the base header or
after the one Hop-by-Hop header already supported by production. The
unfragmentable headers are parsed on every fragment; the reassembled
fragmentable payload is passed to the Fragment header's recorded Next
Header. Fragment Offset is normalized to byte units in the wire API;
the current unused representation exposes raw eight-octet units and
never documents the unit while the IPv4 accessor returns octets, an
avoidable source of offset mistakes.

An IPv6 atomic fragment (`offset == 0 && M == 0`) is validated, has its
Fragment header removed logically, and is processed without allocating
or consulting reassembly state. It therefore cannot collide with a
normal fragmented datagram using the same identification (RFC 6946).

Completion clears the slot only after the reassembled payload has been
handed down during the same poll. TCP/UDP checksum verification is
forced into software after reassembly regardless of any one fragment's
receive-offload metadata. Payload is never exposed before a gap-free
range from zero through the one agreed final size exists.

## Source fragmentation and egress serialization

`Fragmenter` becomes an explicit idle/IPv4/IPv6 state. Starting a large
packet first emits its complete L4 payload into the fixed staging slot,
then commits the first wire fragment. Only after that succeeds does the
socket dispatch return success and dequeue UDP's original datagram.

While staging is active, poll emits at most one fragment per bounded
`poll_egress` call and does not service a second socket packet in that
call. Emitting a pending fragment reports progress so the outer
`Interface::poll` loop continues while the device has tokens; device
exhaustion leaves the state intact and `poll_at` at Now.
An oversized socket packet encountered while the slot is busy receives
a transient dispatch result and remains queued. An ingress-generated
response can be dropped and counted if it cannot claim the slot, but it
can never overwrite an active datagram.

Fragment sizes use the destination's effective PMTU, not Ethernet frame
size:

- IPv4 copies the normal 20-byte emitted header to every fragment. Every
  non-final payload is `floor((PMTU - 20) / 8) * 8`; MF and byte offsets
  are set consistently, DF is clear, and the IPv4 header checksum is
  recomputed for every fragment.
- IPv6 emits an eight-byte Fragment header after the base header. Every
  non-final fragmentable payload is
  `floor((PMTU - 40 - 8) / 8) * 8`; the base header names Fragment and
  the Fragment header names the original upper-layer protocol. Source
  fragmentation in this series covers the production TCP/UDP chain
  directly after the base header; outbound extension-header chains are
  out of scope.
- The UDP/TCP checksum is computed once over the complete original L4
  packet and pseudo-header before its bytes are sliced. UDP stays on the
  existing software-checksum path.

IPv4 uses a fixed table of 256 wrapping 16-bit counters per interface.
SipHash-2-4 under a new independent 128-bit interface key maps the exact
`(source, destination, protocol)` to a bucket. The hashed byte encoding
is domain byte zero, the two IPv4 addresses in network order, and the
protocol byte; the low eight hash bits select the bucket. Domain byte one
and the bucket byte are hashed for its initial counter; the low 16 bits,
with zero mapped to one, become the first value. A 256-bit initialized
bitmap avoids filling the table or drawing 256 random values at
construction. The public `Config::ipv4_fragment_id_key` is
deterministic in tests, and sys-io fills it directly from
the platform entropy source, independently of the TCP ISN and SYN-cookie
keys. Hash collisions merely share a counter; they cannot repeat an ID
within one tuple before the unavoidable 16-bit wrap. There is no dynamic
destination state or eviction. Only actually fragmented IPv4 datagrams
consume a counter value.

IPv6 draws a fresh 32-bit identifier from the existing interface RNG for
each actually fragmented datagram, mapping zero to one. Production
already seeds that RNG from the platform entropy source. This follows
Linux's broad strategies — tuple-keyed counter buckets for IPv4 and a
fresh random value for IPv6 — at a deliberately smaller fixed IPv4 table.
A new IPv6 Fragment header wire type covers all eight bytes, including
Next Header and reserved validation, rather than requiring callers to
compose a generic two-byte extension prefix with the current six-byte
fragment body.

TCP is never IP-fragmented by this work. It consults destination PMTU for
its outgoing effective MSS and emits smaller segments. With TSO it may
still hand the device a super-segment, but `tso_seg_size` is the smaller
path-MSS payload, so every resulting wire packet observes PMTU. The MSS
advertised in SYN/SYN|ACK remains based on interface receive MTU, not an
outgoing route cache that can be asymmetric.

Motor's shared `MAX_UDP_PAYLOAD` becomes 65,507. Validation moves to the
shared moto-io enqueue boundary so `try_send_to`, `send_to_future`, and
the rt.vdso blocking veneer cannot diverge. IPv4 egress at that limit is
exactly 65,535 bytes; IPv6 remains below its non-jumbo payload limit.
Payload above the API maximum fails synchronously before sys-io sees it.

## PMTU cache and authenticated-enough ICMP association

Each interface gets a lazy, fixed-ceiling cache of 64 host destinations.
An entry contains destination address, reduced MTU, and expiry. Expired
entries are removed on lookup/update; full insertion replaces the least
recently updated entry. Route-table mutation flushes the cache; because
`Routes` has no mutation hook today and its default-route helpers bypass
`update`, every mutating entry point is first funneled through one
internal method that reorders and flushes. A cache miss uses the
physical interface IP MTU.

A validated ICMP decrease lives for ten minutes. That lifetime matches
Linux's default PMTU expiry; the 64-entry ceiling does not — Linux route
cache sizing is dynamic and much larger. The fixed Motor ceiling is an
intentional bounded-memory tradeoff. ICMP never raises a cached PMTU and
a non-decrease does not refresh its expiry. Expiry returns the
destination to interface MTU; the next oversized packet can rediscover a
still-small path. There is no periodic probing or PLPMTUD in this series.

IPv6 Packet Too Big values are clamped to the IPv6 minimum MTU of 1,280
and must still be below the current effective PMTU and below the quoted
packet size. IPv4 next-hop MTU is clamped to at least 68. A zero MTU from
an old RFC 1191 peer selects the next lower standard plateau below the
quoted IPv4 header's declared total length, not the number of quote bytes
the ICMP packet happened to carry; a nonzero nonsensical/non-decreasing
value is ignored. PMTU is keyed by the quoted destination, never by the
outer ICMP source (the reporting router need not be the next hop).

The outer ICMP packet must already pass normal IP destination/source and
ICMP checksum validation. The quote must name a source address assigned
to this interface, name a unicast destination, use the production-
supported header chain, and associate with a currently live flow. An
unfragmented quote contains a checked IPv4/IPv6 base header plus the
first eight TCP/UDP bytes.

A fragment quote qualifies only for UDP: TCP is never IP-fragmented by
this design. IPv4 must have offset zero and MF set and include the first
eight UDP bytes. IPv6 must include a complete, checked Fragment header
with zero offset, M set, valid reserved fields, Next Header UDP, and the
first eight UDP bytes. A nonzero offset has no transport header to
associate and is rejected. Accepting a validated first-fragment quote is
necessary because it is what a smaller downstream link drops from
Motor's own fragmented IPv6 datagram; rejecting every fragment quote
would permanently black-hole that UDP flow. The fragment identifier is
not used for association: an exact value is overwritten by the next send,
while an accumulated interval is neither time-bounded under continuous
traffic nor meaningful for interleaved, wrapping IPv4 counters.

Flow association is then:

- TCP: the authoritative exact tuple map must name a TCP socket, and the
  quoted sequence number must lie in sequence space that socket has sent
  but has neither cumulatively retired nor marked SACKed; it is treated
  as the start of the quoted segment. A fragmented TCP quote is rejected.
  Together these checks reject a guessed tuple without plausible live,
  outstanding sequence and make the later loss mark effective.
- UDP: the authoritative local-port map must name the socket, and the
  exact `(local address/port, remote address/port)` actually emitted must
  appear in that socket's eight-entry recent-send LRU, recorded only after
  successful interface dispatch and expiring 60 seconds after that
  tuple's latest successful dispatch. The address types make the IP version part of the
  exact tuple; no fragment-identifier state is retained. Eviction of the
  whole record still deliberately rejects an otherwise valid delayed
  quote rather than weakening association. This is stricter than Linux's
  UDP socket/tuple lookup and is necessary because moto-netstack UDP
  sockets are bound, not connected, so a local-port lookup alone does not
  prove that the quoted destination was used.

These checks do not make ICMP cryptographically authenticated; an
on-path observer can quote a real packet, and an off-path attacker can
still guess a live UDP four-tuple. They prevent a packet containing only
a guessed local port or unrelated destination from lowering a route,
without adding a per-packet global hash table to the hot path.

After a decrease, future UDP datagrams fragment at the cached PMTU and
existing TCP connections resegment retransmissions and new data at it.
Before applying a validated TCP decrease, preserve the old effective
payload MSS. Mark at most
`[quoted_seq, min(quoted_seq + old_effective_mss, SND.MAX))` lost in the
scoreboard, leaving any SACKed subranges alone. The start must be in an
unsacked run; scoreboard runs can coalesce several transmissions, so the
whole run must not be marked. The existing lost-run retransmission path
then resegments that bounded span at the new MSS without treating Packet
Too Big as congestion loss. Without the mark, recovery may wait for
later delivery evidence, TLP, or RTO; it is not necessarily a full RTO.
The forged-message exposure added beyond the MSS change is bounded to one
old-MSS span of spurious retransmission, gated by the same flow
validation.

If the one active fragment staging packet has the same destination, it
restarts at offset zero with a fresh identification so its already-sent,
too-large prefix cannot leave an unreconstructable suffix. A UDP packet
that was sent unfragmented and caused the ICMP is not retained for
automatic retransmission; UDP delivery is still unreliable, and the
cache governs subsequent sends.

An interface whose physical MTU is below 1,280 cannot provide standards-
compliant IPv6 without link-layer fragmentation (which virtio Ethernet
does not provide). As Linux does at IPv6 device admission, configuration
marks such a device IPv6-ineligible and rejects IPv6 addresses and routes
on it; IPv6 bind/connect therefore fails before a datagram can be
accepted. It must not become another successful egress drop. IPv4
remains usable down to 68-byte PMTU. Production devices currently use a
1,500-byte MTU.

## Observability

Add wrapping per-interface counters and drain them into sys-io's existing
stats pass, without per-packet warning logs:

- fragments received and transmitted, by IP version;
- reassemblies completed;
- reassembly datagrams dropped by malformed/true overlap, no slot,
  allocation failure, and expiry, plus a separate count of ignored
  duplicate fragments;
- datagrams poisoned by the 32-range bound, exported specifically as
  `net.reassembly.range_limit_drops` with moto-stats ID
  `NET_REASSEMBLY_RANGE_LIMIT_DROPS`;
- egress fragment-stage busy drops for socketless replies;
- PMTU updates accepted and ICMP PMTU messages rejected.

Tests assert the reason counters at the same time as behavior. Fragment
and rejected-PMTU counters are available through stats but do not emit
warnings: even a per-poll aggregate warning would let untrusted traffic
amplify logs.

## Tests under the production closure

Packet-level moto-netstack tests are the primary protocol regressions and
must compile with exactly the sys-io feature list. Both
`full-test-networking.sh` and `full-test.sh` use one identical list that
includes the two fragmentation flags and sys-io's configuration features
(assembler range count 32, neighbor count 64, and the three
fragment/reassembly size/count selections). The count/size selections
never reach `cargo test` — the crate substitutes its hardcoded
`cfg(test)` config module — so the corrected list makes the scripts'
exact-closure comment true and compiles the fragmentation tests, while
the binding guarantee is the matching hardcoded test constants plus
sys-io const assertions that pin the production values, making drift a
build failure rather than an audit note.

Reassembly tests, for both IP versions where applicable:

- in-order and several out-of-order permutations;
- a gap that completes only with the last arrival;
- identical and fully contained duplicates are ignored without comparing
  or replacing original bytes, and the original assembly can complete;
- a partial overlap, including one arriving after an apparent last
  fragment, poisons and tombstones the key;
- no resurrection of a tombstoned key before expiry, and clean reuse
  after expiry;
- inconsistent final sizes, data beyond final size, zero non-final,
  unaligned non-final, offset/end overflow, reserved bits, IPv4 DF plus
  fragments, IPv6 nested Fragment, and tiny first fragments;
- exact maximum legal payload and one-byte-over-limit rejection without
  allocation beyond the cap;
- four concurrent keys, fifth-key refusal, completion/expiry reuse, and
  33 disjoint ranges taking the bounded poison path and incrementing
  `net.reassembly.range_limit_drops` exactly once for the datagram;
- maximum low-MTU IPv4 input completes in order, while an alternating
  order that exceeds 32 simultaneous ranges takes the documented poison
  path and increments its reason counter;
- keys differing only by source, destination, protocol (IPv4), or
  identification do not mix;
- IPv6 atomic fragments bypass and do not disturb matching normal state;
- Fragment directly after IPv6 base and after the supported Hop-by-Hop
  header;
- reassembled UDP/TCP checksum is verified in software even when every
  input frame claims receive offload validation.

Egress tests:

- exact MTU is one packet; MTU+1 is fragmented;
- every frame is at most PMTU; all non-final payloads are eight-byte
  aligned; offsets, MF/M bits, total/payload lengths, Next Header, IDs,
  IPv4 DF, and IPv4 header checksums are exact;
- reassembling captured fragments byte-for-byte reproduces the original
  UDP header and payload and its checksum verifies;
- IPv4 IDs advance only within the keyed tuple bucket, wrap correctly,
  tolerate bucket collisions, and are not consumed by unfragmented
  packets; IPv6 consumes a fresh nonzero RNG value per fragmented
  datagram;
- the API-maximum 65,507-byte UDP payload completes for IPv4 and IPv6;
- device exhaustion preserves the staging state and later resumes;
- a second oversized socket datagram remains queued while staging is
  busy, cannot overwrite it, and progresses after completion;
- TSO TCP uses path-MSS `tso_seg_size` and never enters IP fragmentation;
- low IPv4 PMTUs remain arithmetic-safe; sub-1,280 devices reject IPv6
  configuration, route selection, and socket setup before send enqueue.

PMTU tests:

- parse/emit IPv4 next-hop MTU, including legacy zero; parse IPv6 PTB;
- accept a live TCP tuple with an outstanding unsacked sequence and a
  recent exact UDP send;
- accept an offset-zero first-fragment UDP quote only when the complete
  Fragment header where applicable and exact quoted flow match a recent
  successful send — including a delayed quote for an earlier datagram
  while that flow keeps sending; reject a missing, stale, or evicted flow
  record, fragmented TCP, and a nonzero-offset fragment quote;
- reject wrong local address, ports, destination, protocol, truncated
  quote, stale UDP send, missing socket, and unsent, retired, or SACKed
  TCP sequence;
- ignore non-decreasing and impossible MTUs; apply IPv4 68 and IPv6 1,280
  floors; exercise the zero-MTU plateau; expire after ten minutes and
  evict the least-recently-updated of 64 entries;
- route mutation flushes PMTU;
- a decrease changes subsequent TCP segment/TSO size and UDP fragment
  size, immediately retransmits at most one old-MSS span starting at the
  quoted unsacked TCP sequence, does not mark a coalesced scoreboard run
  wholesale or charge congestion control, and leaves SYN MSS at the
  interface receive MSS;
- exercise the bounded TCP loss mark with coalesced scoreboard runs,
  SACK boundaries, a short tail segment, and a sequence quoted from a TSO
  wire segment;
- a decrease for the active staged destination restarts it from zero
  under a fresh ID; another destination is unaffected.

Full-stack coverage keeps the existing loopback maximum-UDP test, updates
it to 65,507, adds IPv6 maximum-UDP loopback coverage, and adds a small
std-only host echo helper to the focused gate. A guest subcommand sends
and receives a deterministic payload larger than the 1,500-byte tap MTU
over both `192.168.4.1` and `2001:db8::1`. This gives production sys-io,
virtio, Ethernet, host reassembly/source fragmentation, moto-io, rt.vdso,
and std one deterministic local-tap path without Internet traffic or
privileged raw injection. Malformed/overlap and synthetic PMTU cases stay
in packet tests, where exact frames and time are deterministic.

## Incremental patch sequence

Keep each commit near 100-300 changed lines including tests; split a step
again if its test matrix makes it larger. Every commit is independently
formatted, warning-clean, and gated before the next:

1. Correct the full eight-byte IPv6 Fragment wire representation and
   IPv4 next-hop-MTU representation, with wire tests. ICMPv4 emit
   starts writing the formerly unused field, closing the live
   stale-memory leak recorded in the audit above; a test pins the
   emitted bytes.
2. Make `PacketAssembler` enforce byte/range bounds and expose duplicate,
   overlap, final-size, poison/tombstone, expiry, and allocation outcomes,
   with focused storage tests. Do not enable production features yet.
3. Harden and test IPv4 ingress reassembly on the new engine.
4. Add and test IPv6 ingress reassembly and atomic-fragment behavior.
5. Refactor the egress staging state to bounded payload-only storage and
   serialize polling; retain existing IPv4 behavior behind its feature.
6. Complete IPv4 source-fragment validation/tests, add the fixed keyed
   identifier-counter table, and raise/enforce the shared UDP maximum at
   the moto-io enqueue boundary. This is the reviewed moto-rt API-constant
   change.
7. Implement IPv6 source fragmentation, identifier generation,
   sub-1,280 physical-MTU device rejection, and tests.
8. Add the bounded PMTU cache as a pure interface/route component, with
   expiry, floor, plateau, flush, and capacity tests.
9. Add recent exact UDP-send tracking plus bounded, unsacked TCP
   quoted-sequence validation, then associate ICMPv4/v6 PMTU messages
   with live transmissions.
10. Feed destination PMTU into TCP segmentation/TSO and UDP
    fragmentation, including active-stage restart tests.
11. Add counters, select the exact production feature/config closure in
    sys-io and both scripts, add const pins and the local-tap system test,
    then run the final gates.

The fragmentation flags land in production only in the last step, after
all ingress, egress, and PMTU pieces are present. Intermediate commits
test the explicit feature closure directly but cannot expose partial
behavior in the boot image.

## Validation and stop rules

For each commit:

- `cargo +nightly fmt`;
- target-aware clippy with no new warnings for every touched crate;
- focused unit tests for the touched layer under the exact features;
- three clean debug and three clean release runs of
  `src/tests/full-test-networking.sh` (the user-selected substitute for
  `full-test.sh`).

No retries, timeout increases, ignored failures, or Internet-dependent
new tests. Nothing edits the tree while a gate is running. An
implementation discovery that requires a new protocol decision, a
preexisting non-test defect, an allocation/panic path reachable from an
untrusted fragment, or a performance regression stops the series for diagnosis/review.

## Final review and resolved decisions (2026-08-20)

The final sweep rechecked the normative sections against the deployed
paths and removed two review proposals that were not sound: exact UDP
fragment-ID matching self-invalidates as a flow keeps sending, while an
accumulated ID window grows without a real time bound, admits IDs
interleaved from other IPv4 flows, and becomes ambiguous at wrap. The
final design associates UDP quotes by a recent exact successful-send
tuple and does not treat a fragment ID as authentication.

The Linux comparisons requested in v4 were made against current kernel
behavior. Linux's dynamic scale is not automatically appropriate for a
small VM-focused OS, so the resolutions below distinguish behavior worth
matching from deliberate fixed Motor bounds:

1. Keep four non-evicting reassembly slots shared by IPv4 and IPv6, a
   60-second lifetime, and the 320 KiB maximum fragment-payload footprint
   per interface. Linux instead uses dynamically many queues governed by
   separate IPv4/IPv6 per-namespace memory thresholds, with default
   30-second IPv4 and 60-second IPv6 timeouts. Motor's smaller shared
   fixed limit is the approved deterministic memory/DoS tradeoff.

2. Ignore a structurally valid range already wholly covered, preserving
   the first bytes; poison and tombstone a true partial overlap for both
   protocols. This adopts Linux IPv6's duplicate/overlap distinction.
   Motor's bounded tombstone, and applying the policy to IPv4 too, are
   intentional stricter choices.

3. Keep 64 KiB of fixed zeroed egress staging per interface. Ingress
   allocation remains lazy and bounded.

4. Raise moto-rt's public UDP maximum from 65,493 to 65,507 and enforce it
   at moto-io's common enqueue boundary.

5. Keep a 64-entry destination PMTU cache for ten minutes and keep other
   ICMP socket-error semantics out of scope. Ten minutes matches Linux's
   default PMTU expiry; 64 entries is Motor's intentionally smaller fixed
   ceiling, not a Linux-derived capacity.

6. Expire incomplete reassemblies silently and count them until Motor has
   a separately reviewed ICMP-error rate limiter. Linux can emit Time
   Exceeded when the first fragment arrived, but copying that without a
   limiter would create a reflector. Reject IPv6 configuration on a
   physical MTU below 1,280, consistent with Linux's device-admission
   outcome.

7. Allocate no state for an invalid fragment whose key has no admitted
   bytes. A poisoned existing assembly retains its original slot as a
   tombstone until the original deadline.

8. Accept an offset-zero first-fragment UDP quote only with a recent exact
   successfully dispatched four-tuple and a complete valid fragment
   header; do not match or retain fragment IDs. Reject fragmented TCP
   quotes. For an unfragmented TCP quote, require the exact socket and an
   unsacked outstanding sequence, then mark at most one old-MSS span lost
   without a congestion penalty. Linux uses socket/tuple association for
   UDP and live TCP sequence space without Motor's recent-send LRU and
   narrower loss bound; Motor deliberately remains stricter.

9. Keep the 32-range bound. Poison a datagram that needs a 33rd disjoint
   range and increment the wrapping per-interface counter exactly once.
   Drain it into the public sys-io metric
   `net.reassembly.range_limit_drops`
   (`NET_REASSEMBLY_RANGE_LIMIT_DROPS`). The implementation and metric
   tests cover this exact path.

10. Replace the single interface-wide IPv4 ID counter with the fixed
    256-bucket keyed counter table specified above, and generate each IPv6
    fragment ID freshly from the interface RNG. Linux uses the same broad
    split with a substantially larger dynamically sized IPv4 counter
    table. Motor's fixed table costs about 560 bytes including key and
    initialization bitmap, has no eviction or timer work, and isolates
    most unrelated tuples. A single high-rate IPv4 tuple can still wrap
    its 16-bit space; that protocol limit is explicit rather than hidden
    behind an ineffective PMTU or independent-random-ID claim.

The implementation-readiness sweep found no remaining protocol choice or
ownership ambiguity. All attacker-controlled storage has an explicit
count, byte, and lifetime bound; validation precedes allocation/copy;
egress commit and retry semantics are specified; PMTU association and
cache invalidation are specified; production/test feature closure is
pinned; observability has a drain path; and the test matrix covers each
security and boundary decision. The document is ready to start at step 1.
