#!/usr/bin/env python3
"""Static minimum-cost relay routing and per-hop packet tracing.

Public entry points:

    python relay_path.py route --input PATH
    python relay_path.py trace --input PATH
    python relay_path.py ecmp-trace --input PATH
    python relay_path.py weighted-ecmp-trace --input PATH
    python relay_path.py sticky-ecmp-trace --input PATH
    python relay_path.py latency-trace --input PATH
    python relay_path.py bandwidth-trace --input PATH
    python relay_path.py loss-trace --input PATH
    python relay_path.py queue-trace --input PATH
    python relay_path.py event-trace --input PATH
    python relay_path.py node-event-trace --input PATH
    python relay_path.py fragment-trace --input PATH
    python relay_path.py damped-event-trace --input PATH

Reads a UTF-8 JSON object describing relay nodes and directed links and
prints the minimum-cost route from source to destination (route), the
hop-by-hop forwarding trace of a packet along that route (trace), a
trace that hashes the packet onto an equal-cost minimum-cost next hop at
every node (ecmp-trace), or a trace that hashes the packet onto a
weighted equal-cost next hop using per-link weights
(weighted-ecmp-trace), or a trace that keeps every packet of one flow on
the highest-scoring equal-cost next hop (sticky-ecmp-trace), or a trace
that annotates every hop of the deterministic minimum-cost route with
departure, link-latency and arrival times (latency-trace), or a trace
that additionally accounts for per-link serialization delay from the
packet payload size and link bandwidth (bandwidth-trace), or a trace
that drops the packet on a link when a deterministic per-hop hash falls
below that link's configured loss rate (loss-trace), or a trace that
admits the packet to a per-link queue when the queued bytes plus the
packet bytes fit the link's capacity and tail-drops it otherwise
(queue-trace), or a trace that replays link failure and recovery events
against an explicit event clock and forwards the packet over the
effective topology at the query time (event-trace), or a trace that
replays node failure and recovery events against an explicit event
clock and forwards the packet over the effective topology at the
query time (node-event-trace), or a trace that slices the reassembled
payload into MTU-sized fragments before every successful link
departure and reassembles at the next node (fragment-trace), or a
trace that lets every link event take effect only after a hold-down
wait, suppressing events that are overtaken by a later event for the
same link before their wait completes (damped-event-trace), as one
compact JSON object on stdout.
"""

import argparse
import hashlib
import heapq
import json
import re
import sys

MAX_NODES = 10000
MAX_LINKS = 50000
MAX_PACKET_ID_CODEPOINTS = 128
MAX_PACKET_TTL = 255
MAX_PACKET_PRIORITY = 7
MAX_PAYLOAD_BYTES = 65536
MIN_MTU_BYTES = 1
MAX_MTU_BYTES = 65536
MIN_LINK_WEIGHT = 1
MAX_LINK_WEIGHT = 65535
MAX_CLOCK_THOUSANDTHS = 999999999999999
MAX_LINK_LATENCY_THOUSANDTHS = 86400000000
NODE_TYPES = ("relay", "terminal", "pseudo")
ROOT_FIELDS = ("nodes", "links", "source", "destination")
TRACE_ROOT_FIELDS = ROOT_FIELDS + ("packet",)
WEIGHTED_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("weights",)
LATENCY_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("clock_ms", "latencies")
BANDWIDTH_TRACE_ROOT_FIELDS = LATENCY_TRACE_ROOT_FIELDS + ("bandwidths",)
LOSS_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("loss_rates",)
QUEUE_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + (
    "queue_capacities",
    "queue_occupancies",
)
EVENT_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("clock_ms", "events")
NODE_EVENT_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("clock_ms", "events")
FRAGMENT_TRACE_ROOT_FIELDS = TRACE_ROOT_FIELDS + ("mtus",)
DAMPED_EVENT_TRACE_ROOT_FIELDS = EVENT_TRACE_ROOT_FIELDS + ("hold_down_ms",)
PACKET_FIELDS = ("id", "ttl", "priority", "payload")
STICKY_PACKET_FIELDS = PACKET_FIELDS + ("flow_id",)
TIME_PATTERN = re.compile(r"[0-9]+(\.[0-9]{1,3})?\Z")
LOSS_RATE_PATTERN = re.compile(r"(0\.[0-9]{6}|1\.0{6})\Z")
MAX_LOSS_UNITS = 1000000
MIN_LINK_BANDWIDTH = 1
MAX_LINK_BANDWIDTH = 1000000000000
SERIALIZATION_SCALE_THOUSANDTHS = 1000000
MAX_QUEUE_BYTES = 1000000000000
MAX_EVENTS = 100000
EVENT_FIELDS = ("at_ms", "link", "up")
NODE_EVENT_FIELDS = ("at_ms", "node", "up")

FORMAT_HELP = """\
input format (UTF-8 JSON object with exactly these four fields):
  nodes       array of {"id": <non-empty string>,
                        "type": "relay" | "terminal" | "pseudo"}
              node ids must be unique
  links       array of {"id": <string>, "from": <node id>, "to": <node id>,
                        "cost": <positive integer>, "up": <boolean>}
              link ids must be unique; links are directed and both
              endpoints must be declared in nodes
  source      declared node id where the path starts
  destination declared node id where the path ends

limits:
  at most 10000 nodes and 50000 links.

routing rules:
  only links with up == true participate. The route minimizes the sum of
  link costs; ties are broken by the lexicographic order (Unicode code
  points) of the complete node id sequence, and then by the link id
  sequence. Input array order never affects the result. A source equal to
  its destination yields that single node and zero cost.

output (single compact JSON line on stdout, keys in this order):
  status, source, destination, path, links, total_cost
  status is "found" (path/links in traversal order, integer total_cost) or
  "unreachable" (empty arrays, total_cost null).

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3) for unreadable/invalid input or bad schema;
  ParameterError (exit code 2) when source or destination is not declared.
"""

TRACE_HELP = """\
input format (UTF-8 JSON object with exactly these five fields):
  nodes, links, source, destination
              exactly as in the route command; all route constraints
              on the topology apply unchanged
  packet      object with exactly these four fields:
                id        non-empty string of at most 128 Unicode
                          code points
                ttl       integer in 0..255
                priority  integer in 0..7
                payload   string of at most 65536 bytes when UTF-8
                          encoded
              booleans are not accepted where integers are required

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  route command (up links only, ties broken as in route). ttl must be
  greater than zero before the packet leaves a node and decreases by
  one per traversed link; arriving at the destination with ttl reduced
  to zero still counts as delivered. A packet whose ttl is zero before
  forwarding is dropped at the current node with reason ttl_exhausted.
  If no route exists, the packet is dropped at the source without
  traversing any link, with reason no_route. A source equal to its
  destination is delivered immediately without consuming ttl. At most
  (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision in this
  order, and decision is always "forward".

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3) and ParameterError (exit code 2) as in
  route; PacketError (exit code 4) for an invalid packet, with stdout
  left empty. All validation completes before any tracing begins.
"""

ECMP_HELP = """\
input format (UTF-8 JSON object with exactly five fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged

forwarding rules:
  at each node the candidate next hops are the outgoing links with up
  == true that can enter a minimum-total-cost path from the current
  node to the destination; alternatives of a different total cost never
  participate. Parallel links each occupy a candidate slot. Candidates
  are ordered by (next node id, link id) in Unicode code point order.
  Per hop, SHA-256 is computed over the UTF-8 bytes of packet.id, then
  one zero byte, then the UTF-8 bytes of the current node id; the
  digest interpreted as a big-endian unsigned integer is taken modulo
  the candidate count to select the zero-based index. priority, payload
  and input array order never affect the choice. ttl must be greater
  than zero before the packet leaves a node and decreases by one per
  traversed link; arriving at the destination with ttl reduced to zero
  still counts as delivered. A packet whose ttl is zero before
  forwarding is dropped at the current node with reason ttl_exhausted.
  If no route exists, the packet is dropped at the source without
  traversing any link, with reason no_route. A source equal to its
  destination is delivered immediately without consuming ttl. At most
  (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  candidate_count, selected_index in this order; decision is always
  "ecmp_hash", and candidate_count and selected_index record the number
  of candidates and the hash-selected zero-based index at that hop.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

WEIGHTED_HELP = """\
input format (UTF-8 JSON object with exactly six fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  weights     object whose keys are declared link ids and whose values
              are integers in 1..65535 (booleans are not accepted as
              integers); links not listed default to weight 1. Unknown
              link keys and out-of-range weights are ConfigErrors.

forwarding rules:
  the candidate set is exactly as in ecmp-trace: only up links that can
  enter a minimum-total-cost path from the current node to the
  destination, ordered by (next node id, link id) in Unicode code point
  order. Weights never admit a non-equal-cost alternative. Per hop, the
  same SHA-256 digest as in ecmp-trace (packet.id UTF-8 bytes, one zero
  byte, current node id UTF-8 bytes) is interpreted as a big-endian
  unsigned integer and taken modulo the sum of the candidate weights;
  the unique candidate is located by zero-based cumulative weight
  intervals, never by expanding an array by weight. An empty weights
  object selects exactly as ecmp-trace does. ttl, delivery, no_route,
  ttl_exhausted and the (node count - 1) hop bound are unchanged.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  candidate_count, selected_index, selected_weight, total_weight,
  selected_value in this order; decision is always "weighted_ecmp_hash",
  and the last three numbers record the selected link's weight, the sum
  of candidate weights, and the modulo result so the choice can be
  rechecked.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

STICKY_HELP = """\
input format (UTF-8 JSON object with exactly five fields):
  nodes, links, source, destination
              exactly as in the trace command; every topology
              constraint applies unchanged
  packet      object with exactly these five fields:
                id        non-empty string of at most 128 Unicode
                          code points
                ttl       integer in 0..255
                priority  integer in 0..7
                payload   string of at most 65536 bytes when UTF-8
                          encoded
                flow_id   non-empty string of at most 128 Unicode
                          code points
              booleans are not accepted where integers are required

forwarding rules:
  the candidate set and its ordering are exactly as in ecmp-trace:
  only up links that can enter a minimum-total-cost path from the
  current node to the destination, ordered by (next node id, link id)
  in Unicode code point order. Per hop, each candidate is scored by
  SHA-256 over the UTF-8 bytes of flow_id, one zero byte, the current
  node id, one zero byte, the candidate's next node id, one zero byte,
  and the link id; digests are compared as big-endian unsigned integers
  and the highest score wins, with ties resolved toward the candidate
  that sorts earlier. The choice depends only on flow_id and the
  candidate set: packet.id, priority, payload and input array order
  never affect it, so all packets of one flow follow the same path
  while the candidate sets are unchanged. ttl must be greater than zero
  before the packet leaves a node and decreases by one per traversed
  link; arriving at the destination with ttl reduced to zero still
  counts as delivered. A packet whose ttl is zero before forwarding is
  dropped at the current node with reason ttl_exhausted. If no route
  exists, the packet is dropped at the source without traversing any
  link, with reason no_route. A source equal to its destination is
  delivered immediately without consuming ttl. At most (node count - 1)
  hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  candidate_count, selected_index, selected_score in this order;
  decision is always "sticky_ecmp_hash", and selected_score is the
  winning candidate's digest as 64 lowercase hexadecimal characters.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

LATENCY_HELP = """\
input format (UTF-8 JSON object with exactly these seven fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  clock_ms    decimal millisecond string in
              0..999999999999.999 with at most three fractional
              digits; no exponent, sign, whitespace or non-finite
              value is accepted
  latencies   object whose keys are declared link ids and whose
              values are decimal millisecond strings in
              0..86400000.000 under the same format rules; links
              not listed default to 0.000. Unknown link keys and
              malformed or out-of-range times are ConfigErrors.

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  trace command; path, ttl and drop attribution never depend on the
  latencies. Time is accumulated in thousandths of a millisecond and
  never reads the wall clock. The first hop departs at clock_ms, every
  later hop departs when the previous hop arrived, and a hop arrives
  its latency after departing. Immediate delivery, no_route and
  ttl_exhausted before the first hop finish at the start time;
  ttl_exhausted later finishes at the last hop's arrival. At most
  (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason, started_at_ms, finished_at_ms
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  departed_at_ms, latency_ms, arrived_at_ms in this order, and
  decision is always "forward". All times are decimal millisecond
  strings with exactly three fractional digits.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

BANDWIDTH_HELP = """\
input format (UTF-8 JSON object with exactly these eight fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  clock_ms, latencies
              exactly as in the latency-trace command; every clock and
              link latency constraint applies unchanged
  bandwidths  object whose keys are every declared link id and whose
              values are JSON integers in 1..1000000000000 bits per
              second (booleans are not accepted as integers). Every
              declared link must appear exactly once: a missing link,
              an unknown link key or an out-of-range bandwidth is a
              ConfigError.

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  trace command; neither bandwidth nor latency ever influences the
  path, ttl or drop attribution. Time is accumulated in thousandths of
  a millisecond using integer arithmetic and never reads the wall
  clock. The first hop departs at clock_ms, every later hop departs
  when the previous hop arrived, and a hop arrives its serialization
  time plus its link latency after departing. Serialization time is
  computed from packet.payload's UTF-8 byte count only, with no
  protocol headers, as ceil(bytes * 8 * 1000000 / bandwidth_bps)
  thousandths of a millisecond; an empty payload serializes in zero
  time. Immediate delivery, no_route and ttl_exhausted before the first
  hop finish at the start time; ttl_exhausted later finishes at the
  last hop's arrival. At most (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason, started_at_ms, finished_at_ms
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  departed_at_ms, bandwidth_bps, serialization_ms, latency_ms,
  arrived_at_ms in this order, and decision is always "forward". All
  times are decimal millisecond strings with exactly three fractional
  digits, and bandwidth_bps is the link's integer bandwidth.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

LOSS_HELP = """\
input format (UTF-8 JSON object with exactly these six fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  loss_rates  object whose keys are declared link ids and whose
              values are decimal strings in 0.000000..1.000000 with
              exactly six fractional digits; links not listed default
              to 0.000000. Unknown link keys, non-string values,
              malformed strings and out-of-range rates are
              ConfigErrors.

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  trace command; loss rates never influence the path. Before every
  link attempt, SHA-256 is computed over the UTF-8 bytes of packet.id,
  one zero byte, the UTF-8 bytes of the link id, one zero byte, and
  the decimal ASCII bytes of the zero-based hop index; the first eight
  digest bytes are read as a big-endian unsigned integer loss_value.
  The loss rate is converted to an integer count of millionths
  loss_units; the attempt is lost exactly when
  loss_value * 1000000 < loss_units * 2**64, so a rate of zero never
  loses and a rate of one always loses. No randomness or wall clock is
  used. A ttl of zero before forwarding still drops the packet at the
  current node with reason ttl_exhausted and no digest is computed;
  every actual attempt consumes one ttl. A lost attempt is recorded in
  hops, but its target node is not added to path, final_node stays at
  the sending node, and the trace stops with status dropped and reason
  link_loss. Arriving at the destination with ttl reduced to zero
  still counts as delivered; no_route, source equal to destination and
  the (node count - 1) hop bound are as in trace.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision, loss_rate,
  loss_value in this order; decision is "forward" for a successful
  attempt and "drop_loss" for a lost one, loss_rate is the link's rate
  with exactly six fractional digits, and loss_value is the digest
  prefix as 16 lowercase hexadecimal characters.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

QUEUE_HELP = """\
input format (UTF-8 JSON object with exactly these seven fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  queue_capacities
              object whose keys are every declared link id and whose
              values are JSON integers in 0..1000000000000 bytes
              (booleans are not accepted as integers). Every declared
              link must appear exactly once: a missing link, an
              unknown link key or an out-of-range value is a
              ConfigError.
  queue_occupancies
              object under the same rules as queue_capacities, giving
              the bytes already queued on each link before any attempt;
              an occupancy above the same link's capacity is a
              ConfigError.

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  trace command; queue capacities and occupancies never influence the
  path. Each link's occupancy is an independent snapshot taken before
  the attempt; no wall clock is read and no state is kept between
  links. no_route and ttl_exhausted are decided exactly as in trace
  before any link is attempted. When a link is attempted, packet_bytes
  is the UTF-8 byte count of packet.payload (an empty payload is zero
  bytes). If queued bytes plus packet_bytes does not exceed the
  capacity, the packet is admitted, the sum becomes the new occupancy,
  the packet reaches the next node and one ttl is consumed; filling
  the queue exactly still succeeds. Otherwise the packet is tail
  dropped immediately: it does not reach the next node, consumes no
  ttl and the occupancy is unchanged. A source equal to its
  destination is delivered immediately without any queue check; with
  no route the packet is still dropped at the source. At most (node
  count - 1) successful hops plus one rejected attempt are recorded.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  capacity_bytes, queued_bytes_before, packet_bytes,
  queued_bytes_after in this order; decision is "enqueue" for an
  admitted attempt and "drop_tail" for a rejected one. A rejected
  attempt is recorded in hops, but its target node is not added to
  path, final_node stays at the sending node, ttl_after equals
  ttl_before, and the trace stops with reason queue_tail_drop.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; stdout is left empty. All
  validation completes before any tracing begins.
"""

EVENT_HELP = """\
input format (UTF-8 JSON object with exactly these seven fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  clock_ms    decimal millisecond string in
              0..999999999999.999 with at most three fractional
              digits, exactly as in the latency-trace command
  events      array of at most 100000 objects, each with exactly the
              fields:
                at_ms   decimal millisecond string under the same
                        format and range rules as clock_ms
                link    id of a declared link
                up      JSON boolean
              events are ordered by non-decreasing at_ms; events at
              the same time apply in array order, and repeated sets of
              one link (including later recovery) are allowed.

forwarding rules:
  every link starts in its declared up state. Events with at_ms less
  than or equal to clock_ms are applied in array order; later events
  never take effect. The packet then follows the same deterministic
  minimum-cost route as the trace command over the effective topology:
  links that are down at clock_ms never participate in routing, ties
  break as in route, ttl must be greater than zero before the packet
  leaves a node and decreases by one per traversed link, arriving at
  the destination with ttl reduced to zero still counts as delivered,
  a packet whose ttl is zero before forwarding is dropped at the
  current node with reason ttl_exhausted, and with no route the packet
  is dropped at the source with reason no_route. A source equal to its
  destination is delivered immediately. Applying events consumes no
  ttl and never reads the wall clock. At most (node count - 1) hops
  are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, clock_ms, applied_events,
  path, hops, final_node, ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). clock_ms is the query time with exactly three
  fractional digits. applied_events lists only the events actually
  applied, in input order, each with keys at_ms, link, up in this
  order and at_ms rendered with exactly three fractional digits. path
  lists the nodes actually reached; each hop has keys from, to, link,
  ttl_before, ttl_after, decision in this order, and decision is
  always "event_route".

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; a malformed clock_ms or any
  malformed, misordered, misreferencing or over-limit event is a
  ConfigError; stdout is left empty. All validation completes before
  any event is applied or any tracing begins.
"""

NODE_EVENT_HELP = """\
input format (UTF-8 JSON object with exactly these seven fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  clock_ms    decimal millisecond string in
              0..999999999999.999 with at most three fractional
              digits, exactly as in the latency-trace command
  events      array of at most 100000 objects, each with exactly the
              fields:
                at_ms   decimal millisecond string under the same
                        format and range rules as clock_ms
                node    id of a declared node
                up      JSON boolean
              events are ordered by non-decreasing at_ms; events at
              the same time apply in array order, and repeated sets of
              one node (including later recovery) are allowed.

forwarding rules:
  every node starts available. Events with at_ms less than or equal
  to clock_ms are applied in array order; later events never take
  effect. A link participates in routing exactly when its declared up
  state is true and both of its endpoint nodes are available at
  clock_ms: every link into or out of an unavailable node is excluded,
  and a node recovering restores its links to their declared up
  state. If the source or the destination is unavailable at clock_ms,
  the packet is dropped at the source with reason node_down, path
  holds only the source, hops is empty, final_node is the source and
  no ttl is consumed; this applies even when source equals
  destination. Otherwise the packet follows the same deterministic
  minimum-cost route as the trace command over the effective
  topology: ties break as in route, ttl must be greater than zero
  before the packet leaves a node and decreases by one per traversed
  link, arriving at the destination with ttl reduced to zero still
  counts as delivered, a packet whose ttl is zero before forwarding
  is dropped at the current node with reason ttl_exhausted, and with
  no route the packet is dropped at the source with reason no_route.
  A source equal to its destination is delivered immediately.
  Applying events consumes no ttl and never reads the wall clock. At
  most (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, clock_ms, applied_events,
  path, hops, final_node, ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). clock_ms is the query time with exactly three
  fractional digits. applied_events lists only the events actually
  applied, in input order, each with keys at_ms, node, up in this
  order and at_ms rendered with exactly three fractional digits. path
  lists the nodes actually reached; each hop has keys from, to, link,
  ttl_before, ttl_after, decision in this order, and decision is
  always "node_event_route".

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; a malformed clock_ms or any
  malformed, misordered, misreferencing or over-limit event is a
  ConfigError; stdout is left empty. All validation completes before
  any event is applied or any tracing begins.
"""

FRAGMENT_HELP = """\
input format (UTF-8 JSON object with exactly these six fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  mtus        object whose keys are every declared link id and whose
              values are JSON integers in 1..65536 bytes (booleans are
              not accepted as integers). Every declared link must
              appear exactly once: a missing link, an unknown link key
              or an out-of-range MTU is a ConfigError.

forwarding rules:
  the packet follows the same deterministic minimum-cost route as the
  trace command; MTUs never influence routing, ttl or drop
  attribution. Before every successful departure from a node, the
  UTF-8 byte sequence of packet.payload is treated as the reassembled
  complete payload and sliced front to back according to the selected
  link's MTU: every fragment but the last is exactly MTU bytes, the
  last fragment carries the remainder and is also MTU bytes when the
  length divides exactly, and an empty payload is fixed to a single
  zero-length fragment. Slicing may fall inside a multibyte character;
  fragment contents are neither emitted nor decoded. Fragmentation
  consumes no extra ttl and never changes the path; the payload is
  reassembled at the next node and later links fragment by their own
  MTUs. ttl_exhausted, no_route, a source equal to its destination and
  arrival with ttl reduced exactly to zero are handled as in trace,
  and no fragment record is produced for a link that is never
  attempted. At most (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision, mtu_bytes,
  payload_bytes, fragment_count, last_fragment_bytes in this order;
  decision is always "fragment_forward", and the first
  fragment_count - 1 fragments are each mtu_bytes long while the last
  fragment is last_fragment_bytes long.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; invalid mtus are a
  ConfigError; stdout is left empty. All validation completes before
  any tracing begins.
"""

DAMPED_EVENT_HELP = """\
input format (UTF-8 JSON object with exactly these eight fields):
  nodes, links, source, destination, packet
              exactly as in the trace command; every topology and
              packet constraint applies unchanged
  clock_ms    decimal millisecond string in
              0..999999999999.999 with at most three fractional
              digits, exactly as in the latency-trace command
  events      array of at most 100000 objects, exactly as in the
              event-trace command: each has the fields at_ms, link
              and up, ordered by non-decreasing at_ms
  hold_down_ms
              decimal millisecond string in 0..86400000.000 with at
              most three fractional digits: the stability wait every
              link event must complete before it takes effect

forwarding rules:
  every link starts in its declared up state. Only events with at_ms
  less than or equal to clock_ms are observed; later events never
  take effect and never influence earlier events. An observed event
  takes effect at at_ms + hold_down_ms; a later observed event for
  the same link that arrives strictly before that moment suppresses
  it and restarts the wait, even when the up value is equal, while an
  event arriving exactly at that moment does not. Events at the same
  time are processed in input order, and a zero hold_down_ms lets
  every observed event take effect immediately in input order.
  Surviving events whose effective time is not later than clock_ms
  apply in input order over the declared link states; the packet then
  follows the same deterministic minimum-cost route as the trace
  command over the effective topology, with the same ttl, immediate
  delivery, no_route and ttl_exhausted semantics as event-trace.
  Applying events consumes no ttl and never reads the wall clock. At
  most (node count - 1) hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, clock_ms, hold_down_ms,
  effective_events, path, hops, final_node, ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). clock_ms and hold_down_ms carry exactly three
  fractional digits. effective_events lists only the events that
  actually took effect, in the order they took effect, each with keys
  at_ms, effective_at_ms, link, up in this order and both times
  rendered with exactly three fractional digits; an event whose
  effective value equals the current state is still recorded. path
  lists the nodes actually reached; each hop has keys from, to, link,
  ttl_before, ttl_after, decision in this order, and decision is
  always "damped_event_route".

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3), ParameterError (exit code 2) and
  PacketError (exit code 4) as in trace; a malformed clock_ms or
  hold_down_ms or any malformed, misordered, misreferencing or
  over-limit event is a ConfigError; stdout is left empty. All
  validation completes before any event is applied or any tracing
  begins.
"""


class ConfigError(Exception):
    """The input document is missing, malformed, or violates the schema."""

    error = "ConfigError"
    exit_code = 3


class ParameterError(Exception):
    """The query references an undeclared endpoint."""

    error = "ParameterError"
    exit_code = 2


class PacketError(Exception):
    """The packet object is missing, malformed, or out of range."""

    error = "PacketError"
    exit_code = 4


def load_document(path):
    """Read and decode the input document; all failures are ConfigError."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise ConfigError("input file is not readable")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("input is not valid UTF-8")
    def reject_duplicate_keys(pairs):
        seen = set()
        for key, _value in pairs:
            if key in seen:
                raise ValueError("duplicate JSON object key: %r" % key)
            seen.add(key)
        return dict(pairs)

    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError):
        raise ConfigError("input is not valid JSON")


def validate(document, root_fields=ROOT_FIELDS):
    """Validate the whole document before any routing begins.

    Problems are reported for top-level fields in the order nodes, links,
    source, destination, and within arrays by element position. Returns
    (node_ids, links as (id, u, v, cost, up), source index, dest index).
    """
    if not isinstance(document, dict):
        raise ConfigError("root value must be a JSON object")

    for name in root_fields:
        if name not in document:
            raise ConfigError("missing field: %s" % name)
    for name in sorted(k for k in document if k not in root_fields):
        raise ConfigError("unexpected field: %s" % name)

    raw_nodes = document["nodes"]
    if not isinstance(raw_nodes, list):
        raise ConfigError("nodes must be an array")

    node_ids = []
    node_index = {}
    for pos, element in enumerate(raw_nodes):
        where = "nodes[%d]" % pos
        if not isinstance(element, dict):
            raise ConfigError("%s must be an object" % where)
        if set(element) != {"id", "type"}:
            raise ConfigError(
                "%s must contain exactly the fields id and type" % where
            )
        node_id = element["id"]
        if not isinstance(node_id, str) or not node_id:
            raise ConfigError("%s.id must be a non-empty string" % where)
        node_type = element["type"]
        if node_type not in NODE_TYPES:
            raise ConfigError(
                "%s.type must be one of %s"
                % (where, ", ".join(NODE_TYPES))
            )
        if node_id in node_index:
            raise ConfigError("duplicate node id: %s" % node_id)
        node_index[node_id] = len(node_ids)
        node_ids.append(node_id)
    if len(raw_nodes) > MAX_NODES:
        raise ConfigError("too many nodes: limit is %d" % MAX_NODES)

    raw_links = document["links"]
    if not isinstance(raw_links, list):
        raise ConfigError("links must be an array")

    links = []
    seen_link_ids = set()
    for pos, element in enumerate(raw_links):
        where = "links[%d]" % pos
        if not isinstance(element, dict):
            raise ConfigError("%s must be an object" % where)
        if set(element) != {"id", "from", "to", "cost", "up"}:
            raise ConfigError(
                "%s must contain exactly the fields id, from, to, cost, up"
                % where
            )
        link_id = element["id"]
        if not isinstance(link_id, str) or not link_id:
            raise ConfigError("%s.id must be a non-empty string" % where)
        endpoint_from = element["from"]
        endpoint_to = element["to"]
        if not isinstance(endpoint_from, str):
            raise ConfigError("%s.from must be a string" % where)
        if not isinstance(endpoint_to, str):
            raise ConfigError("%s.to must be a string" % where)
        cost = element["cost"]
        if type(cost) is not int or cost <= 0:
            raise ConfigError("%s.cost must be a positive integer" % where)
        up = element["up"]
        if type(up) is not bool:
            raise ConfigError("%s.up must be a boolean" % where)
        if link_id in seen_link_ids:
            raise ConfigError("duplicate link id: %s" % link_id)
        seen_link_ids.add(link_id)
        if endpoint_from not in node_index:
            raise ConfigError(
                "%s.from does not refer to a declared node" % where
            )
        if endpoint_to not in node_index:
            raise ConfigError(
                "%s.to does not refer to a declared node" % where
            )
        links.append(
            (
                link_id,
                node_index[endpoint_from],
                node_index[endpoint_to],
                cost,
                up,
            )
        )
    if len(raw_links) > MAX_LINKS:
        raise ConfigError("too many links: limit is %d" % MAX_LINKS)

    source = document["source"]
    if not isinstance(source, str):
        raise ConfigError("source must be a string")
    if source not in node_index:
        raise ParameterError("source is not declared")

    destination = document["destination"]
    if not isinstance(destination, str):
        raise ConfigError("destination must be a string")
    if destination not in node_index:
        raise ParameterError("destination is not declared")

    return node_ids, links, node_index[source], node_index[destination]


def validate_packet(document):
    """Validate the packet field; every problem is a PacketError.

    Returns (packet_id, ttl, priority, payload).
    """
    packet = check_packet_object(document, PACKET_FIELDS)
    return validate_packet_values(packet)


def check_packet_object(document, packet_fields):
    """Check that packet is an object with exactly the given fields."""
    packet = document["packet"]
    if not isinstance(packet, dict):
        raise PacketError("packet must be an object")
    for name in packet_fields:
        if name not in packet:
            raise PacketError("packet missing field: %s" % name)
    for name in sorted(k for k in packet if k not in packet_fields):
        raise PacketError("packet has unexpected field: %s" % name)
    return packet


def validate_packet_values(packet):
    """Validate the id, ttl, priority and payload values of a packet.

    Returns (packet_id, ttl, priority, payload).
    """
    packet_id = packet["id"]
    if not isinstance(packet_id, str) or not packet_id:
        raise PacketError("packet.id must be a non-empty string")
    if len(packet_id) > MAX_PACKET_ID_CODEPOINTS:
        raise PacketError(
            "packet.id exceeds %d code points" % MAX_PACKET_ID_CODEPOINTS
        )

    ttl = packet["ttl"]
    if type(ttl) is not int or not 0 <= ttl <= MAX_PACKET_TTL:
        raise PacketError(
            "packet.ttl must be an integer in 0..%d" % MAX_PACKET_TTL
        )

    priority = packet["priority"]
    if type(priority) is not int or not 0 <= priority <= MAX_PACKET_PRIORITY:
        raise PacketError(
            "packet.priority must be an integer in 0..%d"
            % MAX_PACKET_PRIORITY
        )

    payload = packet["payload"]
    if not isinstance(payload, str):
        raise PacketError("packet.payload must be a string")
    if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise PacketError(
            "packet.payload exceeds %d UTF-8 bytes" % MAX_PAYLOAD_BYTES
        )

    return packet_id, ttl, priority, payload


def validate_sticky_packet(document):
    """Validate the packet field including flow_id; every problem is a
    PacketError.

    Returns (packet_id, ttl, priority, payload, flow_id).
    """
    packet = check_packet_object(document, STICKY_PACKET_FIELDS)
    packet_id, ttl, priority, payload = validate_packet_values(packet)

    flow_id = packet["flow_id"]
    if not isinstance(flow_id, str) or not flow_id:
        raise PacketError("packet.flow_id must be a non-empty string")
    if len(flow_id) > MAX_PACKET_ID_CODEPOINTS:
        raise PacketError(
            "packet.flow_id exceeds %d code points" % MAX_PACKET_ID_CODEPOINTS
        )

    return packet_id, ttl, priority, payload, flow_id


def validate_weights(document, link_ids):
    """Validate the weights field; every problem is a ConfigError.

    Keys must refer to declared link ids and values must be integers in
    1..65535 (booleans are not integers). Keys are checked in Unicode
    code point order so the first reported problem is deterministic.
    Links absent from the object default to weight 1. Returns a mapping
    of link id to weight containing only explicitly listed links.
    """
    weights = document["weights"]
    if not isinstance(weights, dict):
        raise ConfigError("weights must be an object")

    declared = set(link_ids)
    resolved = {}
    for link_id in sorted(weights):
        if not isinstance(link_id, str):
            raise ConfigError("weights keys must be strings")
        if link_id not in declared:
            raise ConfigError("weights refers to an undeclared link: %s" % link_id)
        value = weights[link_id]
        if type(value) is not int or not MIN_LINK_WEIGHT <= value <= MAX_LINK_WEIGHT:
            raise ConfigError(
                "weights[%s] must be an integer in %d..%d"
                % (link_id, MIN_LINK_WEIGHT, MAX_LINK_WEIGHT)
            )
        resolved[link_id] = value
    return resolved


def parse_time_value(value, max_thousandths, where):
    """Parse a decimal millisecond string into thousandths of a millisecond.

    Only digits with an optional fractional part of one to three digits
    are accepted: no exponent, sign, whitespace or non-finite value.
    Every problem is a ConfigError. Returns a non-negative integer count
    of thousandths of a millisecond, at most max_thousandths.
    """
    if not isinstance(value, str):
        raise ConfigError("%s must be a decimal millisecond string" % where)
    if TIME_PATTERN.match(value) is None:
        raise ConfigError(
            "%s must be a decimal string with at most three fractional"
            " digits" % where
        )
    integer, dot, fraction = value.partition(".")
    thousandths = int(integer) * 1000
    if dot:
        thousandths += int((fraction + "000")[:3])
    if thousandths > max_thousandths:
        raise ConfigError("%s is out of range" % where)
    return thousandths


def format_ms(thousandths):
    """Render thousandths of a millisecond with exactly three decimals."""
    return "%d.%03d" % (thousandths // 1000, thousandths % 1000)


def validate_latencies(document, link_ids):
    """Validate the latencies field; every problem is a ConfigError.

    Keys must refer to declared link ids and values must be decimal
    millisecond strings in 0..86400000.000. Keys are checked in Unicode
    code point order so the first reported problem is deterministic.
    Links absent from the object default to 0.000. Returns a mapping of
    link id to latency in thousandths of a millisecond containing only
    explicitly listed links.
    """
    latencies = document["latencies"]
    if not isinstance(latencies, dict):
        raise ConfigError("latencies must be an object")

    declared = set(link_ids)
    resolved = {}
    for link_id in sorted(latencies):
        if not isinstance(link_id, str):
            raise ConfigError("latencies keys must be strings")
        if link_id not in declared:
            raise ConfigError(
                "latencies refers to an undeclared link: %s" % link_id
            )
        resolved[link_id] = parse_time_value(
            latencies[link_id],
            MAX_LINK_LATENCY_THOUSANDTHS,
            "latencies[%s]" % link_id,
        )
    return resolved


def validate_bandwidths(document, link_ids):
    """Validate the bandwidths field; every problem is a ConfigError.

    The object must list every declared link id exactly once with a
    JSON integer value in 1..1000000000000 bits per second (booleans
    are not integers). Keys are checked in Unicode code point order so
    the first reported problem is deterministic. Returns a mapping of
    link id to bandwidth containing one entry per declared link.
    """
    bandwidths = document["bandwidths"]
    if not isinstance(bandwidths, dict):
        raise ConfigError("bandwidths must be an object")

    declared = set(link_ids)
    listed = set()
    resolved = {}
    for link_id in sorted(bandwidths):
        if not isinstance(link_id, str):
            raise ConfigError("bandwidths keys must be strings")
        if link_id not in declared:
            raise ConfigError(
                "bandwidths refers to an undeclared link: %s" % link_id
            )
        listed.add(link_id)
        value = bandwidths[link_id]
        if (
            type(value) is not int
            or not MIN_LINK_BANDWIDTH <= value <= MAX_LINK_BANDWIDTH
        ):
            raise ConfigError(
                "bandwidths[%s] must be an integer in %d..%d"
                % (link_id, MIN_LINK_BANDWIDTH, MAX_LINK_BANDWIDTH)
            )
        resolved[link_id] = value
    missing = declared - listed
    if missing:
        raise ConfigError(
            "bandwidths is missing declared link: %s" % sorted(missing)[0]
        )
    return resolved


def validate_mtus(document, link_ids):
    """Validate the mtus field; every problem is a ConfigError.

    The object must list every declared link id exactly once with a
    JSON integer value in 1..65536 bytes (booleans are not integers).
    Keys are checked in Unicode code point order so the first reported
    problem is deterministic. Returns a mapping of link id to MTU
    containing one entry per declared link.
    """
    mtus = document["mtus"]
    if not isinstance(mtus, dict):
        raise ConfigError("mtus must be an object")

    declared = set(link_ids)
    listed = set()
    resolved = {}
    for link_id in sorted(mtus):
        if not isinstance(link_id, str):
            raise ConfigError("mtus keys must be strings")
        if link_id not in declared:
            raise ConfigError(
                "mtus refers to an undeclared link: %s" % link_id
            )
        listed.add(link_id)
        value = mtus[link_id]
        if type(value) is not int or not MIN_MTU_BYTES <= value <= MAX_MTU_BYTES:
            raise ConfigError(
                "mtus[%s] must be an integer in %d..%d"
                % (link_id, MIN_MTU_BYTES, MAX_MTU_BYTES)
            )
        resolved[link_id] = value
    missing = declared - listed
    if missing:
        raise ConfigError(
            "mtus is missing declared link: %s" % sorted(missing)[0]
        )
    return resolved


def validate_loss_rates(document, link_ids):
    """Validate the loss_rates field; every problem is a ConfigError.

    Keys must refer to declared link ids and values must be decimal
    strings in 0.000000..1.000000 with exactly six fractional digits.
    Keys are checked in Unicode code point order so the first reported
    problem is deterministic. Links absent from the object default to
    0.000000. Returns a mapping of link id to loss rate as an integer
    count of millionths containing only explicitly listed links.
    """
    loss_rates = document["loss_rates"]
    if not isinstance(loss_rates, dict):
        raise ConfigError("loss_rates must be an object")

    declared = set(link_ids)
    resolved = {}
    for link_id in sorted(loss_rates):
        if not isinstance(link_id, str):
            raise ConfigError("loss_rates keys must be strings")
        if link_id not in declared:
            raise ConfigError(
                "loss_rates refers to an undeclared link: %s" % link_id
            )
        value = loss_rates[link_id]
        where = "loss_rates[%s]" % link_id
        if not isinstance(value, str):
            raise ConfigError("%s must be a decimal loss rate string" % where)
        if LOSS_RATE_PATTERN.match(value) is None:
            raise ConfigError(
                "%s must be in 0.000000..1.000000 with exactly six"
                " fractional digits" % where
            )
        integer, _dot, fraction = value.partition(".")
        resolved[link_id] = int(integer) * MAX_LOSS_UNITS + int(fraction)
    return resolved


def format_loss_rate(loss_units):
    """Render a millionths loss rate with exactly six decimals."""
    return "%d.%06d" % (loss_units // MAX_LOSS_UNITS, loss_units % MAX_LOSS_UNITS)


def validate_queue_bytes(document, field, link_ids):
    """Validate one queue byte-count field; every problem is a ConfigError.

    The object must list every declared link id exactly once with a
    JSON integer value in 0..1000000000000 (booleans are not integers).
    Keys are checked in Unicode code point order so the first reported
    problem is deterministic. Returns a mapping of link id to byte
    count containing one entry per declared link.
    """
    values = document[field]
    if not isinstance(values, dict):
        raise ConfigError("%s must be an object" % field)

    declared = set(link_ids)
    listed = set()
    resolved = {}
    for link_id in sorted(values):
        if not isinstance(link_id, str):
            raise ConfigError("%s keys must be strings" % field)
        if link_id not in declared:
            raise ConfigError(
                "%s refers to an undeclared link: %s" % (field, link_id)
            )
        listed.add(link_id)
        value = values[link_id]
        if type(value) is not int or not 0 <= value <= MAX_QUEUE_BYTES:
            raise ConfigError(
                "%s[%s] must be an integer in 0..%d"
                % (field, link_id, MAX_QUEUE_BYTES)
            )
        resolved[link_id] = value
    missing = declared - listed
    if missing:
        raise ConfigError(
            "%s is missing declared link: %s" % (field, sorted(missing)[0])
        )
    return resolved


def validate_queues(document, link_ids):
    """Validate queue_capacities and queue_occupancies together.

    Both objects must exactly cover the declared links with integer
    byte counts (see validate_queue_bytes), and no occupancy may exceed
    the same link's capacity; the cross check is done in Unicode code
    point order of link ids so the first reported problem is
    deterministic. Returns (capacities, occupancies) as mappings of
    link id to byte count.
    """
    capacities = validate_queue_bytes(document, "queue_capacities", link_ids)
    occupancies = validate_queue_bytes(document, "queue_occupancies", link_ids)
    for link_id in sorted(capacities):
        if occupancies[link_id] > capacities[link_id]:
            raise ConfigError(
                "queue_occupancies[%s] exceeds queue_capacities[%s]"
                % (link_id, link_id)
            )
    return capacities, occupancies


def validate_events(document, link_ids):
    """Validate the events field; every problem is a ConfigError.

    events must be an array of at most 100000 objects, each with
    exactly the fields at_ms, link and up: at_ms is a decimal
    millisecond string under the same format and range rules as
    clock_ms, link must refer to a declared link id, and up must be a
    JSON boolean. Events must be ordered by non-decreasing at_ms;
    equal times and repeated sets of one link are allowed. Elements
    are checked in array order so the first reported problem is
    deterministic. Returns a list of (at_ms in thousandths, link id,
    up) in input order.
    """
    events = document["events"]
    if not isinstance(events, list):
        raise ConfigError("events must be an array")
    if len(events) > MAX_EVENTS:
        raise ConfigError("too many events: limit is %d" % MAX_EVENTS)

    declared = set(link_ids)
    resolved = []
    previous_at = None
    for pos, element in enumerate(events):
        where = "events[%d]" % pos
        if not isinstance(element, dict):
            raise ConfigError("%s must be an object" % where)
        if set(element) != set(EVENT_FIELDS):
            raise ConfigError(
                "%s must contain exactly the fields at_ms, link, up" % where
            )
        at = parse_time_value(
            element["at_ms"], MAX_CLOCK_THOUSANDTHS, "%s.at_ms" % where
        )
        link_id = element["link"]
        if not isinstance(link_id, str):
            raise ConfigError("%s.link must be a string" % where)
        if link_id not in declared:
            raise ConfigError(
                "%s.link does not refer to a declared link" % where
            )
        up = element["up"]
        if type(up) is not bool:
            raise ConfigError("%s.up must be a boolean" % where)
        if previous_at is not None and at < previous_at:
            raise ConfigError(
                "%s.at_ms is earlier than the previous event" % where
            )
        previous_at = at
        resolved.append((at, link_id, up))
    return resolved


def validate_node_events(document, node_ids):
    """Validate the events field of node-event-trace; every problem is a
    ConfigError.

    events must be an array of at most 100000 objects, each with
    exactly the fields at_ms, node and up: at_ms is a decimal
    millisecond string under the same format and range rules as
    clock_ms, node must refer to a declared node id, and up must be a
    JSON boolean. Events must be ordered by non-decreasing at_ms;
    equal times and repeated sets of one node are allowed. Elements
    are checked in array order so the first reported problem is
    deterministic. Returns a list of (at_ms in thousandths, node id,
    up) in input order.
    """
    events = document["events"]
    if not isinstance(events, list):
        raise ConfigError("events must be an array")
    if len(events) > MAX_EVENTS:
        raise ConfigError("too many events: limit is %d" % MAX_EVENTS)

    declared = set(node_ids)
    resolved = []
    previous_at = None
    for pos, element in enumerate(events):
        where = "events[%d]" % pos
        if not isinstance(element, dict):
            raise ConfigError("%s must be an object" % where)
        if set(element) != set(NODE_EVENT_FIELDS):
            raise ConfigError(
                "%s must contain exactly the fields at_ms, node, up" % where
            )
        at = parse_time_value(
            element["at_ms"], MAX_CLOCK_THOUSANDTHS, "%s.at_ms" % where
        )
        node_id = element["node"]
        if not isinstance(node_id, str):
            raise ConfigError("%s.node must be a string" % where)
        if node_id not in declared:
            raise ConfigError(
                "%s.node does not refer to a declared node" % where
            )
        up = element["up"]
        if type(up) is not bool:
            raise ConfigError("%s.up must be a boolean" % where)
        if previous_at is not None and at < previous_at:
            raise ConfigError(
                "%s.at_ms is earlier than the previous event" % where
            )
        previous_at = at
        resolved.append((at, node_id, up))
    return resolved


def shortest_distances(node_count, adjacency, source):
    """Plain Dijkstra over positive-cost directed edges."""
    dist = [None] * node_count
    dist[source] = 0
    heap = [(0, source)]
    while heap:
        current, u = heapq.heappop(heap)
        if current != dist[u]:
            continue
        for v, cost, _link_id in adjacency[u]:
            candidate = current + cost
            if dist[v] is None or candidate < dist[v]:
                dist[v] = candidate
                heapq.heappush(heap, (candidate, v))
    return dist


def find_route(node_ids, links, source, destination):
    """Return (path node ids, link ids, total cost), or None if unreachable.

    A shortest-path DAG is built from the Dijkstra distances; every edge in
    it strictly raises distance (positive costs), so it is acyclic. Walking
    from source and greedily taking the lexicographically smallest feasible
    (next node id, link id) yields the smallest full node sequence and,
    secondarily, link sequence among all minimum-cost routes.
    """
    if source == destination:
        return [node_ids[source]], [], 0

    node_count = len(node_ids)
    adjacency = [[] for _ in range(node_count)]
    for link_id, u, v, cost, up in links:
        if up:
            adjacency[u].append((v, cost, link_id))

    dist = shortest_distances(node_count, adjacency, source)
    if dist[destination] is None:
        return None

    forward = [[] for _ in range(node_count)]
    reverse = [[] for _ in range(node_count)]
    for link_id, u, v, cost, up in links:
        if up and dist[u] is not None and dist[u] + cost == dist[v]:
            forward[u].append((v, link_id))
            reverse[v].append(u)

    can_reach_destination = [False] * node_count
    can_reach_destination[destination] = True
    stack = [destination]
    while stack:
        node = stack.pop()
        for predecessor in reverse[node]:
            if not can_reach_destination[predecessor]:
                can_reach_destination[predecessor] = True
                stack.append(predecessor)

    path_indices = [source]
    path_links = []
    current = source
    while current != destination:
        best_key = None
        best_node = None
        best_link = None
        for nxt, link_id in forward[current]:
            if not can_reach_destination[nxt]:
                continue
            key = (node_ids[nxt], link_id)
            if best_key is None or key < best_key:
                best_key = key
                best_node = nxt
                best_link = link_id
        path_indices.append(best_node)
        path_links.append(best_link)
        current = best_node

    return [node_ids[i] for i in path_indices], path_links, dist[destination]


def trace_packet(node_ids, links, source, destination, packet_id, ttl):
    """Forward a packet along the deterministic minimum-cost route.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason.
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "forward",
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def fragment_division(payload_bytes, mtu):
    """Describe how a payload is sliced front to back at an MTU.

    Every fragment but the last is exactly mtu bytes; the last carries
    the remainder and is also mtu bytes when the length divides
    exactly. An empty payload is a single zero-length fragment. The
    bytes are never actually sliced or copied and no per-fragment
    record is built; only (fragment_count, last_fragment_bytes) is
    returned, both derived in constant time from the byte count.
    """
    if payload_bytes == 0:
        return 1, 0
    full, remainder = divmod(payload_bytes, mtu)
    if remainder == 0:
        return full, mtu
    return full + 1, remainder


def fragment_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, payload, link_mtus
):
    """Forward a packet along the deterministic minimum-cost route,
    fragmenting the reassembled payload at every successful departure.

    Routing, ttl and drop attribution are exactly as in trace_packet;
    MTUs never influence the path. Before each successful departure the
    UTF-8 bytes of packet.payload are treated as the reassembled
    complete payload and sliced front to back by the selected link's
    MTU (see fragment_division); slicing may fall inside a multibyte
    character, fragment contents are never emitted or decoded, and the
    payload is conceptually reassembled at the next node.
    Fragmentation consumes no extra ttl, and a link that is never
    attempted (immediate delivery, no_route, ttl_exhausted) produces no
    fragment record.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every
    hop carries keys from, to, link, ttl_before, ttl_after, decision,
    mtu_bytes, payload_bytes, fragment_count, last_fragment_bytes, with
    decision "fragment_forward".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    payload_bytes = len(payload.encode("utf-8"))
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        mtu = link_mtus[link_id]
        fragment_count, last_fragment_bytes = fragment_division(
            payload_bytes, mtu
        )
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "fragment_forward",
            "mtu_bytes": mtu,
            "payload_bytes": payload_bytes,
            "fragment_count": fragment_count,
            "last_fragment_bytes": last_fragment_bytes,
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def latency_trace_packet(
    node_ids, links, source, destination, packet_id, ttl,
    start_thousandths, link_latencies,
):
    """Forward a packet along the deterministic minimum-cost route,
    stamping every hop with departure, latency and arrival times.

    Routing, ttl and drop attribution are exactly as in trace_packet;
    latencies never influence the path. Time is accumulated in
    thousandths of a millisecond. The first hop departs at
    start_thousandths, every later hop departs when the previous hop
    arrived, and a hop arrives its link latency after departing.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason,
    started_at_ms, finished_at_ms. Every hop carries keys from, to,
    link, ttl_before, ttl_after, decision, departed_at_ms, latency_ms,
    arrived_at_ms, with decision "forward".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
        "started_at_ms": format_ms(start_thousandths),
        "finished_at_ms": format_ms(start_thousandths),
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    now = start_thousandths
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            output["finished_at_ms"] = format_ms(now)
            return output
        latency = link_latencies.get(link_id, 0)
        arrived = now + latency
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "forward",
            "departed_at_ms": format_ms(now),
            "latency_ms": format_ms(latency),
            "arrived_at_ms": format_ms(arrived),
        }
        output["hops"].append(hop)
        now = arrived
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    output["finished_at_ms"] = format_ms(now)
    return output


def serialization_thousandths(payload_bytes, bandwidth_bps):
    """Serialization delay for a payload on a bandwidth-limited link.

    ceil(bytes * 8 * 1000000 / bandwidth_bps) thousandths of a
    millisecond, using integer arithmetic only; an empty payload is
    zero. Protocol headers are never counted.
    """
    numerator = payload_bytes * 8 * SERIALIZATION_SCALE_THOUSANDTHS
    if numerator == 0:
        return 0
    return (numerator + bandwidth_bps - 1) // bandwidth_bps


def bandwidth_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, payload,
    start_thousandths, link_latencies, link_bandwidths,
):
    """Forward a packet along the deterministic minimum-cost route,
    stamping every hop with departure, bandwidth, serialization,
    latency and arrival times.

    Routing, ttl and drop attribution are exactly as in
    latency_trace_packet; bandwidth and latency never influence the
    path. Time is accumulated in thousandths of a millisecond with
    integer arithmetic. The first hop departs at start_thousandths,
    every later hop departs when the previous hop arrived, and a hop
    arrives its serialization time plus its link latency after
    departing. Serialization time depends only on the payload's UTF-8
    byte count and the link bandwidth.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason,
    started_at_ms, finished_at_ms. Every hop carries keys from, to,
    link, ttl_before, ttl_after, decision, departed_at_ms,
    bandwidth_bps, serialization_ms, latency_ms, arrived_at_ms, with
    decision "forward".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    payload_bytes = len(payload.encode("utf-8"))
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
        "started_at_ms": format_ms(start_thousandths),
        "finished_at_ms": format_ms(start_thousandths),
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    now = start_thousandths
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            output["finished_at_ms"] = format_ms(now)
            return output
        bandwidth = link_bandwidths[link_id]
        serialization = serialization_thousandths(payload_bytes, bandwidth)
        latency = link_latencies.get(link_id, 0)
        arrived = now + serialization + latency
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "forward",
            "departed_at_ms": format_ms(now),
            "bandwidth_bps": bandwidth,
            "serialization_ms": format_ms(serialization),
            "latency_ms": format_ms(latency),
            "arrived_at_ms": format_ms(arrived),
        }
        output["hops"].append(hop)
        now = arrived
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    output["finished_at_ms"] = format_ms(now)
    return output


def loss_hash_value(packet_id, link_id, hop_index):
    """First eight digest bytes of the per-attempt loss hash, as an int.

    SHA-256 over the UTF-8 bytes of packet.id, one zero byte, the UTF-8
    bytes of the link id, one zero byte, and the decimal ASCII bytes of
    the zero-based hop index; the first eight digest bytes are read as
    a big-endian unsigned integer.
    """
    digest = hashlib.sha256()
    digest.update(packet_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(link_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(str(hop_index).encode("ascii"))
    return int.from_bytes(digest.digest()[:8], "big")


def loss_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, link_loss_units
):
    """Forward a packet along the deterministic minimum-cost route,
    losing each link attempt when its deterministic hash falls below
    the link's configured loss rate.

    Routing, ttl and drop attribution are exactly as in trace_packet;
    loss rates never influence the path. An attempt on a link is lost
    exactly when loss_value * 1000000 < loss_units * 2**64, where
    loss_value is loss_hash_value for that attempt and loss_units the
    link's rate in millionths (default zero). A lost attempt is
    recorded in hops and consumes one ttl, but its target node is not
    added to path, final_node stays at the sending node, and the trace
    stops with reason link_loss.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every
    hop carries keys from, to, link, ttl_before, ttl_after, decision,
    loss_rate, loss_value, with decision "forward" or "drop_loss".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for hop_index, (next_id, link_id) in enumerate(zip(path[1:], route_links)):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        loss_units = link_loss_units.get(link_id, 0)
        loss_value = loss_hash_value(packet_id, link_id, hop_index)
        lost = loss_value * MAX_LOSS_UNITS < loss_units << 64
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "drop_loss" if lost else "forward",
            "loss_rate": format_loss_rate(loss_units),
            "loss_value": "%016x" % loss_value,
        }
        output["hops"].append(hop)
        remaining -= 1
        if lost:
            output["status"] = "dropped"
            output["reason"] = "link_loss"
            output["ttl_remaining"] = remaining
            return output
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def queue_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, payload,
    queue_capacities, queue_occupancies,
):
    """Forward a packet along the deterministic minimum-cost route,
    admitting it to each link's queue or tail-dropping it when the
    queued bytes plus the packet bytes exceed the link's capacity.

    Routing, ttl and drop attribution are exactly as in trace_packet;
    queue capacities and occupancies never influence the path. Each
    link's occupancy is an independent snapshot taken before the
    attempt; nothing is read from a wall clock and no state is carried
    between links. packet_bytes is the UTF-8 byte count of the payload.
    An attempt is admitted exactly when occupancy + packet_bytes <=
    capacity (filling the queue exactly still succeeds): the packet
    reaches the next node and one ttl is consumed. Otherwise the packet
    is tail dropped immediately: the attempt is recorded in hops, but
    its target node is not added to path, final_node stays at the
    sending node, ttl_after equals ttl_before, and the trace stops with
    reason queue_tail_drop.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every
    hop carries keys from, to, link, ttl_before, ttl_after, decision,
    capacity_bytes, queued_bytes_before, packet_bytes,
    queued_bytes_after, with decision "enqueue" or "drop_tail".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    payload_bytes = len(payload.encode("utf-8"))
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        capacity = queue_capacities[link_id]
        queued_before = queue_occupancies[link_id]
        admitted = queued_before + payload_bytes <= capacity
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1 if admitted else remaining,
            "decision": "enqueue" if admitted else "drop_tail",
            "capacity_bytes": capacity,
            "queued_bytes_before": queued_before,
            "packet_bytes": payload_bytes,
            "queued_bytes_after": (
                queued_before + payload_bytes if admitted else queued_before
            ),
        }
        output["hops"].append(hop)
        if not admitted:
            output["status"] = "dropped"
            output["reason"] = "queue_tail_drop"
            output["ttl_remaining"] = remaining
            return output
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def apply_events(links, events, clock_thousandths):
    """Replay events up to the query time over the declared link states.

    Every link starts in its declared up state; events with at_ms less
    than or equal to clock_thousandths are applied in input order and
    later events never take effect. Returns (effective links, applied
    events), where effective links are (id, u, v, cost, up) tuples in
    the declared link order and applied events are {"at_ms", "link",
    "up"} objects in input order with at_ms rendered to three
    fractional digits.
    """
    state = {link_id: up for link_id, _u, _v, _cost, up in links}
    applied = []
    for at, link_id, up in events:
        if at > clock_thousandths:
            break
        state[link_id] = up
        applied.append(
            {"at_ms": format_ms(at), "link": link_id, "up": up}
        )
    effective = [
        (link_id, u, v, cost, state[link_id])
        for link_id, u, v, cost, _up in links
    ]
    return effective, applied


def event_trace_packet(
    node_ids, links, source, destination, packet_id, ttl,
    clock_thousandths, events,
):
    """Replay link events against the event clock, then forward a packet
    along the deterministic minimum-cost route of the effective
    topology.

    Links start in their declared up state, events with at_ms less
    than or equal to clock_thousandths are applied in input order, and
    routing, ttl and drop attribution are exactly as in trace_packet
    over the resulting topology. Applying events consumes no ttl and
    never reads the wall clock.

    Returns the output object with keys status, packet_id, source,
    destination, clock_ms, applied_events, path, hops, final_node,
    ttl_remaining, reason. Every hop carries keys from, to, link,
    ttl_before, ttl_after, decision, with decision "event_route".
    """
    effective_links, applied = apply_events(links, events, clock_thousandths)

    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "clock_ms": format_ms(clock_thousandths),
        "applied_events": applied,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, effective_links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "event_route",
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def apply_node_events(node_ids, events, clock_thousandths):
    """Replay node events up to the query time.

    Every node starts available; events with at_ms less than or equal
    to clock_thousandths are applied in input order and later events
    never take effect. Returns (node availability, applied events),
    where node availability is a list of booleans in node declaration
    order and applied events are {"at_ms", "node", "up"} objects in
    input order with at_ms rendered to three fractional digits.
    """
    available = [True] * len(node_ids)
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    applied = []
    for at, node_id, up in events:
        if at > clock_thousandths:
            break
        available[node_index[node_id]] = up
        applied.append(
            {"at_ms": format_ms(at), "node": node_id, "up": up}
        )
    return available, applied


def node_event_trace_packet(
    node_ids, links, source, destination, packet_id, ttl,
    clock_thousandths, events,
):
    """Replay node events against the event clock, then forward a packet
    along the deterministic minimum-cost route of the effective
    topology.

    Nodes start available, events with at_ms less than or equal to
    clock_thousandths are applied in input order, and a link
    participates in routing exactly when its declared up state is true
    and both endpoint nodes are available at the query time. If the
    source or the destination is unavailable, the packet is dropped at
    the source with reason node_down before any other check, even when
    source equals destination. Otherwise routing, ttl and drop
    attribution are exactly as in trace_packet over the effective
    topology. Applying events consumes no ttl and never reads the wall
    clock.

    Returns the output object with keys status, packet_id, source,
    destination, clock_ms, applied_events, path, hops, final_node,
    ttl_remaining, reason. Every hop carries keys from, to, link,
    ttl_before, ttl_after, decision, with decision "node_event_route".
    """
    available, applied = apply_node_events(node_ids, events, clock_thousandths)

    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "clock_ms": format_ms(clock_thousandths),
        "applied_events": applied,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if not available[source] or not available[destination]:
        output["status"] = "dropped"
        output["reason"] = "node_down"
        return output

    if source == destination:
        output["status"] = "delivered"
        return output

    effective_links = [
        (link_id, u, v, cost, up and available[u] and available[v])
        for link_id, u, v, cost, up in links
    ]
    route = find_route(node_ids, effective_links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "node_event_route",
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def apply_damped_events(links, events, clock_thousandths, hold_thousandths):
    """Replay link events with a hold-down wait before each takes effect.

    Only events with at_ms less than or equal to clock_thousandths are
    observed; later events never take effect and never suppress earlier
    ones. An observed event would take effect at at_ms + hold_down_ms;
    it is suppressed when a later observed event for the same link
    arrives strictly before that moment (the wait restarts even for an
    equal up value), while an event arriving exactly at that moment
    does not suppress it. Surviving events whose effective time is not
    later than clock_thousandths apply in input order over the declared
    link states. Returns (effective links, effective events), where
    effective links are (id, u, v, cost, up) tuples in the declared
    link order and effective events are {"at_ms", "effective_at_ms",
    "link", "up"} objects in the order they take effect, with times
    rendered to three fractional digits.
    """
    observed = [event for event in events if event[0] <= clock_thousandths]
    suppressed = [False] * len(observed)
    next_at = {}
    for index in range(len(observed) - 1, -1, -1):
        at, link_id, _up = observed[index]
        later = next_at.get(link_id)
        if later is not None and later < at + hold_thousandths:
            suppressed[index] = True
        next_at[link_id] = at

    state = {link_id: up for link_id, _u, _v, _cost, up in links}
    effective_events = []
    for (at, link_id, up), is_suppressed in zip(observed, suppressed):
        if is_suppressed:
            continue
        effective_at = at + hold_thousandths
        if effective_at > clock_thousandths:
            continue
        state[link_id] = up
        effective_events.append(
            {
                "at_ms": format_ms(at),
                "effective_at_ms": format_ms(effective_at),
                "link": link_id,
                "up": up,
            }
        )
    effective = [
        (link_id, u, v, cost, state[link_id])
        for link_id, u, v, cost, _up in links
    ]
    return effective, effective_events


def damped_event_trace_packet(
    node_ids, links, source, destination, packet_id, ttl,
    clock_thousandths, hold_thousandths, events,
):
    """Replay link events with a hold-down wait, then forward a packet
    along the deterministic minimum-cost route of the effective
    topology.

    Links start in their declared up state, every observed event takes
    effect only after hold_down_ms unless a later same-link event
    suppresses it first, and routing, ttl and drop attribution are
    exactly as in trace_packet over the resulting topology. Applying
    events consumes no ttl and never reads the wall clock.

    Returns the output object with keys status, packet_id, source,
    destination, clock_ms, hold_down_ms, effective_events, path, hops,
    final_node, ttl_remaining, reason. Every hop carries keys from, to,
    link, ttl_before, ttl_after, decision, with decision
    "damped_event_route".
    """
    effective_links, effective_events = apply_damped_events(
        links, events, clock_thousandths, hold_thousandths
    )

    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "clock_ms": format_ms(clock_thousandths),
        "hold_down_ms": format_ms(hold_thousandths),
        "effective_events": effective_events,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    route = find_route(node_ids, effective_links, source, destination)
    if route is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    path, route_links, _total_cost = route
    remaining = ttl
    for next_id, link_id in zip(path[1:], route_links):
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "damped_event_route",
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def ecmp_candidate_table(node_ids, links, destination):
    """Minimum-cost candidate next hops for every node, keyed by distance.

    Dijkstra is run once on the reversed up-link graph from destination,
    so dist[v] is the minimum cost v -> destination. An up link u -> v of
    cost c is a candidate exactly when dist[u] == c + dist[v] (and both
    ends are finite): taking it enters a minimum-total-cost path. Links of
    any other total cost are excluded. Full equal-cost paths are never
    enumerated. Each node's candidates are sorted by (next node id, link
    id) in Unicode code point order; parallel links each take one slot.

    Returns (dist, candidates), where candidates[u] is a list of
    (next node index, link id) sorted as above.
    """
    node_count = len(node_ids)
    reverse = [[] for _ in range(node_count)]
    up_links = []
    for link_id, u, v, cost, up in links:
        if up:
            reverse[v].append((u, cost))
            up_links.append((link_id, u, v, cost))

    dist = [None] * node_count
    dist[destination] = 0
    heap = [(0, destination)]
    while heap:
        current, node = heapq.heappop(heap)
        if current != dist[node]:
            continue
        for predecessor, cost in reverse[node]:
            candidate = current + cost
            if dist[predecessor] is None or candidate < dist[predecessor]:
                dist[predecessor] = candidate
                heapq.heappush(heap, (candidate, predecessor))

    candidates = [[] for _ in range(node_count)]
    for link_id, u, v, cost in up_links:
        if dist[u] is not None and dist[v] is not None and dist[u] == cost + dist[v]:
            candidates[u].append((v, link_id))
    for entry in candidates:
        entry.sort(key=lambda item: (node_ids[item[0]], item[1]))
    return dist, candidates


def select_ecmp_index(packet_id, current_node_id, candidate_count):
    """Hash packet.id and the current node id onto a candidate index.

    SHA-256 over packet.id UTF-8 bytes, one zero byte, then the current
    node id UTF-8 bytes; the digest as a big-endian unsigned integer is
    taken modulo the candidate count.
    """
    digest = hashlib.sha256()
    digest.update(packet_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(current_node_id.encode("utf-8"))
    return int.from_bytes(digest.digest(), "big") % candidate_count


def ecmp_trace_packet(node_ids, links, source, destination, packet_id, ttl):
    """Forward a packet by hashing onto an equal-cost minimum-cost next hop.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every hop
    carries keys from, to, link, ttl_before, ttl_after, decision,
    candidate_count, selected_index, with decision "ecmp_hash".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    dist, candidates = ecmp_candidate_table(node_ids, links, destination)
    if dist[source] is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    remaining = ttl
    current = source
    hop_budget = len(node_ids) - 1
    while current != destination:
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        current_candidates = candidates[current]
        if not current_candidates:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output
        selected = select_ecmp_index(
            packet_id, node_ids[current], len(current_candidates)
        )
        next_node, link_id = current_candidates[selected]
        next_id = node_ids[next_node]
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "ecmp_hash",
            "candidate_count": len(current_candidates),
            "selected_index": selected,
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id
        current = next_node
        hop_budget -= 1
        if hop_budget < 0:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def weighted_ecmp_hash_value(packet_id, current_node_id):
    """SHA-256 digest of packet id and current node id, as an unsigned int.

    Same byte sequence as select_ecmp_index: packet.id UTF-8 bytes, one
    zero byte, then the current node id UTF-8 bytes, interpreted
    big-endian. The caller applies the modulo (candidate count or total
    candidate weight) so the raw value stays auditable.
    """
    digest = hashlib.sha256()
    digest.update(packet_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(current_node_id.encode("utf-8"))
    return int.from_bytes(digest.digest(), "big")


def weighted_ecmp_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, link_weights
):
    """Forward a packet by hashing onto a weighted equal-cost next hop.

    Candidates are identical to ecmp-trace. The hash value is taken
    modulo the sum of candidate weights, then mapped to a candidate via
    zero-based cumulative weight intervals: candidate i owns the
    half-open interval [cumulative before i, cumulative after i). The
    candidate array is never expanded by weight.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every
    hop carries keys from, to, link, ttl_before, ttl_after, decision,
    candidate_count, selected_index, selected_weight, total_weight,
    selected_value, with decision "weighted_ecmp_hash".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    dist, candidates = ecmp_candidate_table(node_ids, links, destination)
    if dist[source] is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    remaining = ttl
    current = source
    hop_budget = len(node_ids) - 1
    while current != destination:
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        current_candidates = candidates[current]
        if not current_candidates:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output
        weights = [
            link_weights.get(link_id, 1) for _next_node, link_id in current_candidates
        ]
        total_weight = sum(weights)
        value = weighted_ecmp_hash_value(packet_id, node_ids[current])
        selected_value = value % total_weight
        cumulative = 0
        selected = 0
        selected_weight = weights[0]
        for index, weight in enumerate(weights):
            if selected_value < cumulative + weight:
                selected = index
                selected_weight = weight
                break
            cumulative += weight
        next_node, link_id = current_candidates[selected]
        next_id = node_ids[next_node]
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "weighted_ecmp_hash",
            "candidate_count": len(current_candidates),
            "selected_index": selected,
            "selected_weight": selected_weight,
            "total_weight": total_weight,
            "selected_value": selected_value,
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id
        current = next_node
        hop_budget -= 1
        if hop_budget < 0:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def sticky_ecmp_score(flow_id, current_node_id, next_node_id, link_id):
    """SHA-256 digest scoring one candidate next hop for a flow.

    The hashed byte sequence is the UTF-8 bytes of flow_id, one zero
    byte, the current node id, one zero byte, the candidate's next node
    id, one zero byte, and the link id. Returns the raw 32-byte digest;
    digests compare as big-endian unsigned integers, which plain byte
    comparison already implements.
    """
    digest = hashlib.sha256()
    digest.update(flow_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(current_node_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(next_node_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(link_id.encode("utf-8"))
    return digest.digest()


def sticky_ecmp_trace_packet(
    node_ids, links, source, destination, packet_id, ttl, flow_id
):
    """Forward a packet onto the highest-scoring equal-cost next hop.

    Candidates are identical to ecmp-trace. Each candidate is scored by
    sticky_ecmp_score; the highest score wins and ties resolve toward
    the candidate that sorts earlier, so the choice depends only on
    flow_id and the candidate set, never on packet.id, priority,
    payload or input array order.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason. Every
    hop carries keys from, to, link, ttl_before, ttl_after, decision,
    candidate_count, selected_index, selected_score, with decision
    "sticky_ecmp_hash".
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    output = {
        "status": None,
        "packet_id": packet_id,
        "source": source_id,
        "destination": destination_id,
        "path": [source_id],
        "hops": [],
        "final_node": source_id,
        "ttl_remaining": ttl,
        "reason": None,
    }

    if source == destination:
        output["status"] = "delivered"
        return output

    dist, candidates = ecmp_candidate_table(node_ids, links, destination)
    if dist[source] is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    remaining = ttl
    current = source
    hop_budget = len(node_ids) - 1
    while current != destination:
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        current_candidates = candidates[current]
        if not current_candidates:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output
        current_id = node_ids[current]
        selected = 0
        best_score = None
        for index, (next_node, link_id) in enumerate(current_candidates):
            score = sticky_ecmp_score(
                flow_id, current_id, node_ids[next_node], link_id
            )
            if best_score is None or score > best_score:
                best_score = score
                selected = index
        next_node, link_id = current_candidates[selected]
        next_id = node_ids[next_node]
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "sticky_ecmp_hash",
            "candidate_count": len(current_candidates),
            "selected_index": selected,
            "selected_score": best_score.hex(),
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id
        current = next_node
        hop_budget -= 1
        if hop_budget < 0:
            output["status"] = "dropped"
            output["reason"] = "no_route"
            output["ttl_remaining"] = remaining
            return output

    output["status"] = "delivered"
    output["ttl_remaining"] = remaining
    return output


def write_json_line(stream, value):
    stream.write(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"
    )
    stream.flush()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="relay_path.py",
        description="Static minimum-cost relay routing and packet tracing.",
        epilog=FORMAT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    route_parser = subparsers.add_parser(
        "route",
        help="route from source to destination",
        description="Route from source to destination.",
        epilog=FORMAT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    route_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON routing document",
    )
    trace_parser = subparsers.add_parser(
        "trace",
        help="trace a packet hop by hop toward the destination",
        description="Trace a packet hop by hop toward the destination.",
        epilog=TRACE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    trace_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON trace document",
    )
    ecmp_parser = subparsers.add_parser(
        "ecmp-trace",
        help="hash a packet onto an equal-cost next hop at every node",
        description=(
            "Trace a packet that is hashed onto an equal-cost "
            "minimum-cost next hop at every node."
        ),
        epilog=ECMP_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ecmp_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON trace document",
    )
    weighted_parser = subparsers.add_parser(
        "weighted-ecmp-trace",
        help="hash a packet onto a weighted equal-cost next hop at every node",
        description=(
            "Trace a packet that is hashed onto a weighted equal-cost "
            "minimum-cost next hop at every node."
        ),
        epilog=WEIGHTED_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    weighted_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON weighted trace document",
    )
    sticky_parser = subparsers.add_parser(
        "sticky-ecmp-trace",
        help="keep a flow on the highest-scoring equal-cost next hop",
        description=(
            "Trace a packet whose flow is kept on the highest-scoring "
            "equal-cost minimum-cost next hop at every node."
        ),
        epilog=STICKY_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sticky_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON sticky trace document",
    )
    latency_parser = subparsers.add_parser(
        "latency-trace",
        help="stamp every hop of the trace with link latency times",
        description=(
            "Trace a packet along the deterministic minimum-cost route "
            "and stamp every hop with departure, link-latency and "
            "arrival times."
        ),
        epilog=LATENCY_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    latency_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON latency trace document",
    )
    bandwidth_parser = subparsers.add_parser(
        "bandwidth-trace",
        help="stamp every hop with serialization plus latency times",
        description=(
            "Trace a packet along the deterministic minimum-cost route "
            "and stamp every hop with departure, bandwidth, "
            "serialization, link-latency and arrival times."
        ),
        epilog=BANDWIDTH_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bandwidth_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON bandwidth trace document",
    )
    loss_parser = subparsers.add_parser(
        "loss-trace",
        help="drop a packet on links whose loss hash falls below the rate",
        description=(
            "Trace a packet along the deterministic minimum-cost route "
            "and lose each link attempt when its deterministic hash "
            "falls below the link's configured loss rate."
        ),
        epilog=LOSS_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    loss_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON loss trace document",
    )
    queue_parser = subparsers.add_parser(
        "queue-trace",
        help="admit a packet to per-link queues or tail-drop it",
        description=(
            "Trace a packet along the deterministic minimum-cost route "
            "and admit it to each link's queue when the queued bytes "
            "plus the packet bytes fit the link's capacity, tail "
            "dropping it otherwise."
        ),
        epilog=QUEUE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    queue_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON queue trace document",
    )
    event_parser = subparsers.add_parser(
        "event-trace",
        help="replay link events, then trace over the effective topology",
        description=(
            "Replay link failure and recovery events against an "
            "explicit event clock, then trace a packet hop by hop over "
            "the effective topology at the query time."
        ),
        epilog=EVENT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    event_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON event trace document",
    )
    node_event_parser = subparsers.add_parser(
        "node-event-trace",
        help="replay node events, then trace over the effective topology",
        description=(
            "Replay node failure and recovery events against an "
            "explicit event clock, then trace a packet hop by hop over "
            "the effective topology at the query time."
        ),
        epilog=NODE_EVENT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    node_event_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON node event trace document",
    )
    fragment_parser = subparsers.add_parser(
        "fragment-trace",
        help="fragment the payload by per-link MTU on every hop",
        description=(
            "Trace a packet along the deterministic minimum-cost route "
            "and slice the reassembled payload into MTU-sized fragments "
            "before every successful link departure, reassembling at "
            "the next node."
        ),
        epilog=FRAGMENT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fragment_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON fragment trace document",
    )
    damped_event_parser = subparsers.add_parser(
        "damped-event-trace",
        help="replay link events with a hold-down wait, then trace",
        description=(
            "Replay link failure and recovery events against an "
            "explicit event clock, letting every event take effect "
            "only after a hold-down wait and suppressing events "
            "overtaken by a later event for the same link, then trace "
            "a packet hop by hop over the effective topology at the "
            "query time."
        ),
        epilog=DAMPED_EVENT_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    damped_event_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON damped event trace document",
    )
    return parser


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    try:
        document = load_document(args.input)
        if args.command == "trace":
            node_ids, links, source, destination = validate(
                document, TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            output = trace_packet(
                node_ids, links, source, destination, packet_id, ttl
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "ecmp-trace":
            node_ids, links, source, destination = validate(
                document, TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            output = ecmp_trace_packet(
                node_ids, links, source, destination, packet_id, ttl
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "weighted-ecmp-trace":
            node_ids, links, source, destination = validate(
                document, WEIGHTED_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            link_weights = validate_weights(
                document, [link[0] for link in links]
            )
            output = weighted_ecmp_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                link_weights,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "sticky-ecmp-trace":
            node_ids, links, source, destination = validate(
                document, TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload, flow_id = (
                validate_sticky_packet(document)
            )
            output = sticky_ecmp_trace_packet(
                node_ids, links, source, destination, packet_id, ttl, flow_id
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "latency-trace":
            node_ids, links, source, destination = validate(
                document, LATENCY_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            start_thousandths = parse_time_value(
                document["clock_ms"], MAX_CLOCK_THOUSANDTHS, "clock_ms"
            )
            link_latencies = validate_latencies(
                document, [link[0] for link in links]
            )
            output = latency_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                start_thousandths,
                link_latencies,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "bandwidth-trace":
            node_ids, links, source, destination = validate(
                document, BANDWIDTH_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, payload = validate_packet(document)
            start_thousandths = parse_time_value(
                document["clock_ms"], MAX_CLOCK_THOUSANDTHS, "clock_ms"
            )
            link_latencies = validate_latencies(
                document, [link[0] for link in links]
            )
            link_bandwidths = validate_bandwidths(
                document, [link[0] for link in links]
            )
            output = bandwidth_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                payload,
                start_thousandths,
                link_latencies,
                link_bandwidths,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "loss-trace":
            node_ids, links, source, destination = validate(
                document, LOSS_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            link_loss_units = validate_loss_rates(
                document, [link[0] for link in links]
            )
            output = loss_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                link_loss_units,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "queue-trace":
            node_ids, links, source, destination = validate(
                document, QUEUE_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, payload = validate_packet(document)
            queue_capacities, queue_occupancies = validate_queues(
                document, [link[0] for link in links]
            )
            output = queue_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                payload,
                queue_capacities,
                queue_occupancies,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "event-trace":
            node_ids, links, source, destination = validate(
                document, EVENT_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            clock_thousandths = parse_time_value(
                document["clock_ms"], MAX_CLOCK_THOUSANDTHS, "clock_ms"
            )
            events = validate_events(document, [link[0] for link in links])
            output = event_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                clock_thousandths,
                events,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "node-event-trace":
            node_ids, links, source, destination = validate(
                document, NODE_EVENT_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            clock_thousandths = parse_time_value(
                document["clock_ms"], MAX_CLOCK_THOUSANDTHS, "clock_ms"
            )
            events = validate_node_events(document, node_ids)
            output = node_event_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                clock_thousandths,
                events,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "fragment-trace":
            node_ids, links, source, destination = validate(
                document, FRAGMENT_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, payload = validate_packet(document)
            link_mtus = validate_mtus(document, [link[0] for link in links])
            output = fragment_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                payload,
                link_mtus,
            )
            write_json_line(sys.stdout, output)
            return 0
        if args.command == "damped-event-trace":
            node_ids, links, source, destination = validate(
                document, DAMPED_EVENT_TRACE_ROOT_FIELDS
            )
            packet_id, ttl, _priority, _payload = validate_packet(document)
            clock_thousandths = parse_time_value(
                document["clock_ms"], MAX_CLOCK_THOUSANDTHS, "clock_ms"
            )
            hold_thousandths = parse_time_value(
                document["hold_down_ms"],
                MAX_LINK_LATENCY_THOUSANDTHS,
                "hold_down_ms",
            )
            events = validate_events(document, [link[0] for link in links])
            output = damped_event_trace_packet(
                node_ids,
                links,
                source,
                destination,
                packet_id,
                ttl,
                clock_thousandths,
                hold_thousandths,
                events,
            )
            write_json_line(sys.stdout, output)
            return 0
        node_ids, links, source, destination = validate(document)
        result = find_route(node_ids, links, source, destination)
    except (ConfigError, ParameterError, PacketError) as exc:
        write_json_line(
            sys.stderr, {"error": exc.error, "message": str(exc)}
        )
        return exc.exit_code

    if result is None:
        output = {
            "status": "unreachable",
            "source": node_ids[source],
            "destination": node_ids[destination],
            "path": [],
            "links": [],
            "total_cost": None,
        }
    else:
        path, route_links, total_cost = result
        output = {
            "status": "found",
            "source": node_ids[source],
            "destination": node_ids[destination],
            "path": path,
            "links": route_links,
            "total_cost": total_cost,
        }
    write_json_line(sys.stdout, output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
