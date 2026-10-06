#!/usr/bin/env python3
"""Static minimum-cost relay routing and per-hop packet tracing.

Public entry points:

    python relay_path.py route --input PATH
    python relay_path.py trace --input PATH
    python relay_path.py ecmp-trace --input PATH

Reads a UTF-8 JSON object describing relay nodes and directed links and
prints the minimum-cost route from source to destination (route), the
hop-by-hop forwarding trace of a packet along that route (trace), or an
equal-cost-multi-path trace in which each hop is hashed onto one of the
minimum-cost next hops (ecmp-trace), as one compact JSON object on
stdout.
"""

import argparse
import hashlib
import heapq
import json
import sys

MAX_NODES = 10000
MAX_LINKS = 50000
MAX_PACKET_ID_CODEPOINTS = 128
MAX_PACKET_TTL = 255
MAX_PACKET_PRIORITY = 7
MAX_PAYLOAD_BYTES = 65536
NODE_TYPES = ("relay", "terminal", "pseudo")
ROOT_FIELDS = ("nodes", "links", "source", "destination")
TRACE_ROOT_FIELDS = ROOT_FIELDS + ("packet",)
PACKET_FIELDS = ("id", "ttl", "priority", "payload")

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
input format (UTF-8 JSON object with exactly these five fields):
  nodes, links, source, destination
              exactly as in the route command; all route constraints
              on the topology apply unchanged
  packet      exactly as in the trace command

forwarding rules:
  at each node the candidate next hops are the up links that start a
  minimum-cost path from the current node to the destination. A link
  u->v with cost c qualifies exactly when dist(u) == c + dist(v), where
  dist is the minimum total cost to the destination; alternatives of a
  different total cost never participate. Parallel links each occupy
  one candidate slot. Candidates are ordered by Unicode code point
  order of (destination node id, link id).

  For every hop, SHA-256 is computed over the concatenation of the
  UTF-8 bytes of packet.id, one zero byte, and the UTF-8 bytes of the
  current node id; the digest is read as a big-endian unsigned integer
  and taken modulo the candidate count, yielding the zero-based
  selected index. priority, payload, and input array order never affect
  the choice. ttl must be greater than zero before the packet leaves a
  node and decreases by one per traversed link; arriving at the
  destination with ttl reduced to zero still counts as delivered. A
  packet whose ttl is zero before forwarding is dropped at the current
  node with reason ttl_exhausted. If no route exists, the packet is
  dropped at the source without traversing any link, with reason
  no_route. A source equal to its destination is delivered immediately
  without hashing and without consuming ttl. At most (node count - 1)
  hops are possible.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  unique drop cause). path lists the nodes actually reached; each hop
  has keys from, to, link, ttl_before, ttl_after, decision,
  candidate_count, selected_index in this order; decision is always
  "ecmp_hash", and the last two fields record this hop's candidate
  count and the selected zero-based index.

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3) and ParameterError (exit code 2) as in
  route; PacketError (exit code 4) for an invalid packet, with stdout
  left empty. All validation completes before any tracing begins.
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
    packet = document["packet"]
    if not isinstance(packet, dict):
        raise PacketError("packet must be an object")
    for name in PACKET_FIELDS:
        if name not in packet:
            raise PacketError("packet missing field: %s" % name)
    for name in sorted(k for k in packet if k not in PACKET_FIELDS):
        raise PacketError("packet has unexpected field: %s" % name)

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


def ecmp_candidates(node_ids, links, destination):
    """Build, for every node, the sorted candidate links toward destination.

    A reverse Dijkstra (edges traversed from their head) gives the
    minimum total cost dist[x] from each node to the destination. An up
    link u->v with cost c is a feasible equal-cost next hop at u exactly
    when dist[u] == c + dist[v]; such an edge strictly decreases the
    remaining distance because costs are positive, so following
    candidates can never loop. Candidates are sorted by Unicode code
    point order of (next node id, link id). Returns (dist, candidates),
    with candidates[u] a list of (v, link_id); nodes with no path to the
    destination have an empty list.
    """
    node_count = len(node_ids)
    reverse_adjacency = [[] for _ in range(node_count)]
    for link_id, u, v, cost, up in links:
        if up:
            reverse_adjacency[v].append((u, cost))

    dist = [None] * node_count
    dist[destination] = 0
    heap = [(0, destination)]
    while heap:
        current, u = heapq.heappop(heap)
        if current != dist[u]:
            continue
        for predecessor, cost in reverse_adjacency[u]:
            candidate = current + cost
            if dist[predecessor] is None or candidate < dist[predecessor]:
                dist[predecessor] = candidate
                heapq.heappush(heap, (candidate, predecessor))

    candidates = [[] for _ in range(node_count)]
    for link_id, u, v, cost, up in links:
        if (
            up
            and dist[u] is not None
            and dist[v] is not None
            and dist[u] == cost + dist[v]
        ):
            candidates[u].append((node_ids[v], link_id, v))
    for slots in candidates:
        slots.sort()
    candidate_links = [
        [(v, link_id) for _nid, link_id, v in slots] for slots in candidates
    ]
    return dist, candidate_links


def ecmp_trace_packet(node_ids, links, source, destination, packet_id, ttl):
    """Forward a packet hashing across the equal-cost minimum-cost next hops.

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

    dist, candidates = ecmp_candidates(node_ids, links, destination)
    if dist[source] is None:
        output["status"] = "dropped"
        output["reason"] = "no_route"
        return output

    packet_bytes = packet_id.encode("utf-8")
    remaining = ttl
    current = source
    while current != destination:
        slots = candidates[current]
        if remaining <= 0:
            output["status"] = "dropped"
            output["reason"] = "ttl_exhausted"
            output["ttl_remaining"] = remaining
            return output
        digest = hashlib.sha256(
            packet_bytes + b"\x00" + node_ids[current].encode("utf-8")
        ).digest()
        selected_index = int.from_bytes(digest, "big") % len(slots)
        nxt, link_id = slots[selected_index]
        next_id = node_ids[nxt]
        hop = {
            "from": output["final_node"],
            "to": next_id,
            "link": link_id,
            "ttl_before": remaining,
            "ttl_after": remaining - 1,
            "decision": "ecmp_hash",
            "candidate_count": len(slots),
            "selected_index": selected_index,
        }
        output["hops"].append(hop)
        remaining -= 1
        output["path"].append(next_id)
        output["final_node"] = next_id
        current = nxt

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
        help="hash a packet across equal-cost minimum-cost next hops",
        description=(
            "Trace a packet, hashing each hop across the equal-cost "
            "minimum-cost next hops."
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
