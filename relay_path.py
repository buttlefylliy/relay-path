#!/usr/bin/env python3
"""Static minimum-cost relay routing and per-hop packet tracing.

Public entry points:

    python relay_path.py route --input PATH
    python relay_path.py trace --input PATH

Reads a UTF-8 JSON object describing relay nodes and directed links and
prints the minimum-cost route from source to destination (route), or the
hop-by-hop forwarding trace of a packet along that route (trace), as one
compact JSON object on stdout.
"""

import argparse
import heapq
import json
import sys

MAX_NODES = 10000
MAX_LINKS = 50000
MAX_PACKET_ID_LENGTH = 128
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
              exactly as in the route command; all of its constraints
              and limits apply unchanged
  packet      object with exactly these four fields:
              id        non-empty string of at most 128 Unicode code
                        points
              ttl       integer in 0..255
              priority  integer in 0..7
              payload   string of at most 65536 bytes when UTF-8
                        encoded
              booleans are not accepted where integers are required

tracing rules:
  the packet follows the same deterministic minimum-cost route the
  route command selects: only up links participate, the total cost is
  minimized, and ties are broken by the same node-id then link-id
  lexicographic order, so input array order never affects the result.
  before leaving a node the ttl must be positive; each traversed link
  decrements it by one. arriving at the destination with ttl reduced
  to zero still counts as delivered. a packet whose ttl reaches zero
  away from the destination is dropped at the current node with reason
  ttl_exhausted. when no route is reachable the packet traverses no
  link and is dropped at the source with reason no_route. a source
  equal to its destination is delivered immediately without consuming
  ttl. a minimum-cost route never revisits a node, so a trace spans at
  most (node count - 1) hops.

output (single compact JSON line on stdout, keys in this order):
  status, packet_id, source, destination, path, hops, final_node,
  ttl_remaining, reason
  status is "delivered" (reason null) or "dropped" (reason is the
  single cause: "no_route" or "ttl_exhausted"). path lists the nodes
  actually reached; each hop in hops is an object with keys from, to,
  link, ttl_before, ttl_after, decision (always "forward").

errors (single compact JSON line on stderr, keys: error, message):
  ConfigError (exit code 3) and ParameterError (exit code 2) as in the
  route command; PacketError (exit code 4) when the packet field is
  malformed or out of range. all validation completes before any
  tracing begins, and on any error stdout stays empty.
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
    """The packet field is malformed or out of range."""

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


def validate(document, root_fields):
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


def validate_packet(packet):
    """Validate the packet field; every problem is a PacketError."""
    if not isinstance(packet, dict):
        raise PacketError("packet must be an object")
    if set(packet) != set(PACKET_FIELDS):
        raise PacketError(
            "packet must contain exactly the fields id, ttl, priority, "
            "payload"
        )
    packet_id = packet["id"]
    if (
        not isinstance(packet_id, str)
        or not packet_id
        or len(packet_id) > MAX_PACKET_ID_LENGTH
    ):
        raise PacketError(
            "packet.id must be a non-empty string of at most %d characters"
            % MAX_PACKET_ID_LENGTH
        )
    ttl = packet["ttl"]
    if type(ttl) is not int or not 0 <= ttl <= 255:
        raise PacketError("packet.ttl must be an integer between 0 and 255")
    priority = packet["priority"]
    if type(priority) is not int or not 0 <= priority <= 7:
        raise PacketError(
            "packet.priority must be an integer between 0 and 7"
        )
    payload = packet["payload"]
    if (
        not isinstance(payload, str)
        or len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES
    ):
        raise PacketError(
            "packet.payload must be a string of at most %d UTF-8 bytes"
            % MAX_PAYLOAD_BYTES
        )
    return packet


def trace_packet(node_ids, links, source, destination, packet):
    """Forward the packet hop by hop along the deterministic route.

    Returns the output object with keys status, packet_id, source,
    destination, path, hops, final_node, ttl_remaining, reason.
    """
    source_id = node_ids[source]
    destination_id = node_ids[destination]
    ttl = packet["ttl"]

    route = find_route(node_ids, links, source, destination)
    if route is None:
        return {
            "status": "dropped",
            "packet_id": packet["id"],
            "source": source_id,
            "destination": destination_id,
            "path": [source_id],
            "hops": [],
            "final_node": source_id,
            "ttl_remaining": ttl,
            "reason": "no_route",
        }

    path, route_links, _total_cost = route
    reached = [path[0]]
    hops = []
    status = "delivered"
    reason = None
    for pos, link_id in enumerate(route_links):
        if ttl == 0:
            status = "dropped"
            reason = "ttl_exhausted"
            break
        ttl_before = ttl
        ttl -= 1
        hops.append(
            {
                "from": path[pos],
                "to": path[pos + 1],
                "link": link_id,
                "ttl_before": ttl_before,
                "ttl_after": ttl,
                "decision": "forward",
            }
        )
        reached.append(path[pos + 1])

    return {
        "status": status,
        "packet_id": packet["id"],
        "source": source_id,
        "destination": destination_id,
        "path": reached,
        "hops": hops,
        "final_node": reached[-1],
        "ttl_remaining": ttl,
        "reason": reason,
    }


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
        help="trace a packet hop by hop from source to destination",
        description="Trace a packet hop by hop from source to destination.",
        epilog=TRACE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    trace_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="path to the UTF-8 JSON tracing document",
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
            packet = validate_packet(document["packet"])
            output = trace_packet(node_ids, links, source, destination, packet)
        else:
            node_ids, links, source, destination = validate(
                document, ROOT_FIELDS
            )
            result = find_route(node_ids, links, source, destination)
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
    except (ConfigError, ParameterError, PacketError) as exc:
        write_json_line(
            sys.stderr, {"error": exc.error, "message": str(exc)}
        )
        return exc.exit_code

    write_json_line(sys.stdout, output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
