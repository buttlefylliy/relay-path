#!/usr/bin/env python3
"""relay_path - 静态最小代价选路命令行工具。"""

import argparse
import heapq
import json
import sys

MAX_NODES = 10000
MAX_LINKS = 50000
NODE_TYPES = ("relay", "terminal", "pseudo")
ROOT_FIELDS = ("nodes", "links", "source", "destination")

DESCRIPTION = """\
静态最小代价中继选路（逐跳转发基础）。

用法:
  python relay_path.py route --input PATH

输入为 UTF-8 编码的单个 JSON 对象，顶层字段固定为
nodes、links、source、destination，字段集合不得增减:
  nodes:       数组，每个元素为 {"id": ..., "type": ...}；
               id 为唯一的非空字符串，type 取值为
               relay、terminal、pseudo 之一。
  links:       数组，每个元素为 {"id", "from", "to", "cost", "up"}；
               id 唯一，from/to 为已声明节点的 id，链路为有向边；
               cost 为正整数，up 为布尔值（true/false，不接受 0/1）。
  source:      查询起点，必须是已声明的节点 id。
  destination: 查询终点，必须是已声明的节点 id。

规模限制:
  节点最多 10000 个，链路最多 50000 条。

选路规则:
  仅使用 up 为 true 的链路，按 cost 总和最小选择完整路径；
  总成本相同依次按节点 id 序列、链路 id 序列的 Unicode
  码点字典序取较小者；结果与数组在输入中的排列顺序无关。
  起点与终点相同且节点存在时，返回单节点路径与零成本。

输出 (stdout，单行紧凑 JSON，以换行结束，键序固定):
  status, source, destination, path, links, total_cost
  可达:   status="found"，path/links 按经过顺序记录，total_cost 为整数；
  不可达: status="unreachable"，path/links 为 []，total_cost 为 null。

错误 (stderr，单行 JSON，键序 error、message):
  ConfigError，退出码 3: 文件不可读、UTF-8/JSON 无效、结构或类型错误、
                         重复 id、悬空端点、cost 非正、整数冒充布尔值、超限；
  ParameterError，退出码 2: source/destination 端点未声明。
"""


def _fail(kind, message, code):
    payload = json.dumps(
        {"error": kind, "message": message},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    sys.stderr.write(payload + "\n")
    raise SystemExit(code)


def config_error(message):
    _fail("ConfigError", message, 3)


def parameter_error(message):
    _fail("ParameterError", message, 2)


def load_document(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        config_error("cannot read input file")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        config_error("input is not valid UTF-8 text")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        config_error("input is not valid JSON")
    return document


def _is_real_int(value):
    # bool 是 int 的子类，必须显式排除。
    return type(value) is int


def validate(document):
    """完成全部解析与校验，返回 (node_ids, edges, source, destination)。

    多个问题按顶层字段 nodes、links、source、destination 的顺序、
    再按数组位置报告首个；校验全部通过前不进行任何选路计算。
    """
    if not isinstance(document, dict):
        config_error("root value must be a JSON object")

    unexpected = sorted(key for key in document if key not in ROOT_FIELDS)
    if unexpected:
        config_error("unexpected field '%s'" % unexpected[0])

    # ---- nodes ----
    if "nodes" not in document:
        config_error("missing field 'nodes'")
    raw_nodes = document["nodes"]
    if not isinstance(raw_nodes, list):
        config_error("field 'nodes' must be an array")
    if len(raw_nodes) > MAX_NODES:
        config_error("too many nodes: at most %d allowed" % MAX_NODES)

    node_ids = set()
    for index, element in enumerate(raw_nodes):
        where = "node at index %d" % index
        if not isinstance(element, dict):
            config_error("%s must be an object" % where)

        if "id" not in element:
            config_error("%s: missing field 'id'" % where)
        node_id = element["id"]
        if not isinstance(node_id, str):
            config_error("%s: field 'id' must be a string" % where)
        if node_id == "":
            config_error("%s: field 'id' must be a non-empty string" % where)
        if node_id in node_ids:
            config_error("%s: duplicate node id" % where)

        if "type" not in element:
            config_error("%s: missing field 'type'" % where)
        node_type = element["type"]
        if not isinstance(node_type, str) or node_type not in NODE_TYPES:
            config_error(
                "%s: field 'type' must be one of %s"
                % (where, ", ".join(NODE_TYPES))
            )

        extra = sorted(key for key in element if key not in ("id", "type"))
        if extra:
            config_error("%s: unexpected field '%s'" % (where, extra[0]))

        node_ids.add(node_id)

    # ---- links ----
    if "links" not in document:
        config_error("missing field 'links'")
    raw_links = document["links"]
    if not isinstance(raw_links, list):
        config_error("field 'links' must be an array")
    if len(raw_links) > MAX_LINKS:
        config_error("too many links: at most %d allowed" % MAX_LINKS)

    link_ids = set()
    edges = []
    for index, element in enumerate(raw_links):
        where = "link at index %d" % index
        if not isinstance(element, dict):
            config_error("%s must be an object" % where)

        for field in ("id", "from", "to"):
            if field not in element:
                config_error("%s: missing field '%s'" % (where, field))
            if not isinstance(element[field], str):
                config_error("%s: field '%s' must be a string" % (where, field))
        link_id = element["id"]
        sender = element["from"]
        target = element["to"]

        if "cost" not in element:
            config_error("%s: missing field 'cost'" % where)
        cost = element["cost"]
        if not _is_real_int(cost):
            config_error("%s: field 'cost' must be an integer" % where)
        if cost <= 0:
            config_error("%s: field 'cost' must be a positive integer" % where)

        if "up" not in element:
            config_error("%s: missing field 'up'" % where)
        if type(element["up"]) is not bool:
            config_error("%s: field 'up' must be a boolean" % where)

        extra = sorted(
            key for key in element if key not in ("id", "from", "to", "cost", "up")
        )
        if extra:
            config_error("%s: unexpected field '%s'" % (where, extra[0]))

        if link_id in link_ids:
            config_error("%s: duplicate link id" % where)

        # 节点集合此时已完整确定，可在同一位置顺序内报告悬空端点。
        if sender not in node_ids:
            config_error(
                "%s: field 'from' refers to an undeclared node" % where
            )
        if target not in node_ids:
            config_error(
                "%s: field 'to' refers to an undeclared node" % where
            )

        link_ids.add(link_id)
        if element["up"]:
            edges.append((sender, target, link_id, cost))

    # ---- source / destination ----
    def endpoint(name):
        value = document.get(name, None)
        if not isinstance(value, str) or value not in node_ids:
            parameter_error("%s endpoint is not declared" % name)
        return value

    source = endpoint("source")
    destination = endpoint("destination")

    return node_ids, edges, source, destination


class Label(object):
    """最短路径 DAG 上某个节点已确定的最优序列标签。

    以持久化前缀链表示从 source 到本节点的节点/链路序列，
    anc[j] 为向上 2^j 步的祖先标签，供倍增爬升在 O(log V) 内
    定位序列位置与最低公共祖先（见 compare_extended）。
    """

    __slots__ = ("node_id", "pred", "link_id", "depth", "anc")

    def __init__(self, node_id, pred, link_id):
        self.node_id = node_id
        self.pred = pred
        self.link_id = link_id
        if pred is None:
            self.depth = 1
            self.anc = []
            return
        self.depth = pred.depth + 1
        ancestors = [pred]
        while True:
            level = len(ancestors)  # 正在求 anc[level] = 2^level 步祖先
            middle = ancestors[level - 1].anc
            if len(middle) >= level:
                ancestors.append(middle[level - 1])
            else:
                break
        self.anc = ancestors


def ancestor(label, steps):
    level = 0
    while steps:
        if steps & 1:
            label = label.anc[level]
        steps >>= 1
        level += 1
    return label


def lowest_common_ancestor(left, right):
    """两棵根链（所有标签同源于 source）的最低公共祖先，O(log V)。"""
    if left.depth < right.depth:
        left, right = right, left
    left = ancestor(left, left.depth - right.depth)
    if left is right:
        return left
    level = len(left.anc) - 1
    while level >= 0:
        up_left = left.anc[level] if level < len(left.anc) else None
        up_right = right.anc[level] if level < len(right.anc) else None
        if up_left is not None and up_left is not up_right:
            left, right = up_left, up_right
        level -= 1
    return left.pred


def compare_extended(left, right, node_id):
    """比较 left+[node_id] 与 right+[node_id] 的节点 id 序列字典序。

    候选序列来自不同前驱，其中一条前驱序列可能是另一条的真前缀
    （到 node_id 的最短路径无环，同终点序列之间不会互为前缀）；
    此时须用追加的 node_id 与较长序列的下一节点比较。利用标签树
    的 LCA 一次爬升定位首个分歧位置，比较为 O(log V)。
    """
    if left is right:
        return 0

    lca = lowest_common_ancestor(left, right)
    base_depth = lca.depth

    if base_depth == left.depth:  # left 是 right 的真前缀（或两序列相同）
        if base_depth == right.depth:
            return 0
        other = ancestor(right, right.depth - base_depth - 1).node_id
        return -1 if node_id < other else 1

    if base_depth == right.depth:  # right 是 left 的真前缀
        other = ancestor(left, left.depth - base_depth - 1).node_id
        return -1 if other < node_id else 1

    left_id = ancestor(left, left.depth - base_depth - 1).node_id
    right_id = ancestor(right, right.depth - base_depth - 1).node_id
    if left_id < right_id:
        return -1
    return 1 if left_id > right_id else 0


def route(node_ids, edges, source, destination):
    """返回 (path_nodes, path_links, total_cost)；不可达时 total_cost 为 None。"""
    adjacency = dict((node_id, []) for node_id in node_ids)
    for sender, target, link_id, cost in edges:
        adjacency[sender].append((target, link_id, cost))

    # 第一阶段：纯代价 Dijkstra，确定每个可达节点的最小代价。
    distance = {source: 0}
    heap = [(0, source)]
    while heap:
        current_cost, node = heapq.heappop(heap)
        if current_cost != distance.get(node):
            continue
        for target, _link_id, cost in adjacency[node]:
            candidate_cost = current_cost + cost
            if candidate_cost < distance.get(target, float("inf")):
                distance[target] = candidate_cost
                heapq.heappush(heap, (candidate_cost, target))

    if destination not in distance:
        return [], [], None

    # 第二阶段：在最短路径 DAG（边严格指向更大代价）上按代价升序确定标签。
    # 每个节点的选择只依赖更小代价节点的已定标签，彼此独立，与遍历顺序无关。
    incoming = dict((node_id, []) for node_id in node_ids)
    for sender, target, link_id, cost in edges:
        if sender in distance and distance[sender] + cost == distance[target]:
            incoming[target].append((sender, link_id))

    order = sorted(distance, key=lambda node_id: (distance[node_id], node_id))
    labels = {source: Label(source, None, None)}
    for node in order:
        if node == source:
            continue
        best_pred = None
        best_link = None
        for sender, link_id in incoming[node]:
            pred = labels[sender]
            if best_pred is None:
                best_pred, best_link = pred, link_id
                continue
            comparison = compare_extended(pred, best_pred, node)
            if comparison < 0 or (comparison == 0 and link_id < best_link):
                best_pred, best_link = pred, link_id
        labels[node] = Label(node, best_pred, best_link)

    path_nodes = []
    path_links = []
    label = labels[destination]
    total_cost = distance[destination]
    while label is not None:
        path_nodes.append(label.node_id)
        if label.link_id is not None:
            path_links.append(label.link_id)
        label = label.pred
    path_nodes.reverse()
    path_links.reverse()
    return path_nodes, path_links, total_cost


def write_result(source, destination, path_nodes, path_links, total_cost):
    if total_cost is None:
        result = {
            "status": "unreachable",
            "source": source,
            "destination": destination,
            "path": [],
            "links": [],
            "total_cost": None,
        }
    else:
        result = {
            "status": "found",
            "source": source,
            "destination": destination,
            "path": path_nodes,
            "links": path_links,
            "total_cost": total_cost,
        }
    sys.stdout.write(
        json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n"
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="relay_path.py",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    route_parser = subparsers.add_parser(
        "route",
        help="read a routing query JSON file and print the chosen path",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    route_parser.add_argument(
        "--input",
        required=True,
        metavar="PATH",
        help="UTF-8 JSON file containing nodes, links, source, destination",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "route":
        document = load_document(args.input)
        node_ids, edges, source, destination = validate(document)
        path_nodes, path_links, total_cost = route(
            node_ids, edges, source, destination
        )
        write_result(source, destination, path_nodes, path_links, total_cost)


if __name__ == "__main__":
    main()
