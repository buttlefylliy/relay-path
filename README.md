# relay-path

跨跳中继决策的解码、归因与路径追踪。

## 约束

* 仅使用 Python 标准库，不联网，不依赖第三方包。
* 行为必须确定：相同输入多次运行产生逐字节一致的输出；时间相关行为由显式注入的时钟驱动，不读墙上时钟。
* 所有结论可由公开接口与落盘产物独立验收。

## 公开入口

* 入口文件：`relay_path.py` 
* 命令行：`python relay_path.py --help` 
* 使用说明与行为契约以本文件为准；入口的签名、键序与既有语义在迭代中保持兼容。

## 命令

### `route --input PATH`

读取 UTF-8 JSON 拓扑文档（`nodes`、`links`、`source`、`destination`，拒绝其他字段），输出静态最小代价选路的一行紧凑 JSON。错误分类：`ConfigError`（退出码 3）、`ParameterError`（退出码 2）。

### `trace --input PATH`

在 route 的根字段之外增加 `packet`，拓扑约束与 route 完全一致。`packet` 仅含 `id`（非空、不超过 128 个 Unicode 码点）、`ttl`（整数 0–255）、`priority`（整数 0–7）、`payload`（UTF-8 编码后不超过 65536 字节）；布尔值不得冒充整数。packet 非法时标准错误输出 `PacketError`（键序 error、message），退出码 4，标准输出为空；全部校验完成后才开始追踪。

报文沿 route 的确定性最小代价路径逐跳转发：离开节点前 ttl 须大于零，每条链路后减一；到达 destination 时 ttl 为零仍算送达。转发前 ttl 为零在当前节点以 `ttl_exhausted` 丢弃；无可达路径时在 source 以 `no_route` 丢弃且不经过链路；source 等于 destination 直接送达且不消耗 ttl。跳数上限为节点数减一。

成功时标准输出一行紧凑 JSON，键序为 `status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `forward`）。送达时 `reason` 为 null，标准错误为空。

### `ecmp-trace --input PATH`

输入与 `trace` 完全相同（同样的拓扑根字段与 `packet` 字段、数量上限与完整校验顺序）；报文与错误语义（`ConfigError` 退出码 3、`ParameterError` 退出码 2、`PacketError` 退出码 4，错误时标准输出为空、成功或业务丢弃时标准错误为空，全部校验完成后才追踪）也与 `trace` 一致。

在每个节点，候选出链是 up 且能进入从当前节点到 destination 的最小总代价路径的出链：在反向图上从 destination 做一次 Dijkstra 得到各节点到终点的最小代价 `dist`，出链 `u→v`（代价 c）成为候选当且仅当 `dist[u] == c + dist[v]`；不同总代价的备选不参与，正代价保证每跳严格降距从而不会成环。平行链路各占一个候选位置；候选按（目标节点 id、链路 id）的 Unicode 码点序排列。不枚举任何完整路径。

每跳将 `packet.id` 的 UTF-8 字节、一个零字节、当前节点 id 的 UTF-8 字节依次拼接后计算 SHA-256，摘要作为大端无符号整数对候选数取模，得到从零开始的选中下标；`priority`、`payload` 与输入数组顺序不影响选择。

输出沿用 trace 的顶层字段与固定键序；每个实际 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`、`candidate_count`、`selected_index`，其中 `decision` 固定为 `ecmp_hash`，后两项记录本跳候选数与选中下标。source 等于 destination 时直接送达、不计算候选也不消耗 ttl；无路在 source 以 `no_route` 丢弃；转发前 ttl 为零在当前节点以 `ttl_exhausted` 丢弃，到达 destination 时 ttl 恰减为零仍算送达。单次调用最多节点数减一跳；时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

## 状态

仓库初始为空，功能按增量需求持续构建。
