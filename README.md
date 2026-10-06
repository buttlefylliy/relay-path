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

输入与 `trace` 完全相同（`nodes`、`links`、`source`、`destination`、`packet` 五个字段，packet 约束与校验顺序不变）；既有 `route`、`trace` 的输入、输出与错误语义保持不变。每个节点仅把 `up` 且能够进入「从当前节点到 destination 的最小总代价路径」的出链作为候选；代价不同的备选不得参与，平行链路各占一个候选位置。候选按（目标节点 id、链路 id）的 Unicode 码点序排列。

逐跳将 `packet.id` 的 UTF-8 字节、一个零字节、当前节点 id 的 UTF-8 字节依次拼接后计算 SHA-256，摘要解释为大端无符号整数后对候选数取模，结果为从零开始的选中下标；`priority`、`payload` 与输入数组顺序均不影响选择。不枚举任何完整等价路径（在反向图上以 destination 为起点做一次 Dijkstra，满足 `dist[u] == cost + dist[v]` 的 up 出链即候选），时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

TTL 与丢弃语义与 `trace` 一致：离开节点前 ttl 须大于零；到达 destination 时 ttl 恰减为零仍算送达；转发前 ttl 为零在当前节点以 `ttl_exhausted` 丢弃；无路时在 source 以 `no_route` 丢弃且不经过链路；source 等于 destination 直接送达，不计算候选也不消耗 ttl；单次调用最多输出节点数减一跳。错误分类仍为 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4），错误时标准输出为空，成功或业务丢弃时标准错误为空，全部校验完成后才生成结果。

成功时标准输出沿用 `trace` 的一行紧凑 JSON 顶层键序（`status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`）；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `ecmp_hash`）、`candidate_count`、`selected_index`，后两项记录本跳候选数与哈希选中的下标。

### `weighted-ecmp-trace --input PATH`

输入在 `trace` 的五个字段之外额外且仅额外接受 `weights`（共六个字段，拓扑与 packet 约束及校验顺序不变）。`weights` 必须是对象：键为已声明的链路 id，值为 1–65535 的整数（布尔值不得冒充整数）；未列出的链路权重为 1。未知链路 id 或非法权重按 `ConfigError`（退出码 3）处理，错误时标准输出为空；拓扑、端点、报文与全部权重完整校验通过后才开始追踪。

每个节点的候选集与 `ecmp-trace` 完全一致：仅 `up` 且能进入「从当前节点到 destination 的最小总代价路径」的出链，权重不会让非等价路径进入候选集；平行链路各占一个候选位置，候选按（目标节点 id、链路 id）的 Unicode 码点序排列。逐跳计算与 `ecmp-trace` 相同的 SHA-256 摘要（`packet.id` UTF-8 字节、一个零字节、当前节点 id UTF-8 字节），解释为大端无符号整数后对候选权重总和取模，再按候选顺序的从零开始累计权重区间确定唯一候选；不按权重展开数组。空 `weights`（`{}`）产生与 `ecmp-trace` 相同的路径。不枚举完整等价路径，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)，同一输入多次执行逐字节一致。

TTL 与丢弃语义与 `ecmp-trace` 一致：离开节点前 ttl 须大于零；到达 destination 时 ttl 恰减为零仍算送达；转发前 ttl 为零在当前节点以 `ttl_exhausted` 丢弃；无路时在 source 以 `no_route` 丢弃且不经过链路；source 等于 destination 直接送达，不计算候选也不消耗 ttl；单次调用最多输出节点数减一跳。错误分类仍为 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4），错误时标准输出为空，成功或业务丢弃时标准错误为空。

成功时标准输出沿用 `trace` 的一行紧凑 JSON 顶层键序；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `weighted_ecmp_hash`）、`candidate_count`、`selected_index`、`selected_weight`、`total_weight`、`selected_value`，后三项分别记录所选链路的权重、候选权重总和与取模结果，使选择可复核。

## 状态

仓库初始为空，功能按增量需求持续构建。
