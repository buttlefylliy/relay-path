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

在 `ecmp-trace` 的根字段之外仅增加 `weights`（对象）：键为已声明的链路 id，值为 1 到 65535 的整数，布尔值不得冒充整数；未列出的链路权重为 1。未知链路键或非法权重输出 `ConfigError`（退出码 3）。拓扑、端点、报文与全部权重完整校验后才开始追踪；`ParameterError`（2）、`PacketError`（4）与错误时标准输出为空的规则不变。

候选集与 `ecmp-trace` 完全相同：仅 `up` 且满足 `dist[u] == cost + dist[v]`（反向 Dijkstra）的出链参与，按（目标节点 id、链路 id）Unicode 码点序排列；权重只控制等价候选之间的选择，不会让不同总代价的路径进入候选。逐跳计算与 `ecmp-trace` 相同的 SHA-256 摘要（`packet.id` UTF-8 字节、零字节、当前节点 id UTF-8 字节）并解释为大端无符号整数，对候选权重总和取模；以从零开始的累计权重区间（候选 i 拥有 `[此前累计, 此前累计 + w_i)`）确定唯一候选，不按权重展开数组。空 `weights` 产生与 `ecmp-trace` 相同的路径。总权重为候选权重的精确整数和，不依赖平台；时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

TTL、立即送达、`no_route`、`ttl_exhausted`、节点数减一跳上限与 `ecmp-trace` 一致。成功时标准输出沿用相同的一行紧凑 JSON 顶层键序；每个 hop 的键依次为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `weighted_ecmp_hash`）、`candidate_count`、`selected_index`、`selected_weight`、`total_weight`、`selected_value`，后三个数分别记录所选链路权重、候选权重总和与取模结果，使选择可复核。成功或业务丢弃时标准错误为空，同一输入多次执行逐字节一致。

### `sticky-ecmp-trace --input PATH`

根字段与 `ecmp-trace` 相同（`nodes`、`links`、`source`、`destination`、`packet` 五个字段，拒绝其他字段），但 `packet` 在既有四个字段之外必须增加 `flow_id`：非空字符串且不超过 128 个 Unicode 码点。字段缺失、额外字段或取值非法均输出 `PacketError`（退出码 4），标准输出为空；拓扑、端点和报文完整校验后才开始追踪。既有命令仍只接受各自原有结构（`trace`、`ecmp-trace`、`weighted-ecmp-trace` 的 packet 含 `flow_id` 会被拒绝）。

候选集与排序沿用 `ecmp-trace`：仅 `up` 且满足 `dist[u] == cost + dist[v]` 的出链，按（目标节点 id、链路 id）Unicode 码点序排列。每个候选的粘滞分数为 SHA-256，输入依次为 `flow_id`、当前节点 id、候选目标节点 id、链路 id 的 UTF-8 字节，各部分间插入一个零字节；摘要按大端无符号整数比较，选择分数最大者，摘要相同时选择排序靠前者。选择只取决于 `flow_id` 与候选集：`packet.id`、`priority`、`payload` 与输入数组顺序均不影响；候选不变时同一 `flow_id` 路径一致，删除未选候选不改变本跳，删除已选候选时在剩余候选中重选，新增候选仅在分数更高时接管。

TTL 衰减、到达时 ttl 为零仍送达、起终点相同时立即送达、`no_route` 与 `ttl_exhausted` 归因、节点数减一跳上限，以及 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4）和标准流规则均与 `ecmp-trace` 一致。成功时标准输出沿用相同的一行紧凑 JSON 顶层键序；每个 hop 的键依次为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `sticky_ecmp_hash`）、`candidate_count`、`selected_index`、`selected_score`，其中 `selected_score` 为获胜候选摘要的 64 个小写十六进制字符。相同输入逐字节一致，不读墙上时钟，不枚举完整路径，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

### `latency-trace --input PATH`

在 `trace` 的根字段之外仅增加 `clock_ms` 与 `latencies` 两个字段（根对象共七个字段，拒绝其他字段）。`clock_ms` 是 0 至 999999999999.999 的十进制毫秒字符串，最多三位小数；`latencies` 是对象，键为已声明的链路 id，值为 0 至 86400000.000 的十进制毫秒字符串，未列出的链路按 0.000 处理。时间字符串不接受指数、符号、空白和非有限值。未知链路键、非法时间、字段缺失或额外字段均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文、起始时间和全部时延完整校验后才开始计算。

报文仍沿 `trace` 的确定性最小代价路径转发，路径、TTL 与丢弃归因不因时延改变。时间以千分之一毫秒精确累加，不读墙上时钟：首跳离开时间为 `clock_ms`，后续离开时间为上一跳到达时间，到达时间为离开时间加本链路时延。立即送达、`no_route` 或首节点 `ttl_exhausted` 的完成时间等于开始时间；中途 `ttl_exhausted` 的完成时间等于最后一跳的到达时间。跳数上限仍为节点数减一，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

成功时标准输出沿用 `trace` 的顶层键序，并在 `reason` 后依次增加 `started_at_ms`、`finished_at_ms`；每个 hop 在既有键后依次增加 `departed_at_ms`、`latency_ms`、`arrived_at_ms`。所有时间输出统一补足三位小数，相同输入逐字节一致。既有五个命令的输入、输出、错误和键序保持不变。

### `bandwidth-trace --input PATH`

完全沿用 `latency-trace` 的拓扑、端点、`packet`、`clock_ms` 与 `latencies` 语义，仅增加 `bandwidths` 根字段（根对象共八个字段，拒绝其他字段）。`bandwidths` 是对象，为每条已声明链路给出每秒比特数：键必须恰好覆盖全部链路且不重复，值只能是 1 到 1000000000000 的 JSON 整数，布尔值不得冒充整数。缺少链路、未知链路、重复 JSON 键或越界值均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文、起始时间、全部时延与全部带宽完整校验后才开始计算。

报文仍沿 `trace` 的确定性最小代价路径转发，带宽和时延都不参与选路，路径、TTL 与丢弃归因不变。每一跳只按 `packet.payload` 的 UTF-8 字节数计算串行化时间，不计协议头；以千分之一毫秒为内部单位，按 `ceil(字节数 × 8 × 1000000 ÷ bandwidth_bps)` 用整数运算取整，空载荷结果为零。时间以千分之一毫秒精确累加，不读墙上时钟、不使用浮点数：首跳离开时间为 `clock_ms`（沿用 `latency-trace`），本跳抵达时刻等于离开时刻加串行化时间再加该链路传播时延，下一跳在此前一跳抵达后离开。立即送达、`no_route` 或首节点 `ttl_exhausted` 的完成时间等于开始时间；中途 `ttl_exhausted` 的完成时间等于最后一跳的抵达时间。跳数上限仍为节点数减一，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。

成功或业务丢弃时输出一行紧凑 JSON，顶层字段及顺序与 `latency-trace` 相同（`status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`、`started_at_ms`、`finished_at_ms`）；每个 hop 在 `decision` 后依次输出 `departed_at_ms`、`bandwidth_bps`、`serialization_ms`、`latency_ms`、`arrived_at_ms`。所有时间字符串固定三位小数，`bandwidth_bps` 保持整数，使每跳时间可独立复核。同一输入逐字节一致。既有七个命令的输入、输出、异常和帮助行为保持不变。

### `loss-trace --input PATH`

在 `trace` 的根字段之外仅增加 `loss_rates` 一个字段（根对象共六个字段，拒绝其他字段）。`loss_rates` 是对象，键为已声明的链路 id，值为 `0.000000` 至 `1.000000` 且恰有六位小数的十进制字符串；未列出的链路按 `0.000000` 处理。未知链路键、非字符串值、格式错误或越界均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文和全部丢包率完整校验后才开始追踪。

报文仍沿 `trace` 的确定性最小代价路径转发，丢包率不改变选路。每次尝试链路前，顺序拼接 `packet.id` 的 UTF-8 字节、一个零字节、链路 id 的 UTF-8 字节、一个零字节和从零开始的跳序号十进制 ASCII 字节，计算 SHA-256，取摘要前八字节作为大端无符号整数 `loss_value`；丢包率换算为百万分整数 `loss_units`，当 `loss_value × 1000000 < loss_units × 2^64` 时本次尝试丢失，否则到达下一节点。判定不使用随机数或墙上时钟，概率零永不丢、概率一总是丢。发送前 ttl 为零仍以 `ttl_exhausted` 在当前节点丢弃且不计算摘要；每次实际尝试消耗一次 ttl。丢失的尝试写入 `hops`，但不把目标节点加入 `path`，`final_node` 保持发送节点，状态为 `dropped`、`reason` 为 `link_loss`，随后停止。到达目的节点时 ttl 变为零仍算送达；`no_route`、起终点相同立即送达与节点数减一跳上限均沿用 `trace`。

成功时标准输出沿用 `trace` 的顶层键序；每个 hop 在前五个字段后依次写入 `decision`、`loss_rate`、`loss_value`：`decision` 成功为 `forward`、丢失为 `drop_loss`，`loss_rate` 固定六位小数，`loss_value` 为 16 个小写十六进制字符。同一输入的输出逐字节一致，输入数组顺序不影响既有选路，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)，最多记录节点数减一条尝试。既有六个命令的输入、输出、错误和键序保持不变。

### `queue-trace --input PATH`

在 `trace` 的根字段之外仅增加 `queue_capacities` 与 `queue_occupancies` 两个字段（根对象共七个字段，拒绝其他字段）。二者都是对象，键必须恰好覆盖全部已声明链路且不重复，值只能是 0 到 1000000000000 的 JSON 整数，布尔值不得冒充整数；同一链路的占用不得超过容量。字段缺失、额外字段、未知链路键、值非法或占用超限均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文和全部队列字段完整校验后才开始追踪。

报文仍沿 `trace` 的确定性最小代价路径转发，队列不参与选路。`queue_occupancies` 表示每次尝试前该链路已排队的字节数，各链路是相互独立的快照，不读墙上时钟、不在链路间保存状态。每跳先沿用 `no_route` 与 `ttl_exhausted` 判定；尝试链路时以 `packet.payload` 的 UTF-8 字节数为 `packet_bytes`（空载荷为零字节）。若占用与报文字节之和不超过容量则准入：以该和为新占用，报文到达下一节点并消耗一次 ttl，恰好占满也成功；否则立即尾丢弃：不到达下一节点、不消耗 ttl、占用不变。起终点相同立即送达且不检查队列；无路可达仍在源节点以 `no_route` 丢弃。最多记录节点数减一条成功跳转及一次拒绝尝试。

成功或业务丢弃时输出一行紧凑 JSON，顶层键序与 `trace` 相同（`status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`）；每个 hop 在既有五个字段后依次写入 `decision`、`capacity_bytes`、`queued_bytes_before`、`packet_bytes`、`queued_bytes_after`，`decision` 准入为 `enqueue`、拒绝为 `drop_tail`。拒绝的尝试仍写入 `hops`，但目标节点不加入 `path`，`final_node` 保持发送节点，`ttl_after` 等于 `ttl_before`，状态为 `dropped`、`reason` 为 `queue_tail_drop`。同一输入逐字节一致，时间上界 O((N+M)log(N+M))，额外内存 O(N+M)。既有七个命令的输入、输出、错误和键序保持不变。

### `priority-queue-trace --input PATH`

在 `trace` 的根字段之外增加 `queue_capacities`、`queue_occupancies` 与 `service_budgets` 三个字段（根对象共八个字段，拒绝其他字段）。三个对象的键都必须恰好覆盖全部已声明链路且不重复：`queue_capacities` 与 `service_budgets` 的值只能是 0 到 1000000000000 的 JSON 整数；`queue_occupancies` 的值是恰好八项的数组，每项为同范围 JSON 整数，下标对应优先级 0 至 7，且同一链路八项之和不得超过其容量。布尔值不得冒充整数。字段缺失、额外字段、未知链路键、值非法或占用超限均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文和全部队列字段完整校验后才开始追踪。

报文仍沿 `trace` 的确定性最小代价路径转发，队列与预算不参与选路。各链路占用是相互独立的快照，不读墙上时钟、不在链路间保存状态。每跳先沿用 `no_route` 与 `ttl_exhausted` 判定；尝试链路时先用该链路预算服务已有字节：从优先级 7 到 0 逐级扣减，每级取占用与剩余预算的较小值，未用预算舍弃，当前报文不参与服务。随后以 `packet.payload` 的 UTF-8 字节数为 `packet_bytes`（空载荷为零字节）加入 `packet.priority` 对应级别：若服务后总占用加报文字节不超过容量则准入，报文到达下一节点并消耗一次 ttl，恰好占满也成功；否则立即尾丢弃：不到达下一节点、不消耗 ttl、队列只保留服务结果。起终点相同立即送达且不检查队列；无路可达仍在源节点以 `no_route` 丢弃。最多记录节点数减一条成功跳转及一次拒绝尝试。

成功或业务丢弃时输出一行紧凑 JSON，顶层键序与 `trace` 相同（`status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`）；每个 hop 在既有五个字段后依次写入 `decision`、`capacity_bytes`、`service_budget_bytes`、`queue_before`、`serviced`、`packet_priority`、`packet_bytes`、`queue_after`，其中 `queue_before`、`serviced`、`queue_after` 均为固定八项数组（下标为优先级 0 至 7）。`decision` 准入为 `priority_enqueue`、拒绝为 `drop_priority_tail`；准入时 `queue_after` 包含新报文，拒绝时 `queue_after` 只反映服务结果。拒绝的尝试仍写入 `hops`，但目标节点不加入 `path`，`final_node` 保持发送节点，`ttl_after` 等于 `ttl_before`，状态为 `dropped`、`reason` 为 `queue_priority_tail_drop`。同一输入逐字节一致，设实际跳数为 H，时间上界 O((N+M)log(N+M)+8H)，额外内存 O(N+M+8H)。既有十四个命令的输入、输出、错误和键序保持不变。

### `event-trace --input PATH`

在 `trace` 的根字段之外仅增加 `clock_ms` 与 `events` 两个字段（根对象共七个字段，拒绝其他字段）。`clock_ms` 沿用 `latency-trace` 的规则：0 至 999999999999.999 的十进制毫秒字符串，最多三位小数，不接受指数、符号、空白和非有限值。`events` 是最多 100000 项的数组，每项只含 `at_ms`（与 `clock_ms` 同规则同范围的毫秒字符串）、`link`（必须引用已声明链路）、`up`（必须是 JSON 布尔值）；事件按 `at_ms` 非递减排列，同一时刻按数组顺序应用，允许对同一链路重复设置及随后恢复。时钟或事件的结构、顺序、引用、数量非法均输出 `ConfigError`（退出码 3），标准输出为空；拓扑、端点、报文错误仍为 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4）。拓扑、端点、报文、时钟和全部事件完整校验后才开始计算。

各链路从声明的初始 `up` 状态开始，只应用 `at_ms` 小于或等于 `clock_ms` 的事件，晚于查询时刻的合法事件不生效。随后在查询时刻的有效拓扑上沿用 `trace` 的最小代价选路、平局处理、TTL 衰减、立即送达、`no_route` 与 `ttl_exhausted` 语义：故障链路不参与选路，应用事件不消耗 ttl，不读墙上时钟。跳数上限仍为节点数减一，处理 E 个事件的额外时间和内存均为 O(E)，总时间上界 O(E+(N+M)log(N+M))。

成功或业务丢弃时输出一行紧凑 JSON，顶层键依次为 `status`、`packet_id`、`source`、`destination`、`clock_ms`、`applied_events`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`。`clock_ms` 与事件时间统一补足三位小数；`applied_events` 只列实际应用的事件并保持输入顺序，每项键依次为 `at_ms`、`link`、`up`；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `event_route`）。同一输入逐字节一致。既有八个命令的输入、输出、错误和键序保持不变。

### `damped-event-trace --input PATH`

在 `event-trace` 的根字段之外仅增加 `hold_down_ms` 一个字段（根对象共八个字段，拒绝其他字段）。`clock_ms` 与 `events` 沿用 `event-trace` 的全部规则；`hold_down_ms` 是 0 至 86400000.000 的十进制毫秒字符串，格式与 `clock_ms` 相同（最多三位小数，不接受指数、符号、空白和非有限值）。根字段错误、非法时间、事件乱序或未知链路均输出 `ConfigError`（退出码 3），标准输出为空；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4）。拓扑、端点、报文、时钟、稳定等待期和全部事件完整校验后才开始计算。

回放只观察 `at_ms` 不晚于 `clock_ms` 的事件，更晚的事件不生效也不影响此前事件。各链路从声明的初始 `up` 状态开始；同一链路的事件在 `at_ms` 加 `hold_down_ms` 后生效，若输入中更晚的同链路事件早于该生效时刻到达，前一事件被抑制而永不生效，后一事件重新等待自己的稳定期，即使 `up` 值相同也重新等待；后续事件恰好位于前一事件生效时刻时不抑制前者，同一时刻的事件按输入顺序处理。`hold_down_ms` 为零时全部已到达事件立即按原顺序生效，行为与 `event-trace` 一致。随后在查询时刻的有效拓扑上沿用 `trace` 的确定性最小代价选路、平局处理、TTL 衰减、立即送达、`no_route` 与 `ttl_exhausted` 语义：故障链路不参与选路，应用事件不消耗 ttl，不读墙上时钟。跳数上限仍为节点数减一，处理 E 个事件的额外时间和内存均为 O(E)，总时间上界 O(E+(N+M)log(N+M))。

成功或业务丢弃时输出一行紧凑 JSON，顶层键依次为 `status`、`packet_id`、`source`、`destination`、`clock_ms`、`hold_down_ms`、`effective_events`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`。`clock_ms`、`hold_down_ms` 与事件时间统一补足三位小数；`effective_events` 只列真正生效的事件并按生效顺序排列，每项键依次为 `at_ms`、`effective_at_ms`、`link`、`up`，生效值与当前状态相同也记录；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `damped_event_route`）。同一输入逐字节一致。既有九个命令的输入、输出、错误和键序保持不变。

### `node-event-trace --input PATH`

在 `trace` 的根字段之外仅增加 `clock_ms` 与 `events` 两个字段（根对象共七个字段，拒绝其他字段）。`clock_ms` 沿用 `latency-trace` 的规则：0 至 999999999999.999 的十进制毫秒字符串，最多三位小数，不接受指数、符号、空白和非有限值。`events` 是最多 100000 项的数组，每项只含 `at_ms`（与 `clock_ms` 同规则同范围的毫秒字符串）、`node`（必须引用已声明节点）、`up`（必须是 JSON 布尔值）；事件按 `at_ms` 非递减排列，同一时刻按数组顺序应用，允许对同一节点重复设置及随后恢复。时钟或事件的结构、顺序、引用、数量非法均输出 `ConfigError`（退出码 3），标准输出为空；拓扑、端点、报文错误仍为 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4）。拓扑、端点、报文、时钟和全部事件完整校验后才开始计算。

各节点初始均可用，只应用 `at_ms` 小于或等于 `clock_ms` 的事件，晚于查询时刻的合法事件不生效。不可用节点的全部入链和出链均不参与选路；节点恢复后，其链路仍遵循拓扑声明的 `up` 状态。随后在查询时刻的有效拓扑上沿用 `trace` 的确定性最小代价选路、平局处理、TTL 衰减、立即送达、`no_route` 与 `ttl_exhausted` 语义；应用事件不消耗 ttl，不读墙上时钟。查询时刻 source 或 destination 不可用时，报文在 source 以 `node_down` 丢弃：`path` 仅含 source、`hops` 为空、`final_node` 为 source 且 ttl 不变；起终点相同时也优先返回 `node_down`。跳数上限仍为节点数减一，处理 E 个事件的额外时间和内存均为 O(E)，总时间上界 O(E+(N+M)log(N+M))。

成功或业务丢弃时输出一行紧凑 JSON，顶层键依次为 `status`、`packet_id`、`source`、`destination`、`clock_ms`、`applied_events`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`。`clock_ms` 与事件时间统一补足三位小数；`applied_events` 只列实际应用的事件并保持输入顺序，每项键依次为 `at_ms`、`node`、`up`；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `node_event_route`）。同一输入逐字节一致。既有十个命令的输入、输出、错误和键序保持不变。

### `topology-event-trace --input PATH`

在 `trace` 的根字段之外仅增加 `clock_ms` 与 `events` 两个字段（根对象共七个字段，拒绝其他字段）。`clock_ms` 沿用 `latency-trace` 的规则：0 至 999999999999.999 的十进制毫秒字符串，最多三位小数，不接受指数、符号、空白和非有限值。`events` 是最多 100000 项的数组，每项只含 `at_ms`（与 `clock_ms` 同规则同范围的毫秒字符串）、`target_type`（只能为 JSON 字符串 `link` 或 `node`）、`target`（字符串；`target_type` 为 `link` 时必须引用已声明链路，为 `node` 时必须引用已声明节点）、`up`（必须是 JSON 布尔值）；事件按 `at_ms` 非递减排列，同一时刻按数组顺序处理，允许对同一目标重复设置及随后恢复。时钟或事件的结构、次序、类型、时间、引用或数量非法均输出 `ConfigError`（退出码 3），标准输出为空；拓扑、端点、报文错误仍为 `ConfigError`（3）、`ParameterError`（2）、`PacketError`（4）。拓扑、端点、报文、时钟和全部事件完整校验后才开始计算。

各节点初始均可用，各链路从声明的初始 `up` 状态开始；只处理 `at_ms` 小于或等于 `clock_ms` 的事件，晚于查询时刻的合法事件不生效，已到达事件按数组顺序依次覆盖对应状态。节点事件只设置节点可用性，链路事件只覆盖链路自身状态：节点不可用时其全部入链和出链均不参与选路，但不改写链路状态；节点恢复后，链路仍服从最后一次链路事件（无则为声明的初始 `up`）。查询时刻 source 或 destination 不可用时，报文在 source 以 `node_down` 丢弃：`path` 仅含 source、`hops` 为空、`final_node` 为 source 且 ttl 不变；该判定优先于 source 等于 destination。否则在查询时刻的有效拓扑上沿用 `trace` 的最小代价选路、平局处理、TTL 衰减、立即送达、`no_route` 与 `ttl_exhausted` 语义；处理事件不消耗 ttl，不读墙上时钟。跳数上限仍为节点数减一，处理 E 个事件的额外时间和内存均为 O(E)，总时间上界 O(E+(N+M)log(N+M))。

成功或业务丢弃时输出一行紧凑 JSON，顶层键依次为 `status`、`packet_id`、`source`、`destination`、`clock_ms`、`applied_events`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`。`clock_ms` 与事件时间统一补足三位小数；`applied_events` 只含已生效事件且顺序不变，每项键依次为 `at_ms`、`target_type`、`target`、`up`；每个 hop 的键序为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `topology_event_route`）。同一输入逐字节一致。既有十一个命令的输入、输出、错误和键序保持不变。

### `fragment-trace --input PATH`

在 `trace` 的根字段之外仅增加 `mtus` 一个字段（根对象共六个字段，拒绝其他字段）。`mtus` 是对象，键必须恰好覆盖全部已声明链路且不重复，值只能是 1 到 65536 的 JSON 整数，布尔值不得充当整数。缺少链路、未知链路、重复 JSON 键或越界值均输出 `ConfigError`（退出码 3）；端点与报文错误仍为 `ParameterError`（2）与 `PacketError`（4），错误时标准输出为空。拓扑、端点、报文与全部 MTU 完整校验后才开始追踪，MTU 不参与选路。

报文仍沿 `trace` 的确定性最小代价路径逐跳转发，路径、TTL 与丢弃归因不因 MTU 改变。每次成功离开节点前，把 `packet.payload` 的 UTF-8 字节序列视为已重组的完整载荷，再按所选链路 MTU 从前到后切片：除最后一片外均为 MTU 字节，最后一片承载余数，字节数恰好整除时最后一片也是 MTU 字节，空载荷固定为一个长度为零的空分片。不输出或解码分片内容，允许在多字节字符内部切分。分片不额外消耗 TTL，也不改变路径；到下一节点后重新组装，后续链路再按自身 MTU 分片。TTL 为零、无路可达、起终点相同和到达时 TTL 恰为零的处理沿用 `trace`，未尝试链路（立即送达、`no_route`、`ttl_exhausted`）不产生分片记录。

成功或业务丢弃时输出一行紧凑 JSON，顶层字段及顺序与 `trace` 相同（`status`、`packet_id`、`source`、`destination`、`path`、`hops`、`final_node`、`ttl_remaining`、`reason`）；每个实际跳的字段依次为 `from`、`to`、`link`、`ttl_before`、`ttl_after`、`decision`（固定 `fragment_forward`）、`mtu_bytes`、`payload_bytes`、`fragment_count`、`last_fragment_bytes`，其中前 `fragment_count` 减一片的长度均等于 `mtu_bytes`，最后一片长度由 `last_fragment_bytes` 给出。相同输入逐字节一致，不读墙上时钟；设实际跳数为 H、载荷字节数为 P，时间上界为 O((N+M)log(N+M)+P+H)，额外内存为 O(N+M+P+H)，不按分片数展开输出。既有十二个命令的输入、输出、错误分类、退出码和帮助行为保持不变。

## 状态

仓库初始为空，功能按增量需求持续构建。
