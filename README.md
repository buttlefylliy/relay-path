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

* `route --input PATH`：静态最小代价选路，输出 status/source/destination/path/links/total_cost。
* `trace --input PATH`：在 route 的拓扑字段之外要求 `packet` 对象（恰好含 id、ttl、priority、payload；
  id 为 1–128 码点的字符串，ttl 为 0–255 整数，priority 为 0–7 整数，payload 为 UTF-8 编码后
  不超过 65536 字节的字符串，布尔不得冒充整数）。报文沿 route 的确定性最小代价路径逐跳转发：
  离开节点前 ttl 须大于零，每条链路减一，到达 destination 时 ttl 归零仍算送达；ttl 耗尽在当前
  节点以 ttl_exhausted 丢弃，无可达路径在 source 以 no_route 丢弃，source 等于 destination
  直接送达。跳数上限为节点数减一。成功输出一行紧凑 JSON，键序为 status、packet_id、source、
  destination、path、hops、final_node、ttl_remaining、reason；hop 键序为 from、to、link、
  ttl_before、ttl_after、decision。
* 退出码：ParameterError=2，ConfigError=3，PacketError=4；出错时标准输出为空。

## 状态

仓库初始为空，功能按增量需求持续构建。
