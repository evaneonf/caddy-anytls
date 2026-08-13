# 技术设计

## 设计目标

`caddy-anytls` 的首版实现需要满足以下技术约束：

- 复用 Caddy 的 `:443` 监听与自动 HTTPS 能力
- 在 TLS 握手完成后识别 AnyTLS 首包
- AnyTLS 命中时接管连接并完成认证与转发
- 非 AnyTLS 流量无损回落到现有网站链路

## 模块形态

当前实现采用 Caddy `listener_wrapper` 形态，模块 ID 为 `caddy.listeners.anytls`。

之所以不采用 HTTP handler，原因在于 AnyTLS 识别必须发生在 HTTP 解析之前。HTTP handler 只能处理已经被解释为 HTTP 请求的流量，无法覆盖非 HTTP 的 AnyTLS 首包探测场景。`listener_wrapper` 则可以直接接触 TLS 解密后的 `net.Conn`，满足协议识别所需的接入点要求。

## 数据路径

### 网站流量

1. 客户端连接 `:443`。
2. Caddy 完成 TLS 握手与证书选择。
3. 模块对解密后的连接进行首包窥探。
4. 若判定为非 AnyTLS，则将连接返回给 Caddy 的网站处理链路。
5. HTTP server 按既有站点路由继续处理请求。

### AnyTLS 流量

1. 客户端连接 `:443`。
2. Caddy 完成 TLS 握手与证书选择。
3. 模块对解密后的连接进行首包识别。
4. 若判定为 AnyTLS，则模块接管该连接。
5. 模块从密码哈希识别用户并选择出站。
6. `direct` / `socks5` 在本机解析会话并建立目标连接；`anytls` 替换上游认证哈希后中继完整会话。

## 关键设计点

### 连接分流

包装 listener 使用后台接收循环和有界探测并发池完成分流。TLS 握手与首包探测不会阻塞 Caddy 调用 `Accept()` 的单一 goroutine；网站流量通过结果通道返回上游 HTTP server，AnyTLS 流量则在模块内部启动会话处理。`max_pending_probes` 限制同时处于握手或探测阶段的连接数量。

这一设计意味着模块需要自行维护以下运行时状态：

- AnyTLS 会话生命周期
- 探测、会话和子流三级并发数量控制
- 认证和转发相关日志

### 首包窥探与无损回落

网站回落的前提是不能丢失任何已经读取的字节。为此，模块通过可回放连接包装实现首包窥探：

- 以带缓冲的 reader 包装底层 `net.Conn`
- 使用 `Peek()` 获取首包特征而不消费数据
- 回落到网站时，后续处理链仍能读取完整请求内容

这一点直接决定了回落链路的正确性，是接入设计中的硬性要求。

### 协议实现复用

AnyTLS 协议处理复用 `github.com/anytls/sing-anytls`，模块本身只保留接入层所需的控制逻辑，包括：

- 网站回落控制
- 首包识别入口
- 用户配置与出站选择
- 目标连接桥接
- Caddy 生命周期对接

首包识别使用与 `sing-anytls` 一致的密码哈希前缀规则，以避免模块侧识别与上游协议实现出现偏差。

普通网站流量支持快速回落路径：模块会优先识别 HTTP/2 preface 和常见 HTTP/1 方法前缀，命中后无需等待完整 32 字节 AnyTLS 哈希探测即可返回网站链路。这避免了合法网站首包较短时被 `probe_timeout` 放大延迟。

### 出站选择

模块在非消费式窥探密码哈希时即可识别并验证本地用户，随后根据用户名选择具名出站；未显式指定的用户依次使用默认出站或内置 `direct`。

- `direct` / `socks5` 调用本地会话处理器，由 `sing-anytls` 解析各子流，再把未解析目标交给对应流级连接器。
- `anytls` 在进入本地 `sing-anytls` service 前建立上游 TLS，将最前面的 32 字节认证哈希替换成上游密码哈希，然后原样中继 padding 和所有会话帧。上游因而保留完整的目标握手成功/失败、TCP、UDP-over-TCP 和 DNS 处理语义。

这种选择粒度是用户/物理会话，不是单个目标子流。同一条中继会话中的所有流量都会进入同一个 AnyTLS 上游。

入口的 `max_concurrent` 与 `idle_timeout` 仍作用于中继物理会话；由于入口不解析其中的 stream，`max_streams_per_session` 和 `max_concurrent_streams` 只约束本机处理路径，中继路径的子流限制由最终上游实施。

### 生命周期与配置重载

模块通过 Caddy 标准的 `Provision()`、`Validate()` 和 `Cleanup()`（`caddy.CleanerUpper`）参与配置生命周期。配置卸载时由 wrapper 的 `Cleanup()` 主动关闭全部活跃 AnyTLS 会话。

> 注：不使用 `ctx.OnCancel` 注册清理回调。caddy v2.11.4 中模块 `Provision` 以值接收 `caddy.Context`，`OnCancel` 只会把回调追加到 Context 副本上，配置卸载时永不执行；模块自身的 `Cleanup()` 则可靠触发。

当前策略如下：

- 新配置对新连接立即生效
- 网站链路不参与 AnyTLS 会话清理
- 旧 AnyTLS 会话在配置卸载时经 `Cleanup()` 主动终止

这一行为是有意为之。用户禁用、删除或出站映射变化后，旧会话继续存活会导致配置代际边界模糊，因此当前实现选择在配置代际切换时清理存量 AnyTLS 会话。

### 运行默认值

当前默认值围绕保守接入策略设定：

- `fallback = true`
- `probe_timeout = 5s`
- `idle_timeout = 2m`
- `connect_timeout = 10s`
- `max_concurrent = 128`
- `max_pending_probes = 256`
- `max_streams_per_session = 256`
- `max_concurrent_streams = 1024`
- `padding_scheme` 使用 `sing-anytls` 默认值

除上述默认值外，当前实现还遵循以下安全行为：

- 默认审计日志不输出密码
- `log_node_info` 需要显式开启，开启后会输出包含密码的 AnyTLS URI，适合日志访问权限可控的部署环境
- 用户被禁用后，新命中的连接不会回落到网站
- 认证成功的用户可以连接客户端指定的目标，不附加目标过滤规则

## 配置模型

当前配置模型聚焦于接入层能力，典型 JSON 结构如下：

```json
{
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "max_pending_probes": 256,
  "max_streams_per_session": 256,
  "max_concurrent_streams": 1024,
  "fallback": true,
  "log_node_info": false,
  "node_hosts": ["example.com"],
  "node_port": 443,
  "node_sni": "example.com",
  "node_insecure": false,
  "outbounds": {
    "proxy": {
      "dialer": "socks5",
      "address": "127.0.0.1:1080",
      "username": "proxy-user",
      "password": "proxy-password"
    }
  },
  "default_outbound": "proxy",
  "users": [
    {
      "name": "device-1",
      "password": "redacted",
      "enabled": true,
      "outbound": "direct"
    }
  ]
}
```

该模型有两个明确边界：

- 不提供独立证书配置
- 不提供独立 TLS 监听配置

这部分能力继续由 Caddy 负责。

## 可观测性

当前实现输出结构化日志，用于记录连接识别、认证、转发与会话结束等事件。主要字段包括：

- `connection_id`
- `event`
- `outcome`
- `reason`
- `protocol`
- `uot_is_connect`
- `user`
- `outbound`
- `source`
- `destination`
- `duration`
- `bytes_from_client`
- `bytes_to_client`
- `bytes_from_target`
- `bytes_to_target`

典型事件包括：

- 启动或重载后的节点 URI 输出，事件名为 `anytls_node`
- AnyTLS 会话认证成功
- 网站 fallback
- 禁用用户拒绝
- TCP relay 关闭及字节计数
- 配置卸载导致的会话终止

## 出站扩展点

出站（egress）通过 Caddy guest module 机制可插拔，命名空间为 `caddy.listeners.anytls.outbounds`，inline key 为 `dialer`。所有模块统一实现会话级 `Outbound.HandleSession`。未配置 `default_outbound` 时使用内置 `direct` 出站；显式的 `null` 模块配置无效。

本机处理型模块还实现流级 `StreamOutbound`（`DialContext` + `OpenPacket`），并在 `HandleSession` 中调用 `OutboundSession.ServeLocal`。内置 `direct` 和 `socks5` 属于这一类。内置 `anytls` 则直接使用 `OutboundSession.Connection` 中继协议会话，不实现流级接口。

### 按用户选择出站

一个 wrapper 可以在 `outbounds`（JSON 为 `map[string]模块对象`，Caddyfile 为 `outbound <name> <module>`）中声明任意多个具名出站，`users[].outbound` 按名引用其中之一。选择发生在物理会话进入本地 `sing-anytls` service 之前：listener 从已经窥探的密码哈希取得用户名，查只读映射得到该用户的出站。

对于本机处理型出站，选择结果通过连接上下文传给各子流 handler，TCP（`dialContext`）与 UDP over TCP（`openPacketContext`）使用同一个 `StreamOutbound`。对于 `anytls`，本地 service 不会启动，整条会话直接进入上游。

默认出站规则只有两层：配置 `default_outbound` 时使用它引用的具名出站，否则使用内置 `direct`。用户显式指定的出站优先于默认值。

保留名 `direct` 不可在 `outbounds` 中声明，它始终指向内置直连出站、无需声明即可被引用。引用未声明的出站名在 `Provision` 阶段报错。无名 `outbound` 不属于配置模型：Caddyfile 必须写成 `outbound <name> <module>`，JSON 必须在 `outbounds` 对象中声明模块。

`Provision` 临时构建名→出站映射来解析引用，运行期只保留默认选择和显式的用户→出站选择；这些选择之后只读，拨号路径并发读取无需加锁。

### 职责边界

本机处理的 TCP 和 UDP-over-TCP 都将客户端请求的未解析 `M.Socksaddr` 交给选中的 `StreamOutbound`。通用 relay 不解析域名，也不维护 DNS 缓存。

- `direct` 的 TCP 使用 `net.Dialer`，UDP 发送前使用宿主机 resolver 解析域名。
- `socks5` 将 TCP 域名写入 CONNECT 请求，将每个 UDP 域名写入 SOCKS5 UDP 数据报头，由代理端解析。
- `anytls` 不读取目标地址；入口仅解析上游 `address`，目标域名随会话帧到最终上游后再处理。

UDP 使用项目定义的 `PacketConn` 小接口，其 `ReadPacket` / `WritePacket` 显式携带 `M.Socksaddr`。不使用 `net.PacketConn` 作为出站边界，避免在通用层提前把域名转换成 `net.UDPAddr`。

第三方出站所需的连接池、隧道或代理客户端等资源由对应模块自行管理。wrapper 只保存模块配置并通过统一的 `Outbound` 接口分派会话，不感知具体出口资源的实现方式。

### 实现契约

- `HandleSession` 会被多个物理会话并发调用，实现必须并发安全，并在会话结束前保持阻塞。
- 本机处理型模块调用 `ServeLocal` 后，由本地 service 管理会话；其 `DialContext` / `OpenPacket` 仍可能被多个 handler goroutine 并发调用。
- 流级接口返回的 `net.Conn` / `PacketConn` 由 relay 负责关闭；每次调用必须返回独立连接，不得返回共享或缓存的连接。
- `HandleSession` 的 `ctx` 携带会话取消信号；`OutboundSession.ConnectTimeout()` 给出建连超时。流级 handler 会为 `DialContext` / `OpenPacket` 建立相同的超时上下文。
- `OutboundSession.User()` 和 `Source()` 分别提供本地认证用户名与入口观察到的客户端地址，供会话级出站记录或选路。
- `OpenPacket` 返回的连接需要支持向任意未解析目标发送数据报；实现自行决定本地解析、远端解析或其它路由方式。
- `PacketConn` 的方法返回后不得继续持有调用方提供的字节切片。
- 会话级中继若消费认证头，必须保留后续协议字节顺序；内置 `anytls` 只替换固定 32 字节密码哈希。
- 出站必须容忍 `Cleanup` 时仍有在用连接：Caddy 对各模块 `Cleanup` 的遍历没有跨模块顺序保证，出站的 `Cleanup` 可能先于 wrapper 关闭活跃会话执行。届时在用连接报错即可，由 relay 负责关闭，不会泄漏。

### 生命周期

出站模块的生命周期完全交给 Caddy 模块系统：经 `ctx.LoadModule` 加载并 Provision（具名出站同理，逐个加载）；配置卸载时 Caddy 调用各模块的 `Cleanup`。wrapper 在自己的 `Cleanup()` 中主动关闭全部活跃会话，但 Caddy 不保证 wrapper 与出站模块的 `Cleanup` 先后顺序，因此出站模块须按上文契约容忍清理时仍存在使用中的连接。

仓库内置 `direct`（`outbound.go`）、`socks5`（`outbound_socks5.go`）和 `anytls`（`outbound_anytls.go`）；其它实现可由独立的第三方模块提供和维护。

## 已知约束

当前设计中需要持续关注以下约束：

### listener wrapper 接入点依赖 Caddy 版本语义

模块行为与 Caddy `listener_wrapper` 的实际接口契约相关，升级 Caddy 版本时需要继续校验接入点行为。

### fallback 正确性依赖零字节丢失

任何首包探测逻辑都必须建立在非消费式读取之上。只要发生字节丢失，网站回落链路就会受到影响。
