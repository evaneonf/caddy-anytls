# 实现说明

## 接入和分流

模块注册为 `caddy.listeners.anytls`。Caddy listener wrapper 在 TLS 解密后、HTTP 解析前处理连接，协议实现使用 `github.com/anytls/sing-anytls`。

```text
Caddy listener
  → TLS handshake
  → SNI 不匹配：返回原连接给 Caddy
  → SNI 匹配：窥探首包
      → HTTP 或未知认证哈希：交还网站
      → 已禁用用户：关闭连接
      → 启用用户：选择出站并处理会话
```

listener 通过有界并发处理握手和探测，网站连接经结果通道交还 HTTP server。窥探使用缓冲读取，回落时保留已读取字节和 TLS ConnectionState，因此 HTTP/1.1、HTTP/2 和后续 listener wrapper 可以继续处理网站连接。

## 出站接口

出站注册在 `caddy.listeners.anytls.outbounds` 命名空间，实现 `Outbound.HandleSession`。配置加载时解析具名出站和用户引用，运行时只读这些映射。

`OutboundSession` 提供底层连接、建连超时和 `ServeLocal`：

- `direct`、`socks5` 调用 `ServeLocal` 解析本地 AnyTLS 会话，再通过 `StreamOutbound.DialContext` 和 `OpenPacket` 处理 TCP 与 UDP。
- `anytls` 建立上游 TLS 连接，替换 32 字节密码哈希，然后双向中继其余字节。

`PacketConn` 使用 `Socksaddr` 传递 UDP 地址，使 SOCKS5 出站能够把域名交给远端解析。UDP-over-TCP 支持 connect 和逐包目标地址模式。

## 会话生命周期

物理会话注册连接、取消函数和活动子流计数。子流结束释放并发名额，物理会话结束移除注册项。

空闲计时器按双向读写活动刷新，与应用显式设置的读写 deadline 独立。Caddy 调用 `Cleanup` 时取消并关闭该配置下的活动 AnyTLS 会话；网站连接由 Caddy 管理。

探测连接数、已认证会话数、单会话子流数和全局子流数分别受限。会话级 AnyTLS 转发不解析子流，因此入口只限制探测和物理会话。

## 配置与日志

Caddyfile 和 JSON 共用入口配置字段及校验。`sni` 必填，DNS 名按大小写无关方式匹配；用户密码的 SHA-256 哈希用于首包识别。被禁用用户保留在识别表中以明确拒绝连接，但不进入协议服务的启用用户表。

节点 URI 在 `WrapListener` 时生成，使用配置的 SNI 和已绑定 TCP listener 的端口。会话日志以 `connection_id` 关联，记录用户、出口和目标；TCP 字节计数只在 Debug 日志启用时收集。
