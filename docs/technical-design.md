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
5. 连接进入认证、目标地址解析、出站建立与双向转发流程。

## 关键设计点

### 连接分流

`Accept()` 循环承担分流职责。对于网站流量，包装后的 listener 将连接直接返回给上游 HTTP server；对于 AnyTLS 流量，模块在内部启动会话处理并继续接受下一条连接。

这一设计意味着模块需要自行维护以下运行时状态：

- AnyTLS 会话生命周期
- 并发数量控制
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
- 用户配置与策略边界
- 目标连接桥接
- Caddy 生命周期对接

首包识别使用与 `sing-anytls` 一致的密码哈希前缀规则，以避免模块侧识别与上游协议实现出现偏差。

### 生命周期与配置重载

模块通过 Caddy 标准的 `Provision()`、`Validate()` 和取消回调参与配置生命周期。

当前策略如下：

- 新配置对新连接立即生效
- 网站链路不参与 AnyTLS 会话清理
- 旧 AnyTLS 会话在配置卸载时主动终止

这一行为是有意为之。对于用户禁用、删除或策略收紧等场景，旧会话继续存活会导致安全边界模糊，因此当前实现选择在配置代际切换时清理存量 AnyTLS 会话。

### 安全默认值

当前默认值围绕保守接入策略设定：

- `fallback = true`
- `probe_timeout = 5s`
- `idle_timeout = 2m`
- `connect_timeout = 10s`
- `max_concurrent = 128`
- `allow_private_targets = false`
- `padding_scheme` 使用 `sing-anytls` 默认值

除上述默认值外，当前实现还遵循以下安全行为：

- 日志不输出明文密码
- 用户被禁用后，新命中的连接不会回落到网站
- 默认拒绝访问常见私网目标地址

## 配置模型

当前配置模型聚焦于接入层能力，典型 JSON 结构如下：

```json
{
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "fallback": true,
  "allow_private_targets": false,
  "users": [
    {
      "name": "device-1",
      "password": "redacted",
      "enabled": true
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
- `source`
- `destination`
- `duration`

典型事件包括：

- AnyTLS 会话认证成功
- 网站 fallback
- 禁用用户拒绝
- 私网目标拒绝
- 配置卸载导致的会话终止

## 已知约束

当前设计中需要持续关注以下约束：

### listener wrapper 接入点依赖 Caddy 版本语义

模块行为与 Caddy `listener_wrapper` 的实际接口契约相关，升级 Caddy 版本时需要继续校验接入点行为。

### fallback 正确性依赖零字节丢失

任何首包探测逻辑都必须建立在非消费式读取之上。只要发生字节丢失，网站回落链路就会受到影响。
