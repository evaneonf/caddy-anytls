# Caddy AnyTLS Module 技术设计

## 目标

首版实现一个运行在 Caddy 内部的 AnyTLS 接入层，满足以下约束：

- 复用 Caddy 的 `:443` 监听与自动 HTTPS 能力
- 在 TLS 握手完成后识别 AnyTLS 首包
- AnyTLS 命中时接管连接并执行认证、出站转发
- 非 AnyTLS 流量无感回落到原有网站链路

## 模块形态

首版采用 Caddy `listener_wrapper` 形态，而不是 HTTP handler。

原因：

- HTTP handler 只能处理已经被解析成 HTTP 请求的流量，无法在非 HTTP 流量进入前截获
- 产品要求 AnyTLS 与网站共用同一 TLS 入口，识别必须发生在 TLS 之后、HTTP 解析之前
- listener wrapper 可以直接拿到 TLS 解密后的 `net.Conn`，适合做首包窥探与分流

模块 ID 计划为：

- `caddy.listeners.anytls`

## 请求路径

### 网站流量

1. 客户端连接 `:443`
2. Caddy 完成 TLS 握手和证书选择
3. AnyTLS wrapper 对解密后的连接做首包窥探
4. 判定为非 AnyTLS
5. wrapper 返回该连接给 Caddy 的正常 HTTP 链路
6. 网站按既有站点路由继续处理

### AnyTLS 流量

1. 客户端连接 `:443`
2. Caddy 完成 TLS 握手和证书选择
3. AnyTLS wrapper 读取首包特征
4. 判定为 AnyTLS
5. wrapper 不把该连接交给 HTTP server，而是在模块内部启动会话处理
6. 完成用户认证、目标连接建立和双向转发

## 关键设计

### 1. Accept 循环分流

listener wrapper 的 `Accept()` 负责做连接分流：

- 命中网站回落：直接返回给上游 HTTP server
- 命中 AnyTLS：在后台 goroutine 中处理，然后继续等待下一条连接

这意味着 wrapper 需要自己管理：

- AnyTLS 会话生命周期
- 并发上限
- 认证和转发日志

### 2. 首包窥探

为了在回落时不丢失字节，需要一个可回放的连接包装：

- 以 `bufio.Reader` 包装 `net.Conn`
- 使用 `Peek()` 读取首包，不消费数据
- 如果回落给网站，HTTP server 仍能从同一连接读到完整请求

### 3. 协议接入策略

协议层复用 `github.com/anytls/sing-anytls`：

- listener wrapper 只负责在回落到网站前做最小识别
- AnyTLS 会话、认证、流复用由 `sing-anytls.Service` 处理
- 首包识别使用与 `sing-anytls` 相同的密码哈希前缀规则，避免双实现产生不一致

这样做的边界是：

- 我们仍然保留 Caddy 侧的回落控制权
- AnyTLS 真正的会话实现不在本仓库重复造轮子

### 4. 配置热更新

配置通过 Caddy 标准 `Provision()` / `Validate()` 生命周期加载。

原则：

- reload 时新配置用于新连接
- 网站侧连接尽量不受影响
- AnyTLS 已建立会话在旧配置卸载时会被主动终止，不跨配置代际保留

当前实现选择主动终止旧 AnyTLS 会话，原因是：

- 用户禁用/删除后不应允许旧代理会话继续运行
- 配置变更的安全边界要清晰，不能依赖旧会话自然超时
- 对网站流量的影响面仍然限制在 AnyTLS 会话本身，不扩散到 HTTP 站点链路

### 5. 安全默认值

首版默认值：

- 启用 fallback
- 有探测超时和空闲超时
- 有最大并发上限
- 默认拒绝私网目标地址
- 不在日志中输出明文密码
- 用户被禁用后，命中该用户首包特征的新连接直接拒绝，不回落网站

## 配置模型

首版 JSON 配置建议如下：

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

说明：

- 不提供证书配置
- 不提供独立 TLS 监听配置
- 用户密码后续需要支持哈希或外部 secret 引用

## 实现拆分

### 阶段 1：骨架

- `listener_wrapper` 模块注册
- 配置结构与校验
- 可回放连接封装
- AnyTLS 会话分流框架
- 基础日志字段

### 阶段 2：协议接入

- 接入真实 AnyTLS 首包检测
- 用户认证
- 目标地址解析
- 出站连接建立
- 双向拷贝与超时控制

### 阶段 3：策略与可观测性

- ACL
- 私网地址策略
- 用户级限制
- 指标与更细日志

### 当前可观测性实现

当前已经输出结构化日志字段：

- `connection_id`
- `event`
- `outcome`
- `reason`
- `user`
- `source`
- `destination`
- `duration`

当前已覆盖的典型事件包括：

- AnyTLS 会话认证成功
- 网站 fallback
- 禁用用户命中后拒绝
- 私网目标拒绝
- 配置卸载导致的会话终止

## 当前已知风险

### 1. Caddy listener wrapper 接入点需要用真实依赖校准

不同 Caddy 版本的 listener wrapper 细节可能有差异，需要以 `v2.10.2` 的实际接口为准校正编译。

### 2. fallback 行为必须保证零字节丢失

任何探测逻辑都必须建立在“窥探而非消费”的前提上，否则会破坏网站流量。
