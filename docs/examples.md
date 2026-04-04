# 配置示例

## 构建

使用 `xcaddy` 构建包含 `caddy-anytls` 模块的 Caddy：

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

## 最小 Caddyfile 配置

以下示例适用于常见的 HTTPS 站点接入场景：

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                user phone-1 replace-with-strong-password
                user laptop-1 replace-with-another-password
            }
        }
    }
}

example.com {
    respond "server is running"
}
```

该配置的行为如下：

- Caddy 继续负责 HTTPS 站点和证书生命周期
- `anytls` 在 TLS 解密后识别协议
- 非 AnyTLS 流量继续进入网站链路
- AnyTLS 命中后进入认证与转发流程

对于 `user <name> <password>`：

- `name` 是模块侧的运维标识
- 该字段主要用于设备区分、日志记录和用户管理
- 协议认证仍以密码为核心

## JSON 配置片段

如果使用 JSON 配置，模块需要挂载在 HTTP server 的 `listener_wrappers` 下。示例如下：

```json
{
  "wrapper": "anytls",
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "fallback": true,
  "allow_private_targets": false,
  "users": [
    {
      "name": "phone-1",
      "password": "replace-with-strong-password",
      "enabled": true
    },
    {
      "name": "laptop-1",
      "password": "replace-with-another-password",
      "enabled": true
    }
  ]
}
```

## 默认值

在未显式配置时，当前版本会采用以下默认值：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `probe_timeout` | `5s` | TLS 后首包探测超时 |
| `idle_timeout` | `2m` | AnyTLS 会话空闲超时 |
| `connect_timeout` | `10s` | 出站拨号超时 |
| `max_concurrent` | `128` | 最大并发 AnyTLS 会话数 |
| `fallback` | `true` | 非 AnyTLS 流量回落网站 |
| `allow_private_targets` | `false` | 默认拒绝常见私网目标 |
| `padding_scheme` | `sing-anytls` 默认值 | 复用上游协议实现的默认策略 |

默认值的代码来源分别位于：

- [anytls.go](../anytls.go) 中的 `Provision()`
- `github.com/anytls/sing-anytls/padding.DefaultPaddingScheme`

## 行为说明

当前版本对以下行为有明确约束：

- `sp.v2.udp-over-tcp.arpa` 会按 `UDP over TCP v2` 保留目标处理
- 已禁用用户命中新连接时会被拒绝，不回落到网站
- 配置重载或卸载时，现有 AnyTLS 会话会被终止
- 网站请求链路不参与 AnyTLS 会话清理

## 已知限制

当前示例覆盖的是首版可用配置，范围仍然有限：

- 仅支持基础用户列表、超时、并发和私网目标开关
- 尚未提供更细粒度 ACL
- 尚未提供管理接口
- 会话不会跨配置代际保活

仓库内测试当前已覆盖网站 fallback、AnyTLS 转发以及 `UDP over TCP v2` 的主要路径。
