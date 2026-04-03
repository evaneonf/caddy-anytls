# 配置示例

## 构建

使用 `xcaddy` 构建带本模块的 Caddy：

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

## Caddyfile 示例

当前已经支持在 `listener_wrappers` 中启用 `anytls`：

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

说明：

- HTTPS 站点场景下，Caddy 会自动插入 TLS listener wrapper，本模块不需要手工声明 `tls`
- `anytls` 只处理 TLS 解密后的明文连接
- 非 AnyTLS 流量会继续进入正常网站链路
- 命中已禁用用户的 AnyTLS 首包会被直接拒绝，不会回落到网站
- 配置 reload/卸载时，现有 AnyTLS 会话会被主动终止；网站请求链路不受这条策略影响

## JSON 片段示例

如果使用 JSON 配置，模块挂在 HTTP server 的 `listener_wrappers` 下：

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

## 默认值表

下面这些值在不显式配置时会自动生效：

| 配置项 | 默认值 | 来源 | 说明 |
| --- | --- | --- | --- |
| `probe_timeout` | `5s` | 模块默认值 | TLS 后首包探测超时，首版取偏保守值 |
| `idle_timeout` | `2m` | 模块默认值 | 控制空闲 AnyTLS 会话的生命周期 |
| `connect_timeout` | `10s` | 模块默认值 | 控制出站拨号最长等待时间 |
| `max_concurrent` | `128` | 模块默认值 | 限制并发 AnyTLS 会话数 |
| `fallback` | `true` | 模块默认值 | 非 AnyTLS 流量继续回落网站 |
| `allow_private_targets` | `false` | Go 零值和模块行为 | 默认拒绝常见私网目标 |
| `padding_scheme` | `sing-anytls` 默认值 | 上游协议实现 | 优先保证与上游协议兼容 |

这些默认值当前的代码来源在：

- `anytls.go` 的 `Provision()`
- `github.com/anytls/sing-anytls/padding.DefaultPaddingScheme`

## 当前限制

- 目前只支持基础用户列表、超时、并发和私网目标开关
- 还没有更细的 ACL 和管理接口
- 端到端行为已在仓库测试里覆盖“网站 fallback”和“AnyTLS 转发”两条核心链路
- reload 语义当前是“新配置立即接管，新旧 AnyTLS 会话不并存”
