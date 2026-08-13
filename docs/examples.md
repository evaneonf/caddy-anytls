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
				log_node_info true
				node_host example.com
			}
		}
	}
}

example.com {
	header -Server
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

## 带资源限制的 Caddyfile 配置

以下示例展示更接近生产环境的资源控制：

```caddyfile
{
	servers :443 {
		listener_wrappers {
			anytls {
				probe_timeout 5s
				idle_timeout 2m
				connect_timeout 10s
				max_concurrent 128
				max_pending_probes 256
				max_streams_per_session 256
				max_concurrent_streams 1024
				fallback true

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

认证成功后，客户端请求的目标会直接交给选中的出站，不再经过额外的域名、IP、端口或私网过滤。

## JSON 配置片段

如果使用 JSON 配置，模块需要挂载在 HTTP server 的 `listener_wrappers` 下。示例如下：

```json
{
  "wrapper": "anytls",
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "max_pending_probes": 256,
  "max_streams_per_session": 256,
  "max_concurrent_streams": 1024,
  "fallback": true,
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
| `max_pending_probes` | `256` | 最大并发 TLS 握手与首包探测数 |
| `max_streams_per_session` | `256` | 每条 AnyTLS 会话的最大并发子流数 |
| `max_concurrent_streams` | `1024` | 全局最大并发代理子流数 |
| `fallback` | `true` | 非 AnyTLS 流量回落网站 |
| `padding_scheme` | `sing-anytls` 默认值 | 复用上游协议实现的默认策略 |
| `log_node_info` | `false` | 启动或重载时输出当前启用用户的 AnyTLS 节点 URI 到 Caddy 日志 |
| `node_host` / `node_hosts` | 从站点 host matcher 推断 | 节点 URI 使用的域名或地址，可写多个 |
| `node_port` | 从 server listen 推断，默认 `443` | 节点 URI 使用的端口 |
| `node_sni` | 同 `node_host` | 节点 URI 使用的 `sni` 参数 |
| `node_insecure` | `false` | 是否在节点 URI 中输出 `insecure=1` |

默认值的代码来源分别位于：

- [anytls.go](../anytls.go) 中的 `Provision()`
- `github.com/anytls/sing-anytls/padding.DefaultPaddingScheme`

## 行为说明

当前版本对以下行为有明确约束：

- `sp.v2.udp-over-tcp.arpa` 会按 `UDP over TCP v2` 保留目标处理
- 已禁用用户命中新连接时会被拒绝，不回落到网站
- 配置重载或卸载时，现有 AnyTLS 会话会被终止
- 网站请求链路不参与 AnyTLS 会话清理
- HTTP/1 与 HTTP/2 网站首包会快速回落，不需要等待完整 AnyTLS 哈希探测
- 认证成功后，TCP 目标地址直接交给选中的出站连接
- 可声明多个具名出站并按用户选择出口（TCP 与 UDP over TCP 均生效），见下文「按用户选择出站」
- 选择 `anytls` 出站时，入口在识别用户后转发完整 AnyTLS 会话，由上游继续解析 TCP、UDP 和目标域名

## 节点信息输出

推荐在 Caddyfile 中显式打开启动日志输出：

```caddyfile
anytls {
	user phone-1 replace-with-strong-password
	log_node_info true
	node_host example.com
}
```

Caddy 启动或重载成功后会输出 `event=anytls_node` 的结构化日志。每个启用用户、每个 `node_host` 会各输出一条，字段包含 `user`、`host`、`port`、`sni`、`insecure` 和 `uri`。

示例 URI：

```text
anytls://replace-with-strong-password@example.com/
```

注意：URI 中包含用户密码。只有在日志访问权限可控时才开启 `log_node_info`。

如果没有配置 `node_host`，模块会尝试从 Caddy 站点的 host matcher 推断具体域名；通配符或 placeholder host 不会被用于节点 URI。

URI 规则：

- 密码放在 URI auth 位置，特殊字符会进行百分号编码
- 端口省略时默认为 `443`
- `ANYTLS_SNI` 与服务端地址不同时会输出 `sni` 参数
- `ANYTLS_SKIP_CERT_VERIFY=true` 时会输出 `insecure=1`

## 使用 SOCKS5 出站

默认情况下，认证后的目标流量通过内置 `direct` 出站，从运行 Caddy 的宿主机网络栈直接发出。需要通过已有的 SOCKS5 代理出站时，可以使用内置 `socks5`：

```caddyfile
anytls {
	outbound proxy socks5 {
		address 127.0.0.1:1080
		username proxy-user
		password proxy-password
	}
	default_outbound proxy
	user phone-1 replace-with-strong-password
}
```

`username` 和 `password` 可同时省略。TCP 使用 SOCKS5 CONNECT；UDP-over-TCP 使用 SOCKS5 UDP ASSOCIATE，因此 SOCKS5 服务端必须支持 UDP ASSOCIATE 才能转发 UDP。目标域名由 SOCKS5 服务端解析。

## 使用 AnyTLS 上游出站

需要把指定用户的整条会话继续交给另一个 AnyTLS 节点时，声明具名 `anytls` 出站：

```caddyfile
anytls {
	outbound relay anytls {
		address upstream.example.com:443
		password upstream-password
	}

	user phone-local replace-with-local-password
	user phone-relay replace-with-relay-password relay
}
```

入口先验证 `phone-relay` 的本地密码，再将首部认证哈希替换成上游密码的哈希；剩余 AnyTLS 会话帧保持不变。上游负责目标解析、DNS、TCP 和 UDP。`server_name` 默认从 `address` 推断；只有拨号地址与证书域名不一致时才需要配置：

```caddyfile
outbound relay anytls {
	address 192.0.2.10:443
	server_name upstream.example.com
	password upstream-password
}
```

`tls_insecure_skip_verify` 可以跳过上游证书校验，但默认关闭，不建议用于生产环境。入口只需要解析上游 `address`；客户端请求的目标域名由最终上游解析。不要配置相互指回的 AnyTLS 上游，否则会形成没有 hop limit 的会话环路。

## 按用户选择出站（多出站）

同一个 `:443` 入口可以声明多个具名出站，并让不同账号走不同出口。客户端只需要配置多个「节点」（同 IP、同端口、同 SNI、单证书，仅密码不同）即可切换出口。

下面的配置让默认用户通过 SOCKS5，另一个用户直接从宿主机出站：

```caddyfile
anytls {
	outbound proxy socks5 {
		address 127.0.0.1:1080
	}
	default_outbound proxy

	user phone-proxy replace-with-password-1
	user phone-direct replace-with-password-2 direct
}
```

规则说明：

- `outbound <name> <module>` 声明具名出站；`outbound` 始终需要名称和模块两个参数。
- `user` 的第 3 个参数按名引用某个具名出站，省略时走默认出站。
- `default_outbound` 指定未标注用户使用的具名出站；不配置时固定使用内置 `direct`。
- 保留名 `direct` 不允许在具名出站中声明。`direct` 始终指向内置直连出站，无需声明即可被 `user` 或 `default_outbound` 引用。
- 引用未声明的出站名、具名出站重名、`default_outbound` 指令重复出现均会在配置阶段报错。
- `direct` 与 `socks5` 在本机解析 AnyTLS 子流；`anytls` 在识别用户后转发整条会话。
- `direct` 依赖宿主机 DNS，`socks5` 由代理端解析目标域名，`anytls` 由最终上游解析目标域名；项目不维护额外 DNS 缓存。

对应的 JSON 配置：

```json
{
  "wrapper": "anytls",
  "outbounds": {
    "proxy": {
      "dialer": "socks5",
      "address": "127.0.0.1:1080"
    }
  },
  "default_outbound": "proxy",
  "users": [
    {"name": "phone-default", "password": "..."},
    {"name": "phone-direct", "password": "...", "outbound": "direct"}
  ]
}
```

其它出站可以继续由实现了会话级 `Outbound.HandleSession` 接口的第三方 Caddy 模块提供，并注册到 `caddy.listeners.anytls.outbounds` 命名空间。本机处理型出站可调用 `OutboundSession.ServeLocal`，并实现流级 `StreamOutbound`。

注意：JSON 的 `outbounds` 是对象，重复键会被 JSON 解析器静默取后者，重名检测仅在 Caddyfile 路径可用。

可观测性：

- Info 级 `anytls session authenticated` 与 `anytls connection established` 日志带 `outbound` 字段，分别记录物理会话选路和本地目标子流使用的出站名；未配置默认出口时记录为 `direct`。
- 开启 `log_node_info` 时，每个用户的节点日志同样带 `outbound` 字段，便于核对哪个账号走哪个出口。

## 已知限制

当前示例覆盖的是首版可用配置，范围仍然有限：

- 尚未提供管理接口或动态用户 API
- 会话不会跨配置代际保活

仓库内测试当前已覆盖网站 fallback、AnyTLS 转发以及 `UDP over TCP v2` 的主要路径。
