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

## 带出站策略的 Caddyfile 配置

以下示例展示更接近生产环境的边界控制：

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
				allow_private_targets false

				deny_port 25
				deny_cidr 127.0.0.0/8 169.254.0.0/16
				deny_domain .blocked.example

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

策略规则：

- `deny_*` 优先于 `allow_*`
- 配置了任意 `allow_*` 后，未命中的目标会被拒绝
- `allow_private_targets false` 时，域名目标会先解析再检查所有返回地址
- `allow_cidr` 可用于精确放行受控内网段，例如 `allow_cidr 10.10.0.0/16`

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
  "allow_private_targets": false,
  "allow_cidrs": [],
  "deny_cidrs": ["127.0.0.0/8", "169.254.0.0/16"],
  "allow_ports": [],
  "deny_ports": [25],
  "allow_domains": [],
  "deny_domains": [".blocked.example"],
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
| `allow_private_targets` | `false` | 默认拒绝常见私网目标 |
| `allow_cidr` / `allow_cidrs` | 无 | 只允许访问指定 CIDR |
| `deny_cidr` / `deny_cidrs` | 无 | 拒绝访问指定 CIDR |
| `allow_port` / `allow_ports` | 无 | 只允许访问指定端口 |
| `deny_port` / `deny_ports` | 无 | 拒绝访问指定端口 |
| `allow_domain` / `allow_domains` | 无 | 只允许访问指定域名或后缀 |
| `deny_domain` / `deny_domains` | 无 | 拒绝访问指定域名或后缀 |
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
- 域名目标会先解析再执行私网和 CIDR 策略
- TCP 域名目标解析出多个地址时，会在统一超时预算内交错 IPv4/IPv6 并发尝试
- `allow_cidr`、`deny_cidr`、`allow_port`、`deny_port`、`allow_domain`、`deny_domain` 可组合限制出站目标
- 可声明多个具名出站并按用户选择出口（TCP 与 UDP over TCP 均生效），见下文「按用户选择出站」

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

## 出站转发到其它出口（WireGuard）

默认情况下认证后的目标流量从运行 Caddy 的机器直接发出。若希望出口流量从另一台主机（例如家宽服务器）出网，可用 `outbound` 指令切换出站模块。

可以直接使用同时包含主模块和 WireGuard 出站插件的预构建镜像（WireGuard 出站是独立仓库 [`github.com/lihuaye/caddy-wireguard`](https://github.com/lihuaye/caddy-wireguard)）：

```sh
docker pull ghcr.io/evaneonf/caddy-anytls:wireguard
```

也可以自行构建：

```sh
xcaddy build \
    --with github.com/evaneonf/caddy-anytls \
    --with github.com/lihuaye/caddy-wireguard@v0.1.0
```

WireGuard 的密钥、端点、地址和 DNS 属于出口资源，先在全局块中定义命名隧道；`anytls` 只引用它：

```caddyfile
{
	wireguard {
		tunnel home {
			private_key <base64 客户端私钥>
			peer_public_key <base64 服务端公钥>
			endpoint home.example.com:51820
			address 10.7.0.2
			allowed_ips 0.0.0.0/0 ::/0
			dns 1.1.1.1
			persistent_keepalive 25
		}
	}

	servers :443 {
		listener_wrappers {
			anytls {
				user phone-1 replace-with-strong-password
				outbound wireguard {
					tunnel home
				}
			}
		}
	}
}

example.com {
	respond "server is running"
}
```

行为说明：

- 入口（客户端到 `:443`）路径不受影响，隧道只承载认证后的出口流量
- 域名由实际选中的出站解析；WireGuard 出站的 DNS 请求经 `home` 隧道发送到其配置的解析器
- 解析结果返回 wrapper 完成私网/CIDR 策略检查，再由同一个出站连接已检查的 IP
- 不写 `outbound` 时使用内置 `direct`，等价于原有直连行为
- 推荐使用全局命名隧道，不在 `anytls` 内重复内联密钥和 endpoint；同一隧道还可安全共享给 `reverse_proxy`

配置项、密钥生成和家宽侧准备见 [`github.com/lihuaye/caddy-wireguard`](https://github.com/lihuaye/caddy-wireguard) 的 README。

## 按用户选择出站（多出站）

同一个 `:443` 入口可以声明多个具名出站，并让不同账号走不同出口。客户端只需要配置多个「节点」（同 IP、同端口、同 SNI、单证书，仅密码不同）即可切换出口。

下例继续引用上一个示例在全局块中定义的 `home` 隧道：

```caddyfile
{
	servers :443 {
		listener_wrappers {
			anytls {
				# 具名出站：outbound <name> <module> { ...模块配置... }
				outbound wg-home wireguard {
					tunnel home
				}

				# 默认出站（可选）：未标注出站的用户走它
				default_outbound wg-home

				# user <name> <password> [outbound-name]
				user phone-home replace-with-password-1 # -> 默认（wg-home）
				user phone-direct replace-with-password-2 direct # -> 内置直连
				user laptop replace-with-password-3 wg-home # 显式引用
			}
		}
	}
}

example.com {
	respond "server is running"
}
```

规则说明：

- `outbound <name> <module>`（2 个参数）声明具名出站；`outbound <module>`（1 个参数）仍是原有的单默认出站写法，语义不变。
- `user` 的第 3 个参数按名引用某个具名出站，省略时走默认出站。
- 默认出站解析顺序：`default_outbound` 指定的具名出站 → 单 `outbound` 模块 → 内置 `direct`。老配置（只有单 `outbound` 或什么都不写）行为完全不变。
- 保留名 `direct` 与 `default` 不允许在具名出站中声明。`direct` 始终指向内置直连出站，无需声明即可被 `user` 引用；`default` 是旧式单 `outbound` 默认档在日志中的哨兵名。
- 引用未声明的出站名、具名出站重名、`default_outbound` 指令重复出现均会在配置阶段报错。
- TCP 与 UDP-over-TCP 的域名解析都由该用户最终选中的出站完成；解析、策略检查和拨号共享同一个连接上下文与超时预算。

对应的 JSON 配置：

```json
{
  "wrapper": "anytls",
  "outbounds": {
    "wg-home": {
      "dialer": "wireguard",
      "tunnel": "home"
    }
  },
  "default_outbound": "wg-home",
  "users": [
    {"name": "phone-home", "password": "..."},
    {"name": "phone-direct", "password": "...", "outbound": "direct"},
    {"name": "laptop", "password": "...", "outbound": "wg-home"}
  ]
}
```

注意：JSON 的 `outbounds` 是对象，重复键会被 JSON 解析器静默取后者，重名检测仅在 Caddyfile 路径可用。

可观测性：

- Info 级 `anytls connection established` 日志带 `outbound` 字段，记录该连接实际使用的出站名（具名引用或 `default_outbound` 命中时为其名；`direct` 引用或兜底为 `direct`；旧式单 `outbound` 默认档为哨兵 `default`）。
- 开启 `log_node_info` 时，每个用户的节点日志同样带 `outbound` 字段，便于核对哪个账号走哪个出口。

## 已知限制

当前示例覆盖的是首版可用配置，范围仍然有限：

- 尚未提供管理接口或动态用户 API
- 会话不会跨配置代际保活

仓库内测试当前已覆盖网站 fallback、AnyTLS 转发以及 `UDP over TCP v2` 的主要路径。
