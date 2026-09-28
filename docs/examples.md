# 配置参考

下列 `anytls` 配置块放在 Caddy 的 `servers` → `listener_wrappers` 中。完整部署示例见 [README](../README.md)。

## 入口和用户

```caddyfile
anytls {
	sni proxy.example.com
	user phone replace-with-password-1
	user laptop replace-with-password-2
}
```

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `sni <domain>` | 必填 | 进入 AnyTLS 探测的域名，也是节点 URI 的域名；不支持通配符、IP、协议前缀或端口 |
| `user <name> <password> [outbound]` | 无 | 添加启用用户；用户名和密码分别唯一，省略出口时使用默认出口 |
| `outbound <name> <module> { ... }` | 无 | 声明具名出站 |
| `default_outbound <name>` | `direct` | 未指定出口的用户使用的出站 |
| `log_node_info <bool>` | `false` | listener 建立时输出包含密码的节点 URI |

内置 `direct` 无需声明，也是保留名称。引用未声明的出站会导致配置加载失败。

## SOCKS5 出站

```caddyfile
anytls {
	sni proxy.example.com
	outbound proxy socks5 {
		address 127.0.0.1:1080
		username proxy-user
		password proxy-password
	}

	user phone replace-with-password-1 proxy
	user laptop replace-with-password-2
}
```

| 选项 | 必填 | 说明 |
| --- | --- | --- |
| `address <host:port>` | 是 | SOCKS5 服务端地址 |
| `username <value>` | 否 | SOCKS5 用户名 |
| `password <value>` | 否 | SOCKS5 密码；配置时必须同时提供用户名 |

不需要认证时省略用户名和密码。UDP 转发要求 SOCKS5 服务端支持 UDP ASSOCIATE；目标域名通过代理解析。

## AnyTLS 上游

```caddyfile
anytls {
	sni proxy.example.com
	outbound relay anytls {
		address upstream.example.com:443
		password upstream-password
	}
	default_outbound relay

	user phone replace-with-password-1
	user laptop replace-with-password-2 direct
}
```

| 选项 | 必填 | 说明 |
| --- | --- | --- |
| `address <host:port>` | 是 | 上游地址 |
| `password <value>` | 是 | 上游密码，可与本地用户密码不同 |
| `server_name <domain>` | 否 | 上游 TLS SNI 和证书校验名，默认取 `address` 的主机名 |
| `tls_insecure_skip_verify` | 否 | 跳过上游证书校验，默认关闭；Caddyfile 中此项不带参数 |

入口验证本地用户后替换会话首部的认证哈希，其他 padding 和会话帧原样转发。目标连接、UDP 和目标域名解析由上游处理；入口只解析上游自身的地址。

## 超时和容量

一般无需配置这些参数，按机器容量和网络情况调整即可。

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `probe_timeout` | `5s` | TLS 握手及每次首包探测读取的等待时间 |
| `idle_timeout` | `2m` | 会话空闲超时，任一方向有效读写会刷新 |
| `connect_timeout` | `10s` | 目标连接或 AnyTLS 上游建连的超时 |
| `max_pending_probes` | `256` | 并发 TLS 握手与首包探测数 |
| `max_concurrent` | `128` | 并发 AnyTLS 物理会话数 |
| `max_streams_per_session` | `256` | 单条会话的并发代理子流数 |
| `max_concurrent_streams` | `1024` | 全局并发代理子流数 |

省略或设为 0 时采用默认值，负数无效。探测并发达到上限后，新连接在系统监听队列中等待。会话或子流达到上限时拒绝新增的会话或子流。

`direct` 和 `socks5` 在本机解析子流，适用两个 stream 限制；`anytls` 出站转发完整会话，子流容量由最终上游管理。padding 使用协议库默认值。

## JSON

以下对象放在 HTTP server 的 `listener_wrappers` 数组中：

```json
{
  "wrapper": "anytls",
  "sni": "proxy.example.com",
  "users": [
    {"name": "phone", "password": "replace-with-password-1", "outbound": "proxy"},
    {"name": "laptop", "password": "replace-with-password-2", "enabled": false}
  ],
  "outbounds": {
    "proxy": {"dialer": "socks5", "address": "127.0.0.1:1080"}
  }
}
```

`users` 为用户数组，`enabled` 默认为 `true`，设置 `false` 可保留账号配置并禁用它。`outbounds` 为出站名称到模块配置的映射，`dialer` 指定模块名。其他入口字段与 Caddyfile 同名，时长可以写成 `"5s"` 等字符串。未知字段会被拒绝。
