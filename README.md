# caddy-anytls

让 AnyTLS 与网站共用 Caddy 的 HTTPS 入口。Caddy 负责监听、TLS 握手、证书和网站路由；模块在 TLS 解密后按 SNI 和密码识别 AnyTLS，其他流量交还网站。

支持多用户、TCP、UDP over TCP，以及按用户选择 `direct`、`socks5` 或 `anytls` 出站。

## 快速开始

将以下内容保存为 `config/Caddyfile`，替换域名和密码。域名应解析到服务器，且 Caddy 能为其取得有效证书。

```caddyfile
{
	servers :443 {
		listener_wrappers {
			anytls {
				sni proxy.example.com
				user phone replace-with-a-long-random-password
			}
		}
	}
}

proxy.example.com {
	header -Server
	respond "server is running"
}
```

实际部署时可将 `respond` 换成已有网站的配置。

```sh
docker run -d --name caddy \
  -p 80:80 -p 443:443 \
  -v "$PWD/config:/etc/caddy:ro" \
  -v caddy_data:/data \
  --restart unless-stopped \
  ghcr.io/evaneonf/caddy-anytls:latest
```

`config` 保存配置，`caddy_data` 持久化证书和私钥。镜像提供 `linux/amd64` 和 `linux/arm64`，`latest` 为正式版本，`vX.Y.Z` 可固定版本，`main` 为分支构建。

确认网站可访问后，客户端使用同一域名、端口和用户密码连接：

```sh
curl -I https://proxy.example.com
```

```text
anytls://replace-with-a-long-random-password@proxy.example.com/
```

修改配置后验证并重载：

```sh
docker exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

## 分流行为

- `sni` 必填，只接受单个具体 DNS 域名，忽略大小写；国际化域名使用 punycode。
- TLS 握手完成后，SNI 不匹配、为空或无法取得 TLS 状态的连接直接交还 Caddy，不读取应用数据或验证 AnyTLS 密码。
- SNI 匹配时才探测 AnyTLS；普通 HTTP/1.1、HTTP/2 仍进入网站，未知密码的流量也交还网站。
- 用户名和密码各自必须唯一。命中已禁用用户的连接会被拒绝。
- 配置重载或卸载会关闭已有 AnyTLS 会话，客户端需要重新连接。

`sni` 不负责创建网站或签发证书，对应域名必须有正常的 Caddy HTTPS 配置。

## 出站与配置

| 出站 | 行为 | 目标域名解析 |
| --- | --- | --- |
| `direct` | 由本机连接目标，默认使用 | 宿主机 |
| `socks5` | 通过 SOCKS5 代理转发 TCP/UDP | SOCKS5 代理 |
| `anytls` | 替换认证哈希后转发完整会话 | 最终 AnyTLS 上游 |

具名出站通过 `outbound <name> <module>` 声明，由用户或 `default_outbound` 引用。详细语法、JSON 配置和资源限制见[配置参考](docs/examples.md)。

## 节点链接与日志

需要生成客户端链接时，在 `anytls` 中临时设置 `log_node_info true`，重载后查看：

```sh
docker logs caddy 2>&1 | grep anytls_node
```

每个启用用户在每个 TCP listener 上输出一条 URI：域名来自 `sni`，端口取实际监听端口，443 省略。外部端口映射需要在客户端调整。URI 包含完整密码，获取后应关闭此选项。

结构化日志使用 `connection_id` 关联物理会话，`user` 和 `outbound` 标识用户及出口。同一会话可包含多个目标连接。Debug 级别记录网站回落、TLS 握手失败及 TCP 转发字节数。

## 本地构建

在仓库目录中构建包含本模块的 Caddy：

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

或修改仓库提供的 [config/Caddyfile](config/Caddyfile)，使用 Compose 构建并运行：

```sh
docker compose up -d --build
```

## 运行边界

认证用户可以访问所选出口能够连接的目标。AnyTLS 上游应避免形成转发环路。单条会话复用一条 TCP，丢包会影响其中多个子流；网站回落也不隐藏 TLS SNI、证书或客户端指纹。

[实现说明](docs/technical-design.md)介绍连接处理和模块接口。

## License

[GPL-3.0-or-later](LICENSE)
