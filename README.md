# caddy-anytls

`caddy-anytls` 是一个 Caddy listener wrapper，让网站与 AnyTLS 共用同一个 HTTPS 入口。

Caddy 继续负责 `443` 监听、TLS、证书和网站路由；本模块只在 TLS 解密后、HTTP 解析前识别 AnyTLS。命中 AnyTLS 的连接由模块接管，其他连接无损交还原网站，因此不需要额外暴露端口或运行独立 AnyTLS 服务。

## 特性

- 网站与 AnyTLS 共用同一个 `443` 入口
- 复用 Caddy 自动 HTTPS 和证书生命周期
- 非 AnyTLS 流量回落真实网站
- 支持多用户、TCP 和 `UDP over TCP v2`
- 支持多个具名出站并按用户选择出口（如部分账号走 WireGuard 家宽、部分直连）
- 默认拒绝私网目标，支持 CIDR、端口和域名策略
- TLS 握手与首包探测采用有界并发，不阻塞 Caddy 的接收循环
- 空闲超时按双向活动刷新，支持单向长时间传输
- 提供会话、探测和代理子流三级资源限制
- 多地址出站共享统一超时预算，并交错尝试 IPv4/IPv6
- 输出结构化审计日志，可选输出节点 URI

## 工作方式

```text
client
  -> Caddy :443
    -> TLS handshake
      -> caddy-anytls 探测解密后的首包
        -> AnyTLS：认证、策略校验、连接目标并转发
        -> HTTP：交还 Caddy 网站处理链路
```

它不是独立代理程序，不自己申请证书，也不替代 Caddy 的网站能力。

## 快速开始

### 1. 准备 Caddyfile

创建 `config` 目录，并将下面的配置保存为 `config/Caddyfile`：

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                user phone-1 replace-with-a-long-random-password
            }
        }
    }
}

example.com {
    header -Server
    respond "server is running"
}
```

部署前必须修改：

- 将 `example.com` 替换为证书可正常签发的真实域名。
- 将示例密码替换为每个用户独立的高强度随机密码。
- 生产环境建议用真实网站替换示例 `respond`。

### 2. 使用预构建镜像

```sh
docker pull ghcr.io/evaneonf/caddy-anytls:latest

docker run -d --name caddy \
  -p 80:80 \
  -p 443:443 \
  -v "$PWD/config:/etc/caddy:ro" \
  -v caddy_data:/data \
  --restart unless-stopped \
  ghcr.io/evaneonf/caddy-anytls:latest
```

`config/Caddyfile` 是需要手动维护的配置文件；`caddy_data` 是 Docker 命名卷，用于持久化证书、私钥等重要运行数据。

### 3. 确认服务

先确认网站可以正常访问，再配置 AnyTLS 客户端：

```sh
curl -I https://example.com
docker logs caddy
```

修改 `config/Caddyfile` 后，可以先检查配置，再让 Caddy 热重载：

```sh
docker exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

默认的 `latest` 与版本标签只包含 `caddy-anytls`。需要使用 WireGuard 出站时，请改用额外包含 `caddy-wireguard` 的预构建变体：

```sh
docker pull ghcr.io/evaneonf/caddy-anytls:wireguard
```

正式版本也提供对应标签，例如 `vX.Y.Z-wireguard`。WireGuard 变体不会替换精简的默认镜像。

## 本地构建

使用 `xcaddy` 构建包含当前模块的 Caddy：

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

也可以直接使用仓库中的 `Dockerfile` 和 `compose.yaml`：

```sh
docker compose up -d --build
```

## 生产配置示例

下面的示例显式展示了资源边界和出站限制。未写出的值与默认值一致，可以按机器规模和用户数量调整。

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                probe_timeout 5s
                idle_timeout 2m
                connect_timeout 10s

                max_pending_probes 256
                max_concurrent 128
                max_streams_per_session 256
                max_concurrent_streams 1024

                fallback true
                allow_private_targets false
                deny_port 25
                deny_cidr 127.0.0.0/8 169.254.0.0/16
                deny_domain .blocked.example

                log_node_info false
                user phone-1 replace-with-a-long-random-password
                user laptop-1 replace-with-another-random-password
            }
        }
    }
}

example.com {
    header -Server
    respond "server is running"
}
```

## 配置参考

### 连接与资源

| Caddyfile 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `probe_timeout` | `5s` | TLS 握手和 TLS 后首包探测超时 |
| `idle_timeout` | `2m` | AnyTLS 会话空闲超时，任一方向有效读写都会刷新 |
| `connect_timeout` | `10s` | DNS 解析与全部候选地址拨号共享的总超时 |
| `max_pending_probes` | `256` | 最大并发 TLS 握手与首包探测数 |
| `max_concurrent` | `128` | 最大并发 AnyTLS 物理会话数 |
| `max_streams_per_session` | `256` | 单条 AnyTLS 会话的最大并发代理子流数 |
| `max_concurrent_streams` | `1024` | 所有会话的全局最大并发代理子流数 |
| `fallback` | `true` | 非 AnyTLS 流量是否交还网站 |
| `padding_scheme` | 上游默认值 | `sing-anytls` padding 策略 |

`max_concurrent` 限制底层 AnyTLS 会话；一条会话可以复用多个目标连接，因此还应保留子流限制。握手和探测并发达到上限后，新连接先在系统监听队列中等待，不会创建无限 goroutine。

### 出站策略

| Caddyfile 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `allow_private_targets` | `false` | 是否允许私网、回环、链路本地等目标 |
| `allow_cidr` / `deny_cidr` | 无 | 按解析后的目标 IP CIDR 放行或拒绝 |
| `allow_port` / `deny_port` | 无 | 按目标端口放行或拒绝 |
| `allow_domain` / `deny_domain` | 无 | 按域名或域名后缀放行或拒绝 |
| `outbound <module> { ... }` | `direct` | 选择默认出站模块，决定认证后的目标流量从哪里发出 |
| `outbound <name> <module> { ... }` | 无 | 声明一个具名出站，供 `user` 或 `default_outbound` 按名引用 |
| `default_outbound <name>` | 无 | 未标注出站的用户使用的具名出站；不写时依次落到单 `outbound`、内置 `direct` |

策略规则：

- `deny_*` 优先于 `allow_*`。
- 配置任意 `allow_*` 后，未命中的对应目标会被拒绝。
- 域名会先解析，再检查所有返回地址，随后只拨号已经检查过的 IP。
- `allow_cidr` 可以精确放行默认私网保护下的受控网段。
- 多个可用地址会在一个 `connect_timeout` 内交错尝试 IPv4/IPv6，而不是逐地址累加超时。

### 用户与节点 URI

| Caddyfile 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `user <name> <password> [outbound]` | 无 | 添加一个启用用户；用户名和密码都必须唯一；第 3 个参数按名引用具名出站（或内置 `direct`），省略走默认出站 |
| `log_node_info` | `false` | 启动或重载时是否把节点 URI 写入日志 |
| `node_host` | 从站点 host matcher 推断 | 节点域名或地址，可配置多个 |
| `node_port` | 从 server listen 推断，通常为 `443` | 节点端口 |
| `node_sni` | 同 `node_host` | 节点 URI 中的 SNI |
| `node_insecure` | `false` | 是否在节点 URI 中输出 `insecure=1` |

## 出站 (outbound)

认证通过后，目标流量默认由运行 Caddy 的这台机器直接发出（内置 `direct` 出站）。你也可以用 `outbound` 指令切换到其它出站模块，把出口流量转发到别处，例如经 WireGuard 隧道从另一台家宽服务器出站，用住宅 IP 出网。

WireGuard 的密钥、端点和隧道地址属于出口资源，应在 `caddy-wireguard` 的全局配置中集中定义；`anytls` 只引用该隧道：

```caddyfile
{
    wireguard {
        tunnel home {
            private_key          <base64 客户端私钥>
            peer_public_key      <base64 服务端公钥>
            endpoint             home.example.com:51820
            address              10.7.0.2
            allowed_ips          0.0.0.0/0 ::/0
            dns                  1.1.1.1
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
```

还可以声明多个具名出站，让不同账号走不同出口（客户端配置多个仅密码不同的节点即可切换）：

```caddyfile
anytls {
    outbound wg-home wireguard {
        tunnel home
    }
    default_outbound wg-home

    user phone-home   replace-with-password-1          # -> 默认（wg-home）
    user phone-direct replace-with-password-2 direct   # -> 内置直连
}
```

- 出站模块注册在 `caddy.listeners.anytls.outbounds` 命名空间下。
- 内置 `direct` 无需配置，是不写 `outbound` 时的默认行为；也可被 `user` 直接按名引用，无需声明。
- 保留名 `direct` 和 `default` 不允许作为具名出站的名字；引用未声明的出站名会在配置阶段报错。
- 未标注出站的用户按 `default_outbound` → 单 `outbound` → 内置 `direct` 的顺序解析默认出口，老配置行为不变。
- 连接建立日志（`anytls connection established`）与节点日志带 `outbound` 字段，标注该连接/该账号实际使用的出站名。
- 域名由认证用户实际选中的出站解析：`direct` 使用宿主机 DNS，隧道出站必须让 DNS 请求经过隧道。
- 出站把解析结果返回 wrapper；wrapper 在拨号前完成私网、CIDR、端口和域名策略校验，然后通过同一出站连接已校验的 IP。
- 推荐在全局块集中配置 WireGuard 隧道，再在 `anytls` 中通过 `tunnel <name>` 引用；这也允许 `reverse_proxy` 等其它模块安全共享同一个 device。
- WireGuard 出站是一个独立仓库 [`github.com/lihuaye/caddy-wireguard`](https://github.com/lihuaye/caddy-wireguard)，用户态实现（wireguard-go + netstack），无需内核模块、TUN 设备或 root。构建方式：

预构建镜像：

```sh
docker pull ghcr.io/evaneonf/caddy-anytls:wireguard
```

或自行构建：

```sh
xcaddy build \
    --with github.com/evaneonf/caddy-anytls \
    --with github.com/lihuaye/caddy-wireguard@v0.1.0
```

配置项、密钥生成和家宽侧准备见该仓库的 README。

## 获取客户端 URI

如需临时获取客户端 URI，可在现有 `listener_wrappers` 的 `anytls` 配置块中加入：

```caddyfile
anytls {
    log_node_info true
    node_host example.com
    user phone-1 replace-with-a-long-random-password
}
```

重载后查找 `event=anytls_node`：

```sh
docker logs caddy-anytls 2>&1 | grep anytls_node
```

日志中的 `uri` 可以直接用于客户端，例如：

```text
anytls://replace-with-a-long-random-password@example.com/
```

URI 中包含完整密码。获取后应重新关闭 `log_node_info`，并避免把相关日志发送到不受控的日志平台。

如果未配置 `node_host`，模块会尝试从 Caddy 站点的 host matcher 推断；通配符和 placeholder 不会用于生成节点 URI。

JSON 配置使用相应的复数数组字段，例如 `users`、`allow_cidrs`、`deny_ports`、`node_hosts`。完整示例见 [docs/examples.md](docs/examples.md)。

## 运行行为与限制

- 普通 HTTPS 请求照常进入网站。
- AnyTLS 客户端在 TLS 后被模块接管。
- `sp.v2.udp-over-tcp.arpa` 按 `UDP over TCP v2` 处理。
- 已禁用用户命中 AnyTLS 首包时会被拒绝，不会回落网站。
- UDP 目标解析在单条代理子流内缓存 30 秒，缓存最多保留 256 个目标。
- 配置 reload 或模块卸载会主动结束已有 AnyTLS 会话。
- 一条 AnyTLS 会话复用单条 TCP，弱网丢包可能使该会话内的多个子流同时受队头阻塞；这是协议层限制。
- 网站回落可以降低未认证主动探测特征，但不能隐藏 SNI、证书、客户端 TLS 指纹或所有流量时序特征。

## 日志

模块输出结构化日志。常见字段包括：

- `connection_id`、`event`、`outcome`、`reason`
- `protocol`、`uot_is_connect`
- `user`、`outbound`、`source`、`destination`
- `duration`
- `bytes_from_client`、`bytes_to_client`
- `bytes_from_target`、`bytes_to_target`

同一个 `connection_id` 可以对应多个目标地址，因为它标识底层 AnyTLS 会话，而不是单个复用子流。

常见事件包括认证成功、网站 fallback、用户或策略拒绝、出站失败、relay 关闭和配置卸载。公网无效 TLS 握手仅记录为 Debug，避免扫描流量放大 Warn 日志；字节计数也只在 Debug 日志开启时采集。

## 开发与验证

```sh
go test ./...
go test -race ./...
go vet ./...
staticcheck ./...
golangci-lint run
```

## 更多文档

- [产品说明](docs/product.md)
- [技术设计](docs/technical-design.md)
- [配置示例](docs/examples.md)
- [容器说明](docs/container.md)
- [发布说明](docs/release.md)

## License

本项目采用 `GPL-3.0-or-later`。
