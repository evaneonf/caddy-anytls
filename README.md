# caddy-anytls

`caddy-anytls` 是一个 Caddy listener wrapper，用来把 AnyTLS 接到现有的 Caddy `443` 入口里。

它解决的是下面几件事：

- 网站和 AnyTLS 共用同一个 `443`
- TLS 握手和证书续期继续交给 Caddy
- 非 AnyTLS 流量继续走网站，不需要额外做端口分流

如果你已经在用 Caddy 托管站点，但不想再单独维护一套 AnyTLS 服务端和证书，这个项目就是为这个场景准备的。

## 为什么要做这个

常见的部署方式里，网站和代理往往是两套入口：

- 网站占用 `443`
- 代理另外开端口，或者自己接管 TLS
- 证书、续期、监听和运维流程也分成两套

`caddy-anytls` 的做法是把 AnyTLS 放进 Caddy 现有的连接处理链里。Caddy 继续负责 TLS 和网站路由，这个模块只在 TLS 解密之后识别 AnyTLS 首包；识别成功就接管连接，识别失败就把连接交还给网站。

## 特性

- 与网站共用同一个 `443` 监听端口
- 完全复用 Caddy 自动 HTTPS 和证书管理
- AnyTLS 识别发生在 TLS 解密之后
- 非 AnyTLS 流量自动回落到正常网站链路
- 支持多用户
- 支持基础 TCP 转发
- 支持 `UDP over TCP v2`
- 输出结构化审计日志
- 支持在 Caddyfile 的 `listener_wrappers` 中启用

## 工作方式

可以把连接路径理解成：

```text
client
  -> Caddy :443
    -> TLS handshake
      -> caddy-anytls 检测 TLS 后首包
        -> 是 AnyTLS：进入认证和转发流程
        -> 不是 AnyTLS：回落到网站
```

这个项目不是独立代理程序，而是 Caddy 的一个扩展模块。它不自己管理证书，也不替代 Caddy 的 HTTP 站点能力。

## 快速开始

### 1. 构建带模块的 Caddy

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

### 2. 准备最小配置

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                user phone-1 replace-with-strong-password
            }
        }
    }
}

example.com {
    respond "server is running"
}
```

使用前至少改两处：

- 把 `example.com` 换成真实域名
- 把 `replace-with-strong-password` 换成强密码

### 3. 启动后会发生什么

- 普通 HTTPS 请求照常进入网站
- AnyTLS 客户端连接会在 TLS 后被模块接管
- `sp.v2.udp-over-tcp.arpa` 会按 `UDP over TCP v2` 保留目标处理
- 证书申请和续期仍由 Caddy 负责

## Docker

可以直接使用预先构建好的镜像：

- `docker pull ghcr.io/evaneonf/caddy-anytls:latest`
- 包地址：https://github.com/evaneonf/caddy-anytls/pkgs/container/caddy-anytls

仓库也包含可直接使用的 [Dockerfile](Dockerfile)、[compose.yaml](compose.yaml) 和默认 [Caddyfile](Caddyfile)。

本地构建镜像：

```sh
docker build -t caddy-anytls:local .
```

使用 Compose 启动：

```sh
docker compose up -d --build
```

默认会挂载：

- `./Caddyfile -> /etc/caddy/Caddyfile`
- `caddy_data -> /data`
- `caddy_config -> /config`

## 配置

大多数场景下，最小必需配置只有两项：

- 站点域名
- 至少一个 `user <name> <password>`

### Caddyfile

目前支持的主要配置项如下：

| 配置项                   | 默认值               | 说明                       |
| ------------------------ | -------------------- | -------------------------- |
| `probe_timeout`          | `5s`                 | TLS 后首包探测超时         |
| `idle_timeout`           | `2m`                 | AnyTLS 会话空闲超时        |
| `connect_timeout`        | `10s`                | 出站拨号超时               |
| `max_concurrent`         | `128`                | 最大并发 AnyTLS 会话数     |
| `fallback`               | `true`               | 非 AnyTLS 流量是否回落网站 |
| `allow_private_targets`  | `false`              | 是否允许访问常见私网目标   |
| `padding_scheme`         | `sing-anytls` 默认值 | AnyTLS padding 策略        |
| `user <name> <password>` | 无                   | 添加一个启用状态的用户     |

`name` 是这个模块里的运维标识，不是协议层强制字段。它主要用于区分设备、管理用户和标记日志。

### JSON

如果你使用 JSON 配置，模块挂在 HTTP server 的 `listener_wrappers` 下：

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
    }
  ]
}
```

## 当前行为

下面这些行为是当前版本明确成立的：

- 已禁用用户命中 AnyTLS 首包时会被直接拒绝，不会回落到网站
- 配置 `reload` 或卸载时，现有 AnyTLS 会话会被主动终止
- 网站请求链路尽量不受上面这条策略影响
- 默认拒绝常见私网目标地址

## 日志

当前会输出结构化审计字段，包括：

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

典型事件包括认证成功、网站 fallback、禁用用户拒绝、私网目标拒绝，以及配置卸载导致的会话终止。

## 文档

- 产品说明见 [docs/product.md](docs/product.md)
- 技术设计见 [docs/technical-design.md](docs/technical-design.md)
- 容器说明见 [docs/container.md](docs/container.md)
- 配置示例见 [docs/examples.md](docs/examples.md)
- 发布说明见 [docs/release.md](docs/release.md)

## License

本项目采用 `GPL-3.0-or-later`。
