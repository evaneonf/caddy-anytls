# Caddy AnyTLS Module

把 AnyTLS 做成 Caddy 内的能力，让网站和代理共用 443，由 Caddy 自动管理 TLS 证书，AnyTLS 只处理 TLS 解密后的应用层数据，识别失败自动回落到网站。

## 是什么

这是一个 Caddy 扩展能力，不是独立代理软件。

对用户来说，它应该表现为：

- 继续使用 Caddy 部署网站
- 在同一个 443 上额外启用 AnyTLS
- 用一个域名给网站，一个域名给代理，或在同一站点入口下启用协议识别
- 不再手工维护代理证书

## 职责边界

这个项目不是把所有能力都自己重写一遍，而是把几层现有能力接起来：

- `Caddy`
  负责 `443` 监听、TLS 握手、证书生命周期、HTTP 站点路由和 reload 生命周期。

- `github.com/anytls/sing-anytls`
  负责 AnyTLS 协议本身，包括用户认证、会话建立，以及把认证后的连接和目标地址交给上层 handler。

- `github.com/sagernet/sing/common/uot`
  负责 `UDP over TCP` 的协议格式和帧编解码，包括 `sp.v2.udp-over-tcp.arpa` 这样的保留目标语义。

- `caddy-anytls`
  负责把这些能力接进 Caddy：TLS 后识别、网站 fallback、AnyTLS 接管、真实出站桥接、结构化日志、会话管理和产品级行为语义。

可以把调用链理解成：

```text
Caddy TLS/网站入口
    -> caddy-anytls 做分流和产品语义
        -> sing-anytls 做 AnyTLS 协议
            -> uot 做 UDP-over-TCP 编解码
                -> caddy-anytls 再负责真实出站桥接
```

## 当前能力

- 网站和 AnyTLS 共用同一个 `443`
- TLS 和证书完全复用 Caddy 自动 HTTPS
- AnyTLS 识别发生在 TLS 解密之后
- 非 AnyTLS 流量回落到网站
- 支持多用户
- 支持基础出站转发
- 支持 `UDP over TCP v2` 目标
- 支持结构化审计日志
- 支持 Caddyfile `listener_wrappers` 配置

## 当前行为语义

- 命中已禁用用户的 AnyTLS 首包会被直接拒绝，不回落网站
- 配置 reload / 卸载时，现有 AnyTLS 会话会被主动终止
- 网站请求链路尽量不受上面这条策略影响
- 默认拒绝常见私网目标地址

## 快速开始

### 1. 构建

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

### 2. 构建容器镜像

```sh
docker build -t caddy-anytls:local .
```

这个镜像会把当前仓库源码编进一个自定义 `caddy` 二进制。

### 3. 使用默认 Caddyfile 启动

仓库已经包含一个可直接挂载的默认 [Caddyfile](Caddyfile)。

在真正部署前，至少要改两处：

- 把 `example.com` 改成你的真实域名
- 把 `change-this-password` 改成强密码

### 4. 使用 Docker Compose 启动

```sh
docker compose up -d --build
```

仓库已包含默认 [compose.yaml](compose.yaml)，会挂载：

- `./Caddyfile -> /etc/caddy/Caddyfile`
- `caddy_data -> /data`
- `caddy_config -> /config`

### 5. 最小 Caddyfile

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

### 6. 启动后效果

- 普通 HTTPS 请求继续进入网站
- AnyTLS 客户端流量由模块在 TLS 后接管
- `sp.v2.udp-over-tcp.arpa` 会按 `UDP over TCP v2` 语义处理，不会被当普通 DNS 名称解析
- 证书申请和续期仍由 Caddy 负责

## 容器发布

仓库已包含：

- [Dockerfile](Dockerfile)
- [.github/workflows/docker.yml](.github/workflows/docker.yml)

GitHub Actions 会在以下场景自动构建镜像：

- push 到 `main`
- push `v*` tag
- 手工触发 `workflow_dispatch`

镜像会发布到：

- `ghcr.io/<owner>/<repo>`

常见 tag 规则：

- `main`
- `latest`（默认分支）
- Git tag 名称，例如 `v0.1.0`

发布架构：

- `linux/amd64`
- `linux/arm64`

## 配置项

- 最小必需配置通常只有：
  - 站点域名
  - 至少一个 `user <name> <password>`

其余参数都可以先省略，模块会使用默认值。

当前默认值来源有两类：

- 模块自身在 `Provision()` 中设置的默认值
- 上游 `sing-anytls` 直接提供的协议默认值

默认值如下：

- `probe_timeout = 5s`
  来源：模块默认值
  理由：给 TLS 后首包探测留足够余量，首版偏保守

- `idle_timeout = 2m`
  来源：模块默认值
  理由：避免空闲代理会话长期占用资源，同时不至于过短

- `connect_timeout = 10s`
  来源：模块默认值
  理由：作为出站拨号超时较稳妥，失败时也不会拖太久

- `max_concurrent = 128`
  来源：模块默认值
  理由：首版给中小规模部署一个保守上限，防止无限制占用资源

- `fallback = true`
  来源：模块默认值
  理由：符合“网站和 AnyTLS 共存”的产品目标

- `allow_private_targets = false`
  来源：Go 零值和模块行为
  理由：默认拒绝常见私网目标，优先保证安全边界

- `padding_scheme = sing-anytls default`
  来源：上游 `sing-anytls/padding.DefaultPaddingScheme`
  理由：直接复用协议实现的默认 padding，优先保证兼容性

- `probe_timeout`: 首包探测超时
- `idle_timeout`: AnyTLS 会话空闲超时
- `connect_timeout`: 出站拨号超时
- `max_concurrent`: 最大并发 AnyTLS 会话数
- `fallback`: 是否允许非 AnyTLS 流量回落网站
- `allow_private_targets`: 是否允许访问常见私网目标
- `user <name> <password>`: 添加一个启用状态的 AnyTLS 用户

## 审计日志

当前日志会输出这些结构化字段：

- `connection_id`
- `event`
- `outcome`
- `reason`
- `protocol`
- `uot_is_connect`（仅 `UDP over TCP v2`）
- `user`
- `source`
- `destination`
- `duration`

典型事件包括：

- AnyTLS 会话认证成功
- 非 AnyTLS 流量回落网站
- 已禁用用户命中后拒绝
- 私网目标拒绝
- 配置卸载导致的会话终止

## 适用边界

- 这是首版实现，不是完整的策略网关
- 当前不包含更细粒度 ACL
- 当前没有管理接口和指标导出
- 旧 AnyTLS 会话不会跨配置代际保活

## 文档

- 详细产品文档见 [docs/product.md](docs/product.md)
- 技术设计见 [docs/technical-design.md](docs/technical-design.md)
- 容器说明见 [docs/container.md](docs/container.md)
- 配置示例见 [docs/examples.md](docs/examples.md)
- 发布说明见 [docs/release.md](docs/release.md)

## 许可证

本项目按 `GPL-3.0-or-later` 分发。

原因：

- 当前实现直接集成 `github.com/anytls/sing-anytls`
- 上游 `sing-anytls` 的 `LICENSE` 原文为 GPL-3.0-or-later
- 本项目作为链接并分发该依赖的 Caddy 模块，需要采用与其兼容的许可证策略
