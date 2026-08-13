# 容器构建与发布

## 概述

仓库提供了用于本地构建和发布的容器文件，包括根目录下的 [Dockerfile](../Dockerfile) 与 [compose.yaml](../compose.yaml)。镜像只包含 Caddy 和 `caddy-anytls`，并以标准 Caddy 运行镜像作为最终运行环境。

## 本地构建

在仓库根目录执行：

```sh
docker build -t caddy-anytls:local .
```

当前镜像构建流程包括：

- 构建阶段基于 [Dockerfile](../Dockerfile) 中的 `caddy:<version>-builder`
- 构建阶段通过 `xcaddy` 将当前仓库模块编译进 `caddy`
- 运行阶段基于 [Dockerfile](../Dockerfile) 中的 `caddy:<version>`
- Caddy 镜像版本应与 [go.mod](../go.mod) 中的 `github.com/caddyserver/caddy/v2` 保持一致，CI 会校验这一点

## 本地运行

仓库已提供最小可运行配置：

- [config/Caddyfile](../config/Caddyfile)
- [compose.yaml](../compose.yaml)

使用前应至少完成以下修改：

- 将示例域名替换为实际部署域名
- 为 AnyTLS 用户设置强密码

如需调整超时、并发、回落或出站选择，可参考 [examples.md](examples.md) 与 [README.md](../README.md)。

默认 [config/Caddyfile](../config/Caddyfile) 关闭 `log_node_info`，避免节点密码进入常规日志。只有在日志访问权限可控且确实需要输出节点 URI 时才临时开启；输出的 `uri` 字段包含完整密码。

## Docker Compose

通过以下命令启动本地环境：

```sh
docker compose up -d --build
```

默认 Compose 配置会挂载以下内容：

- `./config:/etc/caddy:ro`
- `caddy_data:/data`

其中 `./config` 是宿主机上手动维护的配置目录，`caddy_data` 用于持久化证书和私钥等 Caddy 数据。

## 自动发布

仓库提供 GitHub Actions 工作流 [docker.yml](../.github/workflows/docker.yml)，用于构建并发布多架构镜像。

### 触发条件

工作流在以下场景触发：

- 向 `main` 分支推送相关代码变更
- 推送匹配 `v*` 的 Git tag
- 手动触发 `workflow_dispatch`
- 每日定时运行
- 提交涉及容器或 Go 代码的 Pull Request

### 发布行为

工作流的发布策略如下：

- Pull Request 执行代码检查，并构建一次 amd64 smoke 镜像，验证模块注册与 Caddyfile 适配；不会推送镜像
- `main` push 只执行轻量代码检查
- 定时运行会执行完整检查，并且仅在 Docker 或 Go 输入有变化时推送 `main` 镜像
- 手动触发会执行完整检查并推送镜像
- `v*` tag 会执行完整检查、推送版本镜像并更新 `latest`
- 发布目标架构为 `linux/amd64` 和 `linux/arm64`
- 使用 GitHub Actions 缓存加速 `buildx` 构建

## 镜像地址与标签

镜像发布地址为：

```text
ghcr.io/<owner>/<repo>
```

若仓库为 `evaneonf/caddy-anytls`，则镜像地址为：

```text
ghcr.io/evaneonf/caddy-anytls
```

当前标签策略为：分支和定时发布使用 `main`，Git tag 发布使用 `vX.Y.Z`，正式版本同时更新滚动标签 `latest`。

## 发布前提

自动发布依赖以下前提条件：

- 仓库已启用 GitHub Actions
- 工作流具备 `packages: write` 权限
- `GITHUB_TOKEN` 允许向 GHCR 推送包
