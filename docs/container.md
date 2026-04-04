# 容器构建与发布

## 概述

仓库提供了用于本地构建和发布的容器文件，包括根目录下的 [Dockerfile](../Dockerfile) 与 [compose.yaml](../compose.yaml)。容器镜像的目标是产出一个包含 `caddy-anytls` 模块的自定义 `caddy` 可执行文件，并以标准 Caddy 运行镜像作为最终运行环境。

## 本地构建

在仓库根目录执行：

```sh
docker build -t caddy-anytls:local .
```

当前镜像构建流程分为两个阶段：

- 构建阶段基于 `caddy:2.10.2-builder`
- 通过 `xcaddy` 将当前仓库模块编译进 `caddy`
- 运行阶段基于 `caddy:2.10.2`

## 本地运行

仓库已提供最小可运行配置：

- [Caddyfile](../Caddyfile)
- [compose.yaml](../compose.yaml)

使用前应至少完成以下修改：

- 将示例域名替换为实际部署域名
- 为 AnyTLS 用户设置强密码

如需调整超时、并发、回落或私网目标策略，可参考 [examples.md](examples.md) 与 [README.md](../README.md)。

## Docker Compose

通过以下命令启动本地环境：

```sh
docker compose up -d --build
```

默认 Compose 配置会挂载以下内容：

- `./Caddyfile:/etc/caddy/Caddyfile:ro`
- `caddy_data:/data`
- `caddy_config:/config`

其中 `/data` 与 `/config` 分别用于持久化 Caddy 数据和运行配置。

## 自动发布

仓库提供 GitHub Actions 工作流 [docker.yml](../.github/workflows/docker.yml)，用于构建并发布多架构镜像。

### 触发条件

工作流在以下场景触发：

- 向 `main` 分支推送相关代码变更
- 推送匹配 `v*` 的 Git tag
- 手动触发 `workflow_dispatch`
- 提交涉及容器或 Go 代码的 Pull Request

### 发布行为

工作流的发布策略如下：

- Pull Request 只执行构建验证，不推送镜像
- 非 Pull Request 事件会登录 GHCR 并推送镜像
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

当前标签策略如下：

- 分支推送生成对应分支名标签，例如 `main`
- 默认分支额外生成 `latest`
- Git tag 推送生成同名镜像标签，例如 `v0.1.0`

## 发布前提

自动发布依赖以下前提条件：

- 仓库已启用 GitHub Actions
- 工作流具备 `packages: write` 权限
- `GITHUB_TOKEN` 允许向 GHCR 推送包
