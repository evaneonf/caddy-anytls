# 容器构建与发布

## 本地构建

```sh
docker build -t caddy-anytls:local .
```

镜像构建方式：

- 使用 `caddy:2.10.2-builder` 作为构建阶段
- 用 `xcaddy` 将当前仓库模块编进 `caddy`
- 最终运行镜像基于 `caddy:2.10.2`

## 默认运行文件

仓库已包含：

- [Caddyfile](../Caddyfile)
- [compose.yaml](../compose.yaml)

使用前请至少修改：

- 站点域名
- AnyTLS 用户密码

默认 `Caddyfile` 只保留最小可用配置。
如果需要调超时、并发、fallback 或私网目标策略，请参考 [examples.md](examples.md) 和 [README.md](../README.md) 中的参数说明。

## Docker Compose

```sh
docker compose up -d --build
```

默认 compose 会挂载：

- `./Caddyfile:/etc/caddy/Caddyfile:ro`
- `caddy_data:/data`
- `caddy_config:/config`

## GitHub Actions 自动发布

仓库工作流文件：

- `.github/workflows/docker.yml`

触发条件：

- push 到 `main`
- push `v*` tag
- `workflow_dispatch`

行为：

- PR 只构建，不推送
- 非 PR 事件登录 GHCR 并推送镜像
- 使用 GitHub Actions cache 加速 Docker buildx
- 发布 `linux/amd64` 和 `linux/arm64` 多架构镜像

## 发布地址

镜像会推送到：

```text
ghcr.io/<owner>/<repo>
```

例如仓库是 `evaneonf/caddy-anytls`，则镜像地址为：

```text
ghcr.io/evaneonf/caddy-anytls
```

## Tag 策略

- 分支 push: 分支名 tag，例如 `main`
- 默认分支: 额外生成 `latest`
- Git tag push: 同名镜像 tag，例如 `v0.1.0`

## 使用前提

- 仓库需要启用 GitHub Actions
- workflow 需要有 `packages: write` 权限
- 发布者需要允许 `GITHUB_TOKEN` 向 GHCR 推送包
