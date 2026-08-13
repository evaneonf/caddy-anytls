# 发布说明

## 发布定位

当前仓库已经具备首版公开发布的基本条件。对外发布时，建议将其定位为一个运行在 Caddy 内部的 AnyTLS 接入模块，而不是独立代理服务。

当前版本具备以下基础能力：

- 可通过 `xcaddy` 构建
- 支持 Caddyfile `listener_wrappers` 配置
- 已接入 `sing-anytls` 协议实现
- 已覆盖网站 fallback、AnyTLS 转发、UDP over TCP、禁用用户拒绝、出站策略和配置卸载会话终止等关键测试
- 支持端口、域名和 CIDR 出站策略
- 支持启动或重载后在 Caddy 日志输出当前可用 AnyTLS 节点 URI

## 对外说明建议

发布说明应保持与当前实现一致，建议突出以下几点：

- 模块复用 Caddy 自动 HTTPS，不单独管理证书
- 网站与 AnyTLS 共用同一 `443` 入口
- 非 AnyTLS 流量继续进入网站链路
- 已禁用用户命中的新连接会被拒绝
- 默认拒绝私网目标，并会检查域名解析后的所有地址
- 出站 `deny_*` 策略优先于 `allow_*` 策略
- 配置重载或卸载时，已有 AnyTLS 会话会被终止

这些行为属于当前版本的重要边界，发布文案应保持一致。

## 发布前检查

建议在发布前完成以下检查：

- 确认 [README.md](../README.md) 中的构建步骤和最小示例可直接使用
- 确认 `go test ./...` 通过
- 确认 `go test -race ./...` 通过
- 确认 `go vet ./...` 通过
- 确认 `staticcheck ./...` 通过
- 确认 `golangci-lint run` 通过
- 确认 `go mod verify` 通过
- 确认 `core` 与 `wireguard` Docker targets 都能构建
- 确认 WireGuard 镜像包含 `caddy.listeners.anytls.outbounds.wireguard`，并能适配测试 Caddyfile
- 确认许可证文件与仓库说明一致
- 确认文档没有承诺当前尚未实现的能力

## 当前边界

当前尚未覆盖的范围：

- 管理 API
- Prometheus 指标导出
- 多协议网关能力
- 跨配置代际的会话保活
