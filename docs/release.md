# 发布说明

## 当前发布定位

当前仓库已经具备首版公开发布的基础条件：

- 可通过 `xcaddy` 构建
- 已支持 Caddyfile `listener_wrappers` 配置
- 已接入真实 `sing-anytls` 会话处理
- 已覆盖网站 fallback、AnyTLS 转发、禁用用户拒绝、配置卸载终止会话等测试

## 对外行为说明

发布时建议明确告诉用户：

- 本模块复用 Caddy 自动 HTTPS，不单独管理证书
- 非 AnyTLS 流量继续进入网站
- 已禁用用户的 AnyTLS 首包不会回落网站，而是直接拒绝
- 配置 reload / 卸载时，已有 AnyTLS 会话会被主动终止

## 发布前检查

- 确认 README 中的构建和最小配置示例可直接运行
- 确认 `go vet ./...` 通过
- 确认 `go test ./...` 通过
- 确认许可证文件为 `GPL-3.0-or-later`
- 确认文档中没有仍然承诺“旧 AnyTLS 会话跨 reload 保活”

## 当前已知边界

- 没有更细的 ACL
- 没有管理 API
- 没有指标导出
- 目前主要聚焦单协议 AnyTLS

## 建议的首个公开版本说明

如果要打首个对外版本，建议在 release note 里突出：

- Caddy 内单端口 AnyTLS 接入
- TLS 和证书完全复用 Caddy
- 网站 fallback
- 多用户
- 结构化审计日志
- reload 时会主动终止旧 AnyTLS 会话
