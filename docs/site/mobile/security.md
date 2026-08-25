# 移动端安全

## 不要把 boxd key 打包进 App

JavaScript bundle、IPA、APK 和运行内存都不能保护长期服务端 secret。即使使用 Keychain/Keystore，首次下发后的高权限 key 仍可在越狱、调试或代理环境中被提取。

推荐做法：

- boxd key 仅保存在应用后端或受控 secret manager；
- App 使用自己的短期 user access token；
- 应用后端执行 user → tenant → Box ownership 检查；
- 为后端创建最小 scope、可撤销、带 expiry 的 boxd key；
- destructive action 在 App 与后端都做确认/授权；
- 日志只记录 request id、resource id 和结果，不记录 key、prompt secret 或文件正文。

## Preview 与 Terminal

- Preview URL 是带时效 capability，仍不要写入 analytics 或公开 crash report；
- Terminal ticket 60 秒、单用途，只应在用户明确打开 Terminal 时获取；
- App 不得尝试重用 Console cookie、CSRF token 或 terminal ticket；
- WebView 打开 Preview 时禁用不必要 bridge，并限制外部跳转。

## 生命周期

- App 切后台时断开实时订阅，但不要自动 cancel run；
- 返回前台先 refresh status，再恢复可用动作；
- 对 401 清理 App session，不在无限循环中刷新；
- 对 429 尊重服务端 backoff；
- 对 501 缓存为部署 capability，避免重复尝试。
