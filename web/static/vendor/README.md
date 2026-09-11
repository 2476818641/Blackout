# 前端第三方依赖（自托管）

本目录的第三方文件随二进制一起 go:embed 分发，不再从公网 CDN 加载。原因：

1. **供应链**：`cdn.jsdelivr.net/npm/alpinejs@3.x.x` 是浮动版本 + 无 SRI，
   CDN 侧内容变化或劫持会直接进到 dashboard（控制台可下发攻击）。
2. **可用性**：内网/被墙/断网的部署环境加载不到 CDN，面板白屏。
3. **Cloudflare 缓存**：同源文件可长期缓存（`immutable`），不受第三方 CDN
   缓存策略与跨域协商影响；也让 CSP 可以收紧到 `script-src 'self'`。

| 文件 | 版本 | 许可 | 来源 | SHA-256 |
|---|---|---|---|---|
| `alpine.min.js` | 3.14.9 | MIT | https://cdn.jsdelivr.net/npm/alpinejs@3.14.9/dist/cdn.min.js | `3ed1eed252488921df65e363d6715deb04d7f92aaedb9e52199fdf73cb1e0ad3` |

升级步骤：下载新版本 → 替换文件 → 更新上表版本与哈希 → 同步
`web/static/index.html`、`web/static/pool.html` 中的 `?v=` 版本号（用于
让 Cloudflare 与浏览器立刻拿到新文件）。
