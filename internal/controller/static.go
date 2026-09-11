package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// ============================================================
// 静态资源服务 + CDN/缓存策略
//
// 部署形态：Controller 源站 → Cloudflare（自定义域名）→ 浏览器。
// 边缘缓存默认按文件后缀与启发式规则决定，因此源站必须显式声明策略，
// 否则会出现两类问题：
//   - 面板 HTML 被边缘长时间缓存 → 发布新版本后用户仍看到旧界面；
//   - 静态资源每次访问都回源（无 ETag）→ 边缘缓存命中率低、用户首屏变慢。
//
// 本文件的策略：
//   - HTML：Cache-Control: no-cache（每次都回源校验，ETag 命中即 304）。
//     保证发布后刷新页面立即生效，同时把回源流量压到几百字节的 304。
//   - 带内容版本的资源（URL 含 ?v=…）：public, max-age=31536000, immutable
//     ——URL 变化才需要重新下载，可放心长缓存。
//   - 其他静态资源（svg/ico/js/css）：public, max-age=86400 +
//     stale-while-revalidate，配合强 ETag；升级后最多 1 天边缘自动更新。
//   - 所有静态响应带强校验器 ETag（内容 SHA-256），支持 If-None-Match/304。
//
// /api/* 与 /ws 一律 no-store（见 securityHeaders），避免共享缓存
// 保存带权限差异的响应。
// ============================================================

type staticAssets struct {
	fsys  fs.FS
	etags map[string]string // 资源名 → 强 ETag（"<sha256 前 32 位>"）
}

func newStaticAssets(fsys fs.FS) *staticAssets {
	sa := &staticAssets{fsys: fsys, etags: make(map[string]string)}
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		sa.etags[p] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	return sa
}

// resolve 把 URL 路径映射到嵌入资源名（目录 → index.html）。
// 返回空字符串表示不存在（或非法路径）。
func (sa *staticAssets) resolve(urlPath string) string {
	p := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	switch {
	case p == "" || p == ".":
		p = "index.html"
	case strings.HasSuffix(urlPath, "/"):
		p = path.Join(p, "index.html")
	}
	if _, ok := sa.etags[p]; !ok {
		return ""
	}
	return p
}

// serve 输出指定嵌入资源。
func (sa *staticAssets) serve(w http.ResponseWriter, r *http.Request, name string) {
	etag, ok := sa.etags[name]
	if !ok {
		noCache(w)
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(sa.fsys, name)
	if err != nil {
		noCache(w)
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("ETag", etag)
	cc, cdnCC := staticCachePolicy(name, r.URL.RawQuery)
	h.Set("Cache-Control", cc)
	// CDN-Cache-Control（RFC 9211）：单独声明"边缘"缓存策略。
	// Cloudflare 默认按 Cache-Control 决定边缘 TTL，但一旦有人开了
	// Cache Rule / "Cache Everything"，只有 CDN-Cache-Control 能保住
	// "HTML 与 404 绝不进边缘缓存"这条底线（实测：源站不发 Cache-Control 时
	// 边缘会把 404 也缓存 4 小时）。
	h.Set("CDN-Cache-Control", cdnCC)
	// ServeContent 负责 Content-Type（按后缀）、Range、If-None-Match → 304。
	// modTime 传零值：嵌入资源的构建时间无意义，避免误导性的 Last-Modified。
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (sa *staticAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := sa.resolve(r.URL.Path)
	if name == "" {
		noCache(w)
		http.NotFound(w, r)
		return
	}
	sa.serve(w, r, name)
}

// staticCachePolicy 按资源类型与是否带内容版本给出（浏览器策略, 边缘策略）。
//
// 浏览器维度与边缘维度分开声明：
//   - HTML：浏览器必须每次回源校验（no-cache + ETag → 304），边缘绝不存储；
//   - 带 ?v= 的资源：两边都可长缓存（URL 即内容标识）；
//   - 其他资源：边缘可留久一点（7 天，发布后仍能命中），浏览器 1 天 +
//     stale-while-revalidate，兼顾"部署后尽快见到新文件"与"少回源"。
func staticCachePolicy(name, rawQuery string) (browser, edge string) {
	if strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".htm") {
		// 面板入口：必须回源校验，保证发布后立刻生效（304 开销极小）。
		// 边缘 no-store：面板是登录态入口，绝不能出现"旧界面"或跨版本混用。
		return "no-cache", "no-store"
	}
	if hasVersionQuery(rawQuery) {
		// ?v=<内容版本>：URL 即内容标识，可长缓存 + immutable
		return "public, max-age=31536000, immutable", "public, max-age=31536000"
	}
	return "public, max-age=86400, stale-while-revalidate=86400", "public, max-age=604800"
}

// staticCacheControl 兼容旧调用：仅返回浏览器维度策略。
func staticCacheControl(name, rawQuery string) string {
	browser, _ := staticCachePolicy(name, rawQuery)
	return browser
}

func hasVersionQuery(rawQuery string) bool {
	for _, kv := range strings.Split(rawQuery, "&") {
		if strings.HasPrefix(kv, "v=") && len(kv) > 2 {
			return true
		}
	}
	return false
}

func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("CDN-Cache-Control", "no-store")
}

// securityHeaders 统一追加安全响应头，并对 API/WS 禁用共享缓存。
//
// CSP 说明：Alpine 标准版用 new Function 求值 x- 表达式，且页面含内联
// <script>/<style>，因此必须允许 'unsafe-inline' 与 'unsafe-eval'；
// 但 **不允许任何外部脚本源**——第三方 CDN 依赖已改为自托管
// （web/static/vendor），外链脚本一旦被注入即可下发攻击，必须堵死。
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self' data:; " +
		"connect-src 'self' ws: wss:; " +
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		// 面板不用于被嵌入；防点击劫持（与 CSP frame-ancestors 双保险）
		h.Set("X-Frame-Options", "DENY")

		// 带凭据/状态差异的响应绝不能被任何共享缓存保存：
		// API 与 WebSocket 显式 no-store，并声明按 Authorization 变化。
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
			h.Set("Cache-Control", "no-store")
			h.Set("CDN-Cache-Control", "no-store")
			h.Set("Vary", "Authorization")
		}
		next.ServeHTTP(w, r)
	})
}
