package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func newStaticTestMux() http.Handler {
	c := &Ctrl{
		adminToken:     "admin-tok",
		workerToken:    "shared-worker-tok",
		workerTokens:   map[string]bool{},
		workerTokensMu: sync.RWMutex{},
		auditLog:       NewAuditLog("", 200),
	}
	return securityHeaders(corsMiddleware(c.routes()))
}

// TestStaticCacheControlPolicy Cloudflare 场景下的边缘缓存策略必须显式声明：
// HTML 回源校验（发布即生效），带内容版本的资源长缓存，其余短缓存 + 重验证。
func TestStaticCacheControlPolicy(t *testing.T) {
	cases := []struct {
		name, query, want string
	}{
		{"index.html", "", "no-cache"},
		{"pool.html", "", "no-cache"},
		{"vendor/alpine.min.js", "v=3.14.9", "public, max-age=31536000, immutable"},
		{"vendor/alpine.min.js", "", "public, max-age=86400, stale-while-revalidate=86400"},
		{"blackout.svg", "", "public, max-age=86400, stale-while-revalidate=86400"},
	}
	for _, tc := range cases {
		if got := staticCacheControl(tc.name, tc.query); got != tc.want {
			t.Errorf("staticCacheControl(%q, %q) = %q, want %q", tc.name, tc.query, got, tc.want)
		}
	}
}

// TestStaticEdgeCachePolicy CDN-Cache-Control 必须独立声明边缘策略：
// HTML/404 绝不进边缘缓存（实测：源站不发 Cache-Control 时 Cloudflare 会把
// 404 缓存 4 小时，部署新资源后被缓存的 404 会让页面加载失败）。
func TestStaticEdgeCachePolicy(t *testing.T) {
	cases := []struct {
		name, query, wantEdge string
	}{
		{"index.html", "", "no-store"},
		{"pool.html", "", "no-store"},
		{"vendor/alpine.min.js", "v=3.14.9", "public, max-age=31536000"},
		{"blackout.svg", "", "public, max-age=604800"},
	}
	for _, tc := range cases {
		_, edge := staticCachePolicy(tc.name, tc.query)
		if edge != tc.wantEdge {
			t.Errorf("staticCachePolicy(%q, %q) edge = %q, want %q", tc.name, tc.query, edge, tc.wantEdge)
		}
	}
}

// TestStaticServesWithValidators 首页必须带上 ETag 与安全头，
// 且 If-None-Match 命中时返回 304（边缘/浏览器复验几乎零流量）。
func TestStaticServesWithValidators(t *testing.T) {
	mux := newStaticTestMux()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Blackout Dashboard") {
		t.Fatal("GET / did not serve index.html")
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("static response must carry a strong ETag for CDN revalidation")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("index.html Cache-Control = %q, want no-cache", cc)
	}
	if cdn := rec.Header().Get("CDN-Cache-Control"); cdn != "no-store" {
		t.Fatalf("index.html CDN-Cache-Control = %q, want no-store (edge must never cache the panel)", cdn)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("missing CSP on static response: %q", csp)
	}
	if xo := rec.Header().Get("X-Content-Type-Options"); xo != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", xo)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "cdn.jsdelivr.net") {
		t.Fatalf("CSP must not allow the third-party CDN anymore: %q", csp)
	}

	// 条件请求 → 304 且无正文
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("conditional GET / = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatalf("304 must have empty body, got %d bytes", rec2.Body.Len())
	}
}

// TestStaticVendoredAlpine 自托管 Alpine：必须能由源站提供（不再依赖公网 CDN），
// 且带版本查询串时可长缓存。
func TestStaticVendoredAlpine(t *testing.T) {
	mux := newStaticTestMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/vendor/alpine.min.js?v=3.14.9", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /vendor/alpine.min.js = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Alpine") {
		t.Fatal("vendored alpine asset content looks wrong")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("versioned asset should be long-cacheable, got %q", cc)
	}
}

// TestStaticPoolPage /pool 必须提供 pool.html（与旧 ServeFileFS 行为一致）
func TestStaticPoolPage(t *testing.T) {
	mux := newStaticTestMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/pool", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /pool = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Reflector Pool") {
		t.Fatal("GET /pool did not serve pool.html")
	}
}

// TestStaticNotFoundNoStore 未知路径/穿越尝试：不得返回文件内容，
// 404 响应也不得被缓存（路径穿越由 ServeMux 规范化 301 + 本 handler 404 双重拦截）。
func TestStaticNotFoundNoStore(t *testing.T) {
	mux := newStaticTestMux()
	for _, p := range []string{"/nope.html", "/../controller.go", "/vendor/../index.html/../../x"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code == http.StatusOK {
			t.Fatalf("GET %s = 200, must not serve a file", p)
		}
		if rec.Code == http.StatusNotFound {
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Fatalf("GET %s Cache-Control = %q, want no-store", p, cc)
			}
			if cdn := rec.Header().Get("CDN-Cache-Control"); cdn != "no-store" {
				t.Fatalf("GET %s CDN-Cache-Control = %q, want no-store (Cloudflare otherwise caches 404s)", p, cdn)
			}
		}
	}
}

// TestAPINotSharedCacheable API 响应带权限差异，绝不能被 CDN/共享缓存保存。
func TestAPINotSharedCacheable(t *testing.T) {
	mux := newStaticTestMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/nodes", nil))
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("API Cache-Control = %q, want no-store", cc)
	}
	if vary := rec.Header().Get("Vary"); vary != "Authorization" {
		t.Fatalf("API Vary = %q, want Authorization", vary)
	}
}

// TestStaticHeadRequest HEAD 不应写正文（CDN 探测常用）
func TestStaticHeadRequest(t *testing.T) {
	mux := newStaticTestMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("HEAD", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("HEAD / = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD must not write a body, got %d bytes", rec.Body.Len())
	}
}
