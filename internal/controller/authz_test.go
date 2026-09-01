package controller

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestWorkerTokenLeastPrivilege：worker 令牌权限矩阵回归测试。
// worker 凭据（共享 workerToken / per-worker token）只允许访问运行必需端点；
// 管理端点（任务创建/停止、节点、保护规则、代理写、日志、部署命令等）必须拒绝。
func TestWorkerTokenLeastPrivilege(t *testing.T) {
	c := &Ctrl{
		adminToken:    "admin-tok",
		workerToken:   "shared-worker-tok",
		workerTokens:  map[string]bool{"per-worker-1": true},
		workerTokensMu: sync.RWMutex{},
		auditLog:      NewAuditLog("", 200),
	}
	mux := c.routes()

	req := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// 共享 worker 令牌：管理端点必须被拒（401/403）
	adminOnly := []struct{ method, path, body string }{
		{"GET", "/api/nodes", ""},
		{"GET", "/api/tasks", ""},
		{"POST", "/api/tasks", "{}"},
		{"POST", "/api/tasks/task-1/stop", ""},
		{"GET", "/api/tasks/task-1", ""},
		{"GET", "/api/stats", ""},
		{"GET", "/api/guard", ""},
		{"PUT", "/api/guard", "{}"},
		{"PUT", "/api/proxy", "bad-proxy"},
		{"PUT", "/api/dnsamp", "{}"},
		{"GET", "/api/scan", ""},
		{"GET", "/api/logs", ""},
		{"GET", "/api/templates", ""},
		{"GET", "/api/node-groups", ""},
		{"GET", "/api/audit", ""},
		{"GET", "/api/deploy/command", ""},
		{"GET", "/api/deploy/config", ""},
		{"GET", "/api/update/check", ""},
		{"GET", "/api/migrate/export", ""},
		{"GET", "/api/reflectors/manual", ""},
		{"GET", "/api/reflectors/steam", ""},
		{"GET", "/api/pools", ""},
		{"GET", "/api/dnsamp/domains", ""},
		{"GET", "/api/shodan", ""},
		{"GET", "/api/tokens/provision", ""},
	}
	for _, tc := range adminOnly {
		rec := req(tc.method, tc.path, tc.body, "shared-worker-tok")
		if rec.Code != 401 && rec.Code != 403 {
			t.Errorf("worker token must be rejected on %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}

	// per-worker 令牌同样拒绝
	for _, tc := range adminOnly[:5] {
		rec := req(tc.method, tc.path, tc.body, "per-worker-1")
		if rec.Code != 401 && rec.Code != 403 {
			t.Errorf("per-worker token must be rejected on %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}

	// worker 令牌：运行必需端点放行（非 401/403）
	workerAllowed := []struct{ method, path, body string }{
		{"GET", "/api/worker/spoof-status", ""},
		{"POST", "/api/tasks/complete", "{}"},
		{"GET", "/api/reflectors/all", ""},
		{"GET", "/api/reflectors/version", ""},
		{"GET", "/api/deploy/version", ""},
		{"GET", "/api/proxy", ""},
		{"GET", "/api/dnsamp", ""},
		{"POST", "/api/lw/report", `{"token":"shared-worker-tok"}`},
	}
	for _, tc := range workerAllowed {
		rec := req(tc.method, tc.path, tc.body, "shared-worker-tok")
		if rec.Code == 401 || rec.Code == 403 {
			t.Errorf("worker token must be ALLOWED on %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}

	// admin 令牌：管理端点全部放行（非 401/403）
	for _, tc := range adminOnly {
		rec := req(tc.method, tc.path, tc.body, "admin-tok")
		if rec.Code == 401 || rec.Code == 403 {
			t.Errorf("admin token must be allowed on %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}
}
