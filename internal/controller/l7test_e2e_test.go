package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestL7TestEndpoint 端到端：/api/l7/test 指纹探测 → 推荐排序。
// 用本地 TLS+HTTP/2 模拟服务器伪造 Server 头验证 CVE 命中与推荐顺序。
func TestL7TestEndpoint(t *testing.T) {
	mkServer := func(serverHeader string) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if serverHeader != "" {
				w.Header().Set("Server", serverHeader)
			}
			w.WriteHeader(200)
		}))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		return srv
	}
	ngx := mkServer("nginx/1.25.2")
	defer ngx.Close()
	iis := mkServer("Microsoft-IIS/10.0")
	defer iis.Close()
	patched := mkServer("nginx/1.27.0")
	defer patched.Close()

	c := &Ctrl{adminToken: "admintok", workerToken: "workertok", auditLog: NewAuditLog("", 200)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.handleL7Test(w, r)
	}))
	defer srv.Close()

	// 死目标用固定不可达端口（127.0.0.1:1）：此前用"起一个 httptest 再 Close"，
	// 但释放的临时端口随后可能被本测试自己的 API server（或同包其他测试）
	// 重新占用 —— 端口一旦被占，能力探测的 TCP 拨号就会成功并把目标判成
	// "存活但无 CVE"，测试随端口分配随机失败（-race 下已复现）。
	const deadTarget = "http://127.0.0.1:1"

	probe := func(target string) (recs []string, vuln, cont, bomb bool, notes []string) {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(fmt.Sprintf(`{"target":%q}`, target)))
		req.Header.Set("Authorization", "Bearer admintok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		var d struct {
			Fingerprint struct {
				Vulnerable       bool     `json:"vulnerable"`
				ContinuationVuln bool     `json:"continuation_vuln"`
				BombVuln         bool     `json:"bomb_vuln"`
				Notes            []string `json:"notes"`
			} `json:"fingerprint"`
			Recommendations []struct {
				Method string `json:"method"`
			} `json:"recommendations"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, r := range d.Recommendations {
			recs = append(recs, r.Method)
		}
		return recs, d.Fingerprint.Vulnerable, d.Fingerprint.ContinuationVuln, d.Fingerprint.BombVuln, d.Fingerprint.Notes
	}

	// nginx 1.25.2：三个 CVE 命中 + h2_ping + tls_handshake（https 目标）+ 流量型
	recs, vuln, cont, bomb, _ := probe(ngx.URL)
	if !vuln || !cont || !bomb {
		t.Fatalf("nginx 1.25.2 should hit all CVEs: vuln=%v cont=%v bomb=%v", vuln, cont, bomb)
	}
	want := []string{"http2_bomb", "http2_reset", "http2_continuation", "h2_ping", "tls_handshake", "http_flood", "post_flood", "http2_flood"}
	if len(recs) != len(want) {
		t.Fatalf("nginx recs=%v want %v", recs, want)
	}
	for i := range want {
		if recs[i] != want[i] {
			t.Fatalf("nginx recs=%v want %v", recs, want)
		}
	}

	// IIS：bomb 优先
	recs, _, _, bomb, _ = probe(iis.URL)
	if !bomb || recs[0] != "http2_bomb" {
		t.Fatalf("IIS bomb first expected, got %v (bomb=%v)", recs, bomb)
	}

	// nginx 1.27.0：无 CVE → h2_ping + tls_handshake（能力型）+ 流量型
	recs, vuln, cont, bomb, _ = probe(patched.URL)
	if vuln || cont || bomb {
		t.Fatalf("nginx 1.27.0 should not hit CVEs")
	}
	want = []string{"h2_ping", "tls_handshake", "http_flood", "post_flood", "http2_flood"}
	if len(recs) != len(want) {
		t.Fatalf("patched recs=%v want %v", recs, want)
	}

	// 死端口：探测失败也要有流量型兜底（notes 有失败说明）
	recs, _, _, _, notes := probe(deadTarget)
	if len(recs) != 3 {
		t.Fatalf("dead target should still get 3 traffic recs, got %v", recs)
	}
	if len(notes) == 0 {
		t.Fatal("dead target should carry probe failure notes")
	}
}
