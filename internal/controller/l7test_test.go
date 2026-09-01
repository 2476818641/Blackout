package controller

import (
	"testing"

	"blackout/internal/attack"
)

// TestBuildL7Recommendations 推荐逻辑：
//   - IIS（BombVuln）→ http2_bomb 排第一
//   - nginx<1.25.3 → Rapid Reset / CONTINUATION / Bomb 都命中，CVE 优先于流量型
//   - 无漏洞目标 → 只有三种流量型，http2_flood 视 h2 支持标注
func TestBuildL7Recommendations(t *testing.T) {
	methods := func(recs []L7Recommendation) []string {
		out := make([]string, 0, len(recs))
		for _, r := range recs {
			out = append(out, r.Method)
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// IIS：bomb 恒脆弱
	iis := &attack.L7Fingerprint{HTTP2: true, BombVuln: true, Product: "microsoft-iis"}
	recs := buildL7Recommendations(iis)
	if !eq(methods(recs)[:1], []string{"http2_bomb"}) {
		t.Fatalf("IIS: expected http2_bomb first, got %v", methods(recs))
	}

	// nginx 1.25.2：三个 CVE 全命中 + h2_ping 补充（帧级，优先级 70）
	ngx := &attack.L7Fingerprint{HTTP2: true, Vulnerable: true, ContinuationVuln: true, BombVuln: true}
	recs = buildL7Recommendations(ngx)
	want := []string{"http2_bomb", "http2_reset", "http2_continuation", "h2_ping", "http_flood", "post_flood", "http2_flood"}
	if !eq(methods(recs), want) {
		t.Fatalf("nginx vuln: expected %v, got %v", want, methods(recs))
	}

	// 已修复目标 + h2：无 CVE，h2_ping + 流量型兜底
	patched := &attack.L7Fingerprint{HTTP2: true}
	recs = buildL7Recommendations(patched)
	want = []string{"h2_ping", "http_flood", "post_flood", "http2_flood"}
	if !eq(methods(recs), want) {
		t.Fatalf("patched h2: expected %v, got %v", want, methods(recs))
	}
	for _, r := range recs {
		if r.ReasonKey == "" {
			t.Fatalf("recommendation %s missing reason_key", r.Method)
		}
		if r.Params == nil || r.Params["threads"] == nil {
			t.Fatalf("recommendation %s missing params", r.Method)
		}
	}

	// 无 h2：http2_flood 用 noalpn 标注
	noH2 := &attack.L7Fingerprint{}
	recs = buildL7Recommendations(noH2)
	found := false
	for _, r := range recs {
		if r.Method == "http2_flood" {
			found = true
			if r.ReasonKey != "l7_rec_h2_noalpn" {
				t.Fatalf("no-h2 http2_flood should use noalpn key, got %s", r.ReasonKey)
			}
		}
	}
	if !found {
		t.Fatal("no-h2 target should still get http2_flood (marked uncertain)")
	}

	// nil 指纹（探测完全失败）：不 panic，仍给流量型
	recs = buildL7Recommendations(nil)
	if len(recs) != 3 {
		t.Fatalf("nil fingerprint should still get 3 traffic recs, got %d", len(recs))
	}

	// 能力型推荐：https + WS + 慢速适用 + 静态资源 → 对应方法全部出现
	capFP := &attack.L7Fingerprint{
		Target: "https://example.com", HTTP2: true,
		WS: true, SlowApplicable: true, StaticRange: true,
	}
	recs = buildL7Recommendations(capFP)
	got := methods(recs)
	for _, wantMethod := range []string{"tls_handshake", "ws_slow", "ws_flood", "slowloris", "slow_post", "range_flood"} {
		found := false
		for _, m := range got {
			if m == wantMethod {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("capability fp missing recommendation %s (got %v)", wantMethod, got)
		}
	}
	// 能力型在流量型之前（优先级更高）
	if len(recs) < 8 || recs[0].Method == "http_flood" {
		t.Fatalf("capability recommendations should outrank generic traffic: %v", got)
	}
}

// TestBuildL7Combo：一键组合按能力组装且方法全部合法
func TestBuildL7Combo(t *testing.T) {
	combo := buildL7Combo(&attack.L7Fingerprint{
		Target: "https://example.com", HTTP2: true, WS: true, SlowApplicable: true, StaticRange: true,
	})
	if len(combo) < 5 {
		t.Fatalf("combo too small: %d", len(combo))
	}
	for _, sub := range combo {
		if !isValidMethod(sub.Method) || sub.Method == "combo" {
			t.Fatalf("combo sub method %q invalid", sub.Method)
		}
		if sub.Threads < 1 {
			t.Fatalf("combo sub %s threads=%d", sub.Method, sub.Threads)
		}
	}
	// 基本目标：无能力 → 带宽+CPU(无)+连接兜底
	basic := buildL7Combo(&attack.L7Fingerprint{Target: "http://x"})
	if len(basic) < 2 {
		t.Fatalf("basic combo too small: %d", len(basic))
	}
}
