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

	// nginx 1.25.2：三个 CVE 全命中
	ngx := &attack.L7Fingerprint{HTTP2: true, Vulnerable: true, ContinuationVuln: true, BombVuln: true}
	recs = buildL7Recommendations(ngx)
	want := []string{"http2_bomb", "http2_reset", "http2_continuation", "http_flood", "post_flood", "http2_flood"}
	if !eq(methods(recs), want) {
		t.Fatalf("nginx vuln: expected %v, got %v", want, methods(recs))
	}

	// 已修复目标 + h2：无 CVE，流量型兜底
	patched := &attack.L7Fingerprint{HTTP2: true}
	recs = buildL7Recommendations(patched)
	want = []string{"http_flood", "post_flood", "http2_flood"}
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
}
