package attack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestBypassClientFingerprint：uTLS Chrome 指纹客户端的三个关键行为：
//  1. ALPN 协商为 http/1.1（强制 h1，避免 Go h2 SETTINGS 指纹维度）
//  2. Cookie jar 会话保持（Set-Cookie 后后续请求携带）
//  3. Chrome 特征头齐全（Sec-Ch-Ua / Sec-Fetch-* / Chrome UA）
func TestBypassClientFingerprint(t *testing.T) {
	var negotiated string
	var cookies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		negotiated = r.TLS.NegotiatedProtocol
		cookies = append(cookies, r.Header.Get("Cookie"))
		w.Header().Set("Set-Cookie", "cf_clearance=abc123; Path=/; Max-Age=3600")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := newBypassClient("")
	for i := 0; i < 2; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if negotiated != "http/1.1" {
		t.Fatalf("ALPN negotiated %q, want http/1.1", negotiated)
	}
	if len(cookies) < 2 || cookies[1] == "" {
		t.Fatalf("cookie not persisted across requests: %v", cookies)
	}
	if !strings.Contains(cookies[1], "cf_clearance=abc123") {
		t.Fatalf("unexpected cookie value: %q", cookies[1])
	}
}

// TestBypassRequestHeaders：buildBypassRequest 的 Chrome 特征头
func TestBypassRequestHeaders(t *testing.T) {
	rng := NewFastRNG(42)
	req := buildBypassRequest("https://example.com/path", rng)
	if req.Header.Get("Sec-Ch-Ua") == "" {
		t.Fatal("missing Sec-Ch-Ua header")
	}
	if req.Header.Get("Sec-Fetch-Mode") == "" {
		t.Fatal("missing Sec-Fetch-Mode header")
	}
	if req.Header.Get("Sec-Ch-Ua-Platform") == "" {
		t.Fatal("missing Sec-Ch-Ua-Platform header")
	}
	ua := req.Header.Get("User-Agent")
	if !strings.Contains(ua, "Chrome/") || !strings.Contains(ua, "AppleWebKit/537.36") {
		t.Fatalf("UA not Chrome-like: %q", ua)
	}
	// 随机路径（buildL7Request 语义保留）
	if req.URL.Path == "" {
		t.Fatal("missing randomized path")
	}
}

// TestHTTPSBypassSmoke：https_bypass 攻击冒烟（本地 TLS 服务器）
func TestHTTPSBypassSmoke(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Duration: 3, Threads: 4}
	s := StartHTTPSBypassEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("no requests reached the server")
	}
	if snap.PacketsSent == 0 {
		t.Fatal("no packets counted")
	}
	t.Logf("https_bypass smoke: hits=%d pkts=%d bytes=%d", hits, snap.PacketsSent, snap.BytesSent)
}
