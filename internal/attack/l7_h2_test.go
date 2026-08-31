package attack

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestHTTP2FloodRealH2Server：http2_flood 对真实 TLS+ALPN h2 服务器的端到端验证。
// （l7_test.go 的 httptest 是 HTTP/1.1-only，h2c 前言被按 HTTP/1.1 解析，
// 请求能到达但响应侧解析失败，packets 恒 0——那是测试环境限制，不代表功能问题。
// 此测试用 EnableHTTP2 服务器走标准协商路径验证完整请求-响应闭环。）
func TestHTTP2FloodRealH2Server(t *testing.T) {
	var hits int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "http2_flood", Duration: 4, Threads: 4}
	s := StartHTTP2FloodEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("http2_flood: no requests reached the h2 server")
	}
	if snap.PacketsSent == 0 {
		t.Fatalf("http2_flood: 0 packets counted (hits=%d) — response path broken", hits)
	}
	t.Logf("http2_flood h2: hits=%d pkts=%d errs=%d", hits, snap.PacketsSent, snap.Errors)
}

// TestHTTP2ResetTLS：http2_reset 对 TLS h2 服务器（真实目标形态）
func TestHTTP2ResetTLS(t *testing.T) {
	var hits int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "http2_reset", Duration: 4, Threads: 4, PacketSize: 8}
	s := StartHTTP2ResetEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if snap.PacketsSent == 0 {
		t.Fatal("http2_reset TLS: 0 packets sent")
	}
	t.Logf("http2_reset TLS: pkts=%d errs=%d", snap.PacketsSent, snap.Errors)
}
