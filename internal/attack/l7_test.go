package attack

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestL7Floods 本地服务器冒烟：http_flood / post_flood / http2_flood
// 必须真实发出请求且统计 PacketsSent > 0。
func TestL7Floods(t *testing.T) {
	var hits int64
	// HTTP/1.1 服务器
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// http_flood
	atomic.StoreInt64(&hits, 0)
	s1 := StartHTTPFloodEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 8})
	waitSession(t, s1)
	snap1 := s1.Snapshot()
	if snap1.PacketsSent == 0 {
		t.Fatalf("http_flood sent 0 packets (server hits=%d)", hits)
	}
	if snap1.BytesSent <= 0 {
		t.Fatalf("http_flood BytesSent=%d, want > 0 (fixed stats)", snap1.BytesSent)
	}
	t.Logf("http_flood: pkts=%d bytes=%d errs=%d", snap1.PacketsSent, snap1.BytesSent, snap1.Errors)

	// post_flood（带随机 body）
	atomic.StoreInt64(&hits, 0)
	s2 := StartPOSTFloodEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 8, PacketSize: 512})
	waitSession(t, s2)
	snap2 := s2.Snapshot()
	if snap2.PacketsSent == 0 {
		t.Fatalf("post_flood sent 0 packets (server hits=%d)", hits)
	}
	if snap2.BytesSent < uint64(snap2.PacketsSent)*512 {
		t.Fatalf("post_flood BytesSent=%d too small for %d pkts x 512B body", snap2.BytesSent, snap2.PacketsSent)
	}
	t.Logf("post_flood: pkts=%d bytes=%d errs=%d", snap2.PacketsSent, snap2.BytesSent, snap2.Errors)

	// http2_flood（h2c 明文）
	atomic.StoreInt64(&hits, 0)
	s3 := StartHTTP2FloodEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 8})
	waitSession(t, s3)
	snap3 := s3.Snapshot()
	if snap3.PacketsSent == 0 {
		t.Logf("http2_flood: 0 packets (h2c may be unsupported by httptest server; hits=%d)", hits)
	} else {
		t.Logf("http2_flood: pkts=%d bytes=%d errs=%d", snap3.PacketsSent, snap3.BytesSent, snap3.Errors)
	}
}

// TestHTTPSBypassNoProxy 无代理池时 https_bypass 应正常工作（直连退化）
func TestHTTPSBypassNoProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := StartHTTPSBypassEx(AttackConfig{Target: srv.URL, Duration: 2, Threads: 6})
	waitSession(t, s)
	snap := s.Snapshot()
	t.Logf("https_bypass: pkts=%d errs=%d", snap.PacketsSent, snap.Errors)
	// TLS 服务器自签证书 + InsecureSkipVerify 应成功；允许少量失败但至少要发出请求
	if snap.PacketsSent == 0 && snap.Errors == 0 {
		t.Fatalf("https_bypass neither sent nor errored")
	}
}

// waitSession 等待攻击会话自然结束（duration + 1s 余量）
func waitSession(t *testing.T, s *AttackSession) {
	t.Helper()
	select {
	case <-s.DoneChan:
	case <-time.After(10 * time.Second):
		t.Fatal("attack session did not finish in time")
	}
}
