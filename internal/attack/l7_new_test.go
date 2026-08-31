package attack

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRangeFlood：range_flood 请求必须携带 Range 头（响应放大型的核心）
func TestRangeFlood(t *testing.T) {
	var gotRange int32
	var noRange int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			atomic.AddInt32(&gotRange, 1)
		} else {
			atomic.AddInt32(&noRange, 1)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "range_flood", Duration: 3, Threads: 4}
	s := StartRangeFloodEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&gotRange) == 0 {
		t.Fatalf("range_flood: no request carried a Range header (noRange=%d)", noRange)
	}
	if snap.PacketsSent == 0 {
		t.Fatal("range_flood: 0 packets")
	}
	t.Logf("range_flood: range_hits=%d no_range=%d pkts=%d", gotRange, noRange, snap.PacketsSent)
}

// TestHEADFlood：head_flood 请求方法必须是 HEAD 且无 body
func TestHEADFlood(t *testing.T) {
	var headHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			atomic.AddInt32(&headHits, 1)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "head_flood", Duration: 3, Threads: 4}
	s := StartHEADFloodEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&headHits) == 0 {
		t.Fatal("head_flood: no HEAD requests reached server")
	}
	t.Logf("head_flood: head_hits=%d pkts=%d", headHits, snap.PacketsSent)
}

// TestTLSHandshakeStorm：TLS 握手风暴对 TLS 服务器——握手完成计数
func TestTLSHandshakeStorm(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.StartTLS()
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "tls_handshake", Duration: 3, Threads: 4}
	s := StartTLSHandshakeEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if snap.PacketsSent == 0 {
		t.Fatalf("tls_handshake: 0 completed handshakes (errs=%d)", snap.Errors)
	}
	t.Logf("tls_handshake: handshakes=%d errs=%d", snap.PacketsSent, snap.Errors)
}

// TestH2PingFlood：h2_ping 对真实 h2 服务器——PING 帧发送计数
func TestH2PingFlood(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	cfg := AttackConfig{Target: srv.URL, Method: "h2_ping", Duration: 3, Threads: 4}
	s := StartH2PingEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if snap.PacketsSent == 0 {
		t.Fatalf("h2_ping: 0 PING frames sent (errs=%d)", snap.Errors)
	}
	t.Logf("h2_ping: pings=%d errs=%d", snap.PacketsSent, snap.Errors)
}
