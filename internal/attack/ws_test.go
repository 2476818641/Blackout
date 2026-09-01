package attack

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWSFlood：ws_flood 建立连接并发消息——服务器收到连接与消息
func TestWSFlood(t *testing.T) {
	var conns, msgs, pings int32
	var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt32(&conns, 1)
		defer c.Close()
		for {
			mt, _, err := c.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.PingMessage {
				atomic.AddInt32(&pings, 1)
			} else {
				atomic.AddInt32(&msgs, 1)
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws://" + srv.Listener.Addr().String() + "/"
	cfg := AttackConfig{Target: wsURL, Method: "ws_flood", Duration: 3, Threads: 4}
	s := StartWSFloodEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&conns) < 8 {
		t.Fatalf("ws_flood: only %d connections established, want >=8", conns)
	}
	if atomic.LoadInt32(&msgs) == 0 {
		t.Fatalf("ws_flood: no messages received by server")
	}
	if snap.PacketsSent == 0 {
		t.Fatal("ws_flood: 0 packets counted")
	}
	t.Logf("ws_flood: conns=%d msgs=%d pings=%d pkts=%d errs=%d", conns, msgs, pings, snap.PacketsSent, snap.Errors)
}

// TestWSSlow：ws_slow 连接占坑——连接保持但服务器收不到消息
func TestWSSlow(t *testing.T) {
	var conns, msgs int32
	var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt32(&conns, 1)
		defer c.Close()
		// 短读超时：模拟服务器等待消息；客户端不发消息则连接保持
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
			atomic.AddInt32(&msgs, 1)
		}
	}))
	defer srv.Close()

	wsURL := "ws://" + srv.Listener.Addr().String() + "/"
	cfg := AttackConfig{Target: wsURL, Method: "ws_slow", Duration: 3, Threads: 4}
	s := StartWSSlowEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan

	if atomic.LoadInt32(&conns) < 8 {
		t.Fatalf("ws_slow: only %d connections established, want >=8", conns)
	}
	if atomic.LoadInt32(&msgs) != 0 {
		t.Fatalf("ws_slow: server received %d messages, want 0 (conn hold only)", msgs)
	}
	t.Logf("ws_slow: conns=%d msgs=%d pkts=%d errs=%d", conns, msgs, snap.PacketsSent, snap.Errors)
}
