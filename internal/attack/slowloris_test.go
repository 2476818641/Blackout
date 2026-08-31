package attack

import (
	"bufio"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestSlowlorisConnHold：慢速攻击核心行为——连接建立后服务器收不到
// 完整请求（slowloris 头不结束 / slow_post body 不完整），连接被占用。
// 用原始 TCP 服务器模拟：Accept 后等待请求数据，统计"半开占用"连接数。
func TestSlowlorisConnHold(t *testing.T) {
	var held int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&held, 1)
			// 每连接独立 goroutine：模拟服务器等待完整请求（保持占用），
			// 3 秒后超时释放（期间不解析请求，连接一直被占）
			go func(c net.Conn) {
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil {
						break
					}
				}
				c.Close()
			}(conn)
		}
	}()

	for _, method := range []string{"slowloris", "slow_post"} {
		atomic.StoreInt32(&held, 0)
		cfg := AttackConfig{Target: "http://" + ln.Addr().String(), Method: method, Duration: 3, Threads: 4}
		s := StartSlowlorisEx(cfg)
		time.Sleep(2 * time.Second)
		snap := s.Snapshot()
		s.Stop()
		<-s.DoneChan

		if atomic.LoadInt32(&held) < 8 {
			t.Fatalf("%s: expected >=8 held connections, got %d", method, held)
		}
		if snap.PacketsSent == 0 {
			t.Fatalf("%s: no packets counted", method)
		}
		t.Logf("%s: held_conns=%d pkts=%d bytes=%d errs=%d", method, held, snap.PacketsSent, snap.BytesSent, snap.Errors)
	}
}
