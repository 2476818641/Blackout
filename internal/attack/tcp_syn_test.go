package attack

import (
	"net"
	"testing"
	"time"
)

// TestTCPSynFlood 冒烟：
//   - 开放端口（本地监听）：tcp_syn 必须有 PacketsSent > 0
//     （回归：用户实测 PPS=0 —— 旧实现 net.Dial 完整握手后关闭，
//     目标端口关闭时 Dial 全超时，PacketsSent 恒 0）
//   - 关闭端口：任务正常结束不卡死，错误计数合理
func TestTCPSynFlood(t *testing.T) {
	// 开放端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openAddr := ln.Addr().String()
	defer ln.Close()

	// 关闭端口（先占端口再释放，确保无监听）
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := ln2.Addr().String()
	ln2.Close()

	cfg := AttackConfig{Target: openAddr, Method: "tcp_syn", Duration: 3, Threads: 4}
	s := StartTCPFloodEx(cfg)
	time.Sleep(2 * time.Second)
	snap := s.Snapshot()
	s.Stop()
	<-s.DoneChan
	if snap.PacketsSent == 0 {
		t.Fatalf("tcp_syn open port: 0 packets (regression: PPS=0 bug)")
	}
	t.Logf("tcp_syn open port: pkts=%d errs=%d", snap.PacketsSent, snap.Errors)

	// 关闭端口：不卡死、正常结束
	cfg2 := AttackConfig{Target: closedAddr, Method: "tcp_syn", Duration: 3, Threads: 4}
	s2 := StartTCPFloodEx(cfg2)
	time.Sleep(2 * time.Second)
	s2.Stop()
	select {
	case <-s2.DoneChan:
	case <-time.After(10 * time.Second):
		t.Fatal("tcp_syn closed port: task did not finish (hung)")
	}
}
