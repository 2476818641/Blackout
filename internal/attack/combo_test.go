package attack

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestComboAttackSmoke 组合攻击整体冒烟：
// UDP + HTTP + TCP 三类子攻击并发（全部打同一主目标——StartComboAttack
// 用主目标覆盖子攻击 Target 是产品设计，前端子攻击无独立目标输入），
// 验证启动、统计聚合、完成上报链路。
func TestComboAttackSmoke(t *testing.T) {
	// HTTP 服务器（兼作主目标端口）
	var hits int32
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer httpSrv.Close()
	mainTarget := httpSrv.Listener.Addr().String() // "127.0.0.1:port"

	// UDP 接收端（验证 UDP 子攻击确实发包）
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := udpLn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	cfg := AttackConfig{
		Target:   mainTarget,
		Duration: 3,
		Threads:  4,
	}
	subCfgs := []AttackConfig{
		{Method: "udp_stdhex", Threads: 2, PacketSize: 512},
		{Method: "http_flood", Threads: 2},
		{Method: "tcp_connect", Threads: 2},
	}

	cs := StartComboAttack(cfg, subCfgs)
	time.Sleep(2 * time.Second)
	snap := cs.Snapshot()
	cs.Stop()
	select {
	case <-cs.DoneChan:
	case <-time.After(10 * time.Second):
		t.Fatal("combo did not finish")
	}

	if snap.PacketsSent == 0 {
		t.Fatalf("combo sent 0 packets (sub-attacks not running?)")
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("http sub-attack never reached the server")
	}
	// UDP 子攻击的包应能到达 UDP 监听端（UDP 打 http 端口也会发出去，
	// 只是没有接收者；这里校验总包数显著大于 http+tcp 的量）
	if snap.PacketsSent < 10000 {
		t.Fatalf("combo pkts too low: %d (udp sub-attack not contributing?)", snap.PacketsSent)
	}
	t.Logf("combo smoke: pkts=%d bytes=%d errs=%d http_hits=%d", snap.PacketsSent, snap.BytesSent, snap.Errors, hits)
}

// TestComboUnknownSubMethod：未知子攻击方法被跳过，combo 仍正常完成
func TestComboUnknownSubMethod(t *testing.T) {
	cfg := AttackConfig{Target: "127.0.0.1:9", Duration: 2, Threads: 2}
	subCfgs := []AttackConfig{
		{Method: "totally_unknown_method", Threads: 2},
	}
	cs := StartComboAttack(cfg, subCfgs)
	select {
	case <-cs.DoneChan:
	case <-time.After(5 * time.Second):
		t.Fatal("empty combo did not finish")
	}
}
