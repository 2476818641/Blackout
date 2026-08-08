package attack

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	steamAPIKeyFile = "data/steam_api.key"
	steamAPIBaseURL = "https://api.steampowered.com/IGameServersService/GetServerList/v1/"
)

type steamServer struct {
	Addr string `json:"addr"`
}

type steamResponse struct {
	Response struct {
		Servers []steamServer `json:"servers"`
	} `json:"response"`
}

var (
	steamKeyMu       sync.Mutex
	steamKeyCache    string
	steamKeyCachedAt int64 // 缓存对应的文件 mtime（unix 秒），mtime 变化则重新读盘
	steamKeyLoaded   bool
)

func loadSteamAPIKey() string {
	steamKeyMu.Lock()
	defer steamKeyMu.Unlock()

	fi, statErr := os.Stat(steamAPIKeyFile)
	if statErr != nil {
		// 文件不存在时清空缓存，避免删 key 后仍返回旧值。
		steamKeyLoaded = true
		steamKeyCache = ""
		return ""
	}
	mtime := fi.ModTime().Unix()
	if steamKeyLoaded && steamKeyCachedAt == mtime {
		return steamKeyCache
	}

	key := readSteamAPIKeyFile()
	steamKeyCache = key
	steamKeyCachedAt = mtime
	steamKeyLoaded = true
	return key
}

// buildSteamURL 用 url.Values 拼查询串，对 key/filter 做百分号编码，
// 避免反斜杠、特殊字符破坏 URL（filter 形如 "\appid\730"）。
func buildSteamURL(key, filter string) string {
	q := url.Values{}
	q.Set("key", key)
	q.Set("filter", filter)
	q.Set("limit", "50000")
	return steamAPIBaseURL + "?" + q.Encode()
}

func readSteamAPIKeyFile() string {
	data, err := os.ReadFile(steamAPIKeyFile)
	if err != nil {
		return ""
	}

	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		u16 := make([]uint16, (len(data)-2)/2)
		for i := 2; i < len(data)-1; i += 2 {
			u16[(i-2)/2] = uint16(data[i]) | uint16(data[i+1])<<8
		}
		return strings.TrimSpace(string(utf16.Decode(u16)))
	}

	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		u16 := make([]uint16, (len(data)-2)/2)
		for i := 2; i < len(data)-1; i += 2 {
			u16[(i-2)/2] = uint16(data[i])<<8 | uint16(data[i+1])
		}
		return strings.TrimSpace(string(utf16.Decode(u16)))
	}

	return strings.TrimSpace(string(data))
}

func HasSteamAPIKey() bool {
	return loadSteamAPIKey() != ""
}

// sanitizeSteamErr 去除错误消息中的 Steam API key（key 可能随 URL 出现在 *url.Error 中）
func sanitizeSteamErr(err error) string {
	key := loadSteamAPIKey()
	if key == "" {
		return err.Error()
	}
	return strings.ReplaceAll(err.Error(), key, "****")
}

func QuerySteamByAppID(appID int, filter string, timeout time.Duration) ([]string, error) {
	key := loadSteamAPIKey()
	if key == "" {
		return nil, fmt.Errorf("no steam_api.key found")
	}
	if filter == "" && appID > 0 {
		filter = fmt.Sprintf("\\appid\\%d", appID)
	}

	reqURL := buildSteamURL(key, filter)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(reqURL)
	if err != nil {
		// 错误对象内含完整 URL（含 key），必须脱敏后再入日志
		log.Printf("[steam] HTTP request failed: %v", sanitizeSteamErr(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 429 = 触发限流，401/403 = key 无效；此时 body 通常非 JSON，直接返回错误。
		log.Printf("[steam] API returned status %d (appID=%d)", resp.StatusCode, appID)
		return nil, fmt.Errorf("steam api status %d", resp.StatusCode)
	}

	var result steamResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[steam] JSON decode failed: %v", err)
		return nil, err
	}

	var servers []string
	for _, s := range result.Response.Servers {
		if s.Addr != "" {
			servers = append(servers, s.Addr)
		}
	}

	log.Printf("[steam] API returned %d servers (appID=%d filter=%s)", len(servers), appID, filter)
	return servers, nil
}

func QueryAllSteamGames(timeout time.Duration) map[int][]string {
	key := loadSteamAPIKey()
	if key == "" {
		return nil
	}

	results := make(map[int][]string)
	for _, filter := range []string{"\\appid\\730", "\\appid\\346110", "\\appid\\252490"} {
		reqURL := buildSteamURL(key, filter)
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(reqURL)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[steam] API returned status %d (filter=%s)", resp.StatusCode, filter)
			resp.Body.Close()
			continue
		}
		var result steamResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&result); decErr != nil {
			log.Printf("[steam] JSON decode failed (filter=%s): %v", filter, decErr)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		var servers []string
		for _, s := range result.Response.Servers {
			if s.Addr != "" {
				servers = append(servers, s.Addr)
			}
		}
		var appID int
		switch filter {
		case "\\appid\\730":
			appID = 730
		case "\\appid\\346110":
			appID = 346110
		case "\\appid\\252490":
			appID = 252490
		}
		results[appID] = servers
		log.Printf("[steam] appID=%d → %d servers", appID, len(servers))
	}

	return results
}
