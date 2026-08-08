package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"newtool/internal/controller"
)

var (
	grpcAddr = flag.String("grpc", ":9090", "gRPC listen address")
	httpAddr = flag.String("http", ":8080", "HTTP listen address")
)

// 编译时注入（-ldflags "-X main.buildVersion=... -X main.gitRepo=..."）：
// buildVersion = 当前发布标签（如 v1.0.4），Controller 用它标记自身并作为
// 云更新的默认目标版本（Worker 版本需与 Controller 一致）。
// gitRepo = GitHub 仓库（如 2476818641/newtool），云更新默认 URL 基于它拼接。
var (
	buildVersion = "dev"
	gitRepo      = ""
)

func main() {
	flag.Parse()

	grpc := normalizeAddr(*grpcAddr)
	http := normalizeAddr(*httpAddr)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Controller starting...")
	log.Printf("  gRPC: %s", grpc)
	log.Printf("  HTTP: %s", http)
	log.Printf("  Version: %s (repo: %s)", buildVersion, gitRepo)

	scheme := "http"
	if tlsEnabled() {
		scheme = "https"
	}
	log.Printf("  Dashboard (local):  %s://localhost%s", scheme, http)

	// 异步探测公网 IP（iplark.com 优先）：不影响启动速度，
	// 有公网地址时额外输出公网入口供远端起 Dashboard / 连 Worker
	go func() {
		if ip := getPublicIP(); ip != "" {
			log.Printf("  Dashboard (public): %s://%s%s", scheme, ip, http)
			log.Printf("  gRPC (public):      %s:%s", ip, strings.TrimPrefix(grpc, ":"))
		} else {
			log.Printf("  Dashboard (public): unavailable (public IP lookup failed)")
		}
	}()

	ensureSteamKey()

	ctrl := controller.New(grpc, http, controller.BuildInfo{Version: buildVersion, GitRepo: gitRepo})
	if err := ctrl.Start(); err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func normalizeAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	return ":" + addr
}

// tlsEnabled 判断 data/cert/ 下是否已存在证书（决定 Dashboard 用 http 还是 https）
func tlsEnabled() bool {
	_, certErr := os.Stat("data/cert/server.crt")
	_, keyErr := os.Stat("data/cert/server.key")
	return certErr == nil && keyErr == nil
}

// getPublicIP 通过 iplark.com 获取公网 IP（失败时回退到其他服务）。
// 兼容纯文本 IP（iplark.com / ipify）与 JSON 格式（api.ip.cc）。
func getPublicIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	var jsonResp struct {
		IP string `json:"ip"`
	}
	for _, u := range []string{"https://iplark.com", "https://api.ipify.org", "https://api.ip.cc/"} {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		raw := strings.TrimSpace(string(body))
		if raw == "" {
			continue
		}
		if net.ParseIP(raw) != nil {
			return raw
		}
		if json.Unmarshal(body, &jsonResp) == nil && net.ParseIP(jsonResp.IP) != nil {
			return jsonResp.IP
		}
	}
	return ""
}

func ensureSteamKey() {
	os.MkdirAll("data", 0755)
	keyFile := "data/steam_api.key"

	if _, err := os.Stat(keyFile); err == nil {
		return
	}

	fmt.Print("\nSteam Web API Key not found.\n")
	fmt.Print("Get one at: https://steamcommunity.com/dev/apikey\n")
	fmt.Print("Enter your key (or press Enter to skip): ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		log.Printf("Steam API: disabled (no key provided)")
		return
	}

	if err := os.WriteFile(keyFile, []byte(input), 0600); err != nil {
		log.Printf("Failed to save key: %v", err)
		return
	}

	log.Printf("Steam API: key saved to %s", keyFile)
}
