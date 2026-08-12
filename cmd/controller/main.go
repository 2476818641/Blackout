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
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"newtool/internal/controller"
)

var (
	grpcAddr = flag.String("grpc", ":9090", "gRPC listen address")
	httpAddr = flag.String("http", ":8080", "HTTP listen address")
	install  = flag.Bool("install", false, "Install as system service (auto-start) and print management commands")
)

// 编译时注入（-ldflags "-X main.buildVersion=... -X main.gitRepo=... -X main.ghProxy=..."）：
// buildVersion = 当前发布标签（如 v1.0.4），Controller 用它标记自身并作为
// 云更新的默认目标版本（Worker 版本需与 Controller 一致）。
// gitRepo = GitHub 仓库（如 2476818641/newtool），云更新默认 URL 基于它拼接。
// ghProxy = GitHub 转发代理前缀（国内服务器直连 GitHub 下载慢/失败时的加速通道），
// 默认内置 cf.liuass.eu.org/ghproxy/，可用 ldflags 覆盖为空串禁用。
var (
	buildVersion = "dev"
	gitRepo      = ""
	ghProxy      = "https://cf.liuass.eu.org/ghproxy/"
)

func main() {
	flag.Parse()

	if *install {
		name, err := controller.InstallAutoStart(normalizeAddr(*grpcAddr), normalizeAddr(*httpAddr))
		if err != nil {
			log.Fatalf("Install failed: %v", err)
		}
		printManageCommands(name)
		return
	}

	grpc := normalizeAddr(*grpcAddr)
	http := normalizeAddr(*httpAddr)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Controller starting...")
	log.Printf("  gRPC: %s", grpc)
	log.Printf("  HTTP: %s", http)
	log.Printf("  Version: %s (repo: %s)", buildVersion, gitRepo)
	if ghProxy != "" {
		log.Printf("  Update proxy: %s", ghProxy)
	}

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

	// 信号处理：
	// - SIGHUP：清空证书缓存 → 下次 TLS 握手自动加载新证书。
	//   配套 acme.sh --reloadcmd "kill -HUP <pid>" / systemctl reload
	//   实现证书热更新（HTTP + gRPC 都生效，服务不中断）。
	// - SIGINT/SIGTERM：正常退出。
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigChan {
			switch s {
			case syscall.SIGHUP:
				log.Printf("SIGHUP received, reloading TLS certificate")
				controller.ReloadTLS()
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Signal %v received, shutting down", s)
				os.Exit(0)
			}
		}
	}()

	ctrl := controller.New(grpc, http, controller.BuildInfo{Version: buildVersion, GitRepo: gitRepo, GhProxy: ghProxy})
	if err := ctrl.Start(); err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

// printManageCommands 安装完成后输出服务管理命令（启动/暂停/重启/日志/位置）
func printManageCommands(serviceName string) {
	if runtime.GOOS == "windows" {
		fmt.Println("NetTool Controller 已安装为计划任务: " + serviceName)
		fmt.Println()
		fmt.Println("管理命令:")
		fmt.Println("  启动:   schtasks /run   /tn " + serviceName)
		fmt.Println("  停止:   schtasks /end   /tn " + serviceName)
		fmt.Println("  状态:   schtasks /query /tn " + serviceName + " /v")
		fmt.Println()
		fmt.Println("日志: 无持久化日志文件，前台运行可见 stdout（schtasks 下 stdout 丢弃）")
		return
	}

	fmt.Println("NetTool Controller 已安装为 systemd 服务: " + serviceName)
	fmt.Println()
	fmt.Println("管理命令:")
	fmt.Println("  启动:   systemctl start   " + serviceName)
	fmt.Println("  停止:   systemctl stop    " + serviceName)
	fmt.Println("  重启:   systemctl restart " + serviceName)
	fmt.Println("  状态:   systemctl status  " + serviceName)
	fmt.Println("  日志:   journalctl -u " + serviceName + " -f      （实时跟踪）")
	fmt.Println("          journalctl -u " + serviceName + " --since today")
	fmt.Println("  热更新证书: systemctl reload " + serviceName + "   （SIGHUP，零中断）")
	fmt.Println()
	fmt.Println("日志位置: systemd journal（/var/log/journal/ 或 /run/log/journal/），")
	fmt.Println("         日志大小上限由 journald 配置控制（默认日志滚动保留）")
	fmt.Println()
	fmt.Println("注意: 安装后如果移动了 controller 二进制的位置，")
	fmt.Println("      需要手动修改 /etc/systemd/system/" + serviceName + ".service 中的")
	fmt.Println("      ExecStart 与 WorkingDirectory 路径，然后执行:")
	fmt.Println("      systemctl daemon-reload && systemctl restart " + serviceName)
	fmt.Println()
	fmt.Println("提示: 如已存在旧的 controller.service（手动创建的），请先停用避免端口冲突:")
	fmt.Println("      systemctl disable --now controller")
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
