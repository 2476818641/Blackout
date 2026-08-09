package controller

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SpoofProbe 伪造探测记录
type SpoofProbe struct {
	WorkerID  string
	ClaimIP   string
	Nonce     string
	Timestamp int64
	Verified  bool
}

// spoofProbes 存储待验证的探测请求（nonce → probe）
var (
	spoofProbes   = make(map[string]*SpoofProbe)
	spoofProbesMu sync.RWMutex
)

// probeVerifyTimeout 验证窗口：UDP 包必须在此时间窗口内到达
const probeVerifyTimeout = 5 * time.Second

// startUDPProbeListener 启动 UDP 探测监听器（端口 9091）
func (c *Ctrl) startUDPProbeListener() error {
	addr, err := net.ResolveUDPAddr("udp", ":9091")
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	log.Printf("[spoof-probe] UDP listener started on :9091")

	go func() {
		defer conn.Close()
		buf := make([]byte, 2048)

		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[spoof-probe] UDP read error: %v", err)
				continue
			}

			payload := string(buf[:n])
			if !strings.HasPrefix(payload, "SPOOF_PROBE:") {
				continue
			}

			nonce := strings.TrimPrefix(payload, "SPOOF_PROBE:")
			srcIP := remoteAddr.IP.String()

			// 查找对应的探测请求
			spoofProbesMu.Lock()
			probe, exists := spoofProbes[nonce]
			if exists && probe.ClaimIP == srcIP {
				probe.Verified = true
				log.Printf("[spoof-probe] verified: worker=%s claim_ip=%s actual_ip=%s nonce=%s ✓",
					probe.WorkerID, probe.ClaimIP, srcIP, nonce)
			} else if exists {
				log.Printf("[spoof-probe] mismatch: worker=%s claim_ip=%s actual_ip=%s nonce=%s ✗",
					probe.WorkerID, probe.ClaimIP, srcIP, nonce)
			}
			spoofProbesMu.Unlock()
		}
	}()

	// 定期清理过期探测记录（超过 30 秒）
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now().Unix()
			spoofProbesMu.Lock()
			for nonce, probe := range spoofProbes {
				if now-probe.Timestamp > 30 {
					delete(spoofProbes, nonce)
				}
			}
			spoofProbesMu.Unlock()
		}
	}()

	return nil
}

// handleWorkerSpoofProbe 处理 Worker 的伪造探测注册请求
// 两阶段协议第一步：注册 nonce → claim_ip 映射后立即返回。
// 绝不在此处阻塞等待 UDP 包，由 Worker 注册成功后再发包，通过 result 端点轮询结果。
func (c *Ctrl) handleWorkerSpoofProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	// 从 query 参数读取（避免 body 解析问题）
	workerID := r.URL.Query().Get("worker_id")
	claimIP := r.URL.Query().Get("claim_ip")
	nonce := r.URL.Query().Get("nonce")

	if workerID == "" || claimIP == "" || nonce == "" {
		http.Error(w, `{"error":"missing parameters"}`, 400)
		return
	}

	// 注册探测请求
	spoofProbesMu.Lock()
	spoofProbes[nonce] = &SpoofProbe{
		WorkerID:  workerID,
		ClaimIP:   claimIP,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Verified:  false,
	}
	spoofProbesMu.Unlock()

	log.Printf("[spoof-probe] registered: worker=%s claim_ip=%s nonce=%s", workerID, claimIP, nonce)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"registered": true,
		"nonce":      nonce,
	})
}

// handleSpoofProbeResult 处理 Worker 的探测结果轮询
// 两阶段协议第二步：查询 nonce 对应的伪造 UDP 包是否已验证到达。
func (c *Ctrl) handleSpoofProbeResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}

	nonce := r.URL.Query().Get("nonce")
	if nonce == "" {
		http.Error(w, `{"error":"missing nonce"}`, 400)
		return
	}

	// 在锁内完成读取 + 判定 + 清理，消除与 UDP 监听 goroutine 的
	// 数据竞态（此前 RLock 释放后锁外读 probe.Verified/Timestamp）
	spoofProbesMu.Lock()
	probe, exists := spoofProbes[nonce]
	resp := map[string]interface{}{}

	if !exists {
		resp["can_spoof"] = false
		resp["message"] = "probe record expired or never registered"
	} else {
		if probe.Verified {
			delete(spoofProbes, nonce)
			resp["can_spoof"] = true
			resp["message"] = "IP spoofing verified successfully"
		} else if time.Now().Unix()-probe.Timestamp > int64(probeVerifyTimeout.Seconds()) {
			// 超过验证窗口仍未到达 → 清理并判定失败
			delete(spoofProbes, nonce)
			resp["can_spoof"] = false
			resp["message"] = "IP spoofing failed: packets blocked by anti-spoofing filter (uRPF/BCP38) or worker raw socket unavailable"
		} else {
			// 仍在等待窗口内
			resp["pending"] = true
		}
	}
	spoofProbesMu.Unlock()

	// 探测结果（成功或失败）都更新节点的真实伪造能力。
	// 仅在返回明确 can_spoof 结果时更新（pending 分支没有该字段，跳过，
	// 避免 UDP 包尚未到达时误把节点标记为不支持）。
	if verified, hasResult := resp["can_spoof"].(bool); hasResult && probe != nil && probe.WorkerID != "" {
		c.mu.Lock()
		if node, exists := c.nodes[probe.WorkerID]; exists {
			if verified {
				node.CanSpoof = true
				node.SpoofTested = true
				node.Tags = appendIfNotExists(node.Tags, "spoof")
			} else {
				node.CanSpoof = false
				node.SpoofTested = true
				node.Tags = removeTag(node.Tags, "spoof")
			}
		}
		c.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// spoofCacheGet 查询伪造能力缓存（按 IP）。ok=false 表示无记录。
func (c *Ctrl) spoofCacheGet(ip string) (bool, bool) {
	if ip == "" {
		return false, false
	}
	c.spoofCacheMu.RLock()
	v, ok := c.spoofCache[ip]
	c.spoofCacheMu.RUnlock()
	return v, ok
}

// spoofCacheSet 保存伪造能力缓存（按 IP）并持久化。
func (c *Ctrl) spoofCacheSet(ip string, canSpoof bool) {
	if ip == "" {
		return
	}
	c.spoofCacheMu.Lock()
	c.spoofCache[ip] = canSpoof
	data, _ := json.Marshal(c.spoofCache)
	c.spoofCacheMu.Unlock()
	if err := os.WriteFile(c.spoofCacheFile, data, 0644); err != nil {
		log.Printf("[spoof-probe] cache write failed: %v", err)
	}
}

// handleSpoofStatus POST /api/worker/spoof-status
// Worker 上报探测结果（can_spoof），更新节点表的真实伪造能力并缓存到磁盘
// （按 IP 持久化：同 IP 的 worker 重新上线时直接打标签，无需重新探测）。
// 探测失败/平台不支持也会上报 false，避免节点停留在"待检测"。
func (c *Ctrl) handleSpoofStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		WorkerID string `json:"worker_id"`
		CanSpoof bool   `json:"can_spoof"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}
	if req.WorkerID == "" {
		http.Error(w, `{"error":"missing worker_id"}`, 400)
		return
	}

	var nodeIP string
	c.mu.Lock()
	if node, exists := c.nodes[req.WorkerID]; exists {
		node.CanSpoof = req.CanSpoof
		node.SpoofTested = true
		if req.CanSpoof {
			node.Tags = appendIfNotExists(node.Tags, "spoof")
		} else {
			node.Tags = removeTag(node.Tags, "spoof")
		}
		nodeIP = node.IP
	}
	c.mu.Unlock()

	// 按 IP 缓存探测结果：同 IP worker 重新上线直接复用
	if nodeIP != "" && nodeIP != "127.0.0.1" {
		c.spoofCacheSet(nodeIP, req.CanSpoof)
	}

	log.Printf("[spoof-probe] %s reported can_spoof=%v", req.WorkerID, req.CanSpoof)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handleSpoofCacheQuery GET /api/worker/spoof-status?worker_id=xxx
// Worker 注册后查询：该节点 IP 是否有历史伪造能力缓存。
// 命中则返回 cached=true + can_spoof，Worker 跳过重复探测直接使用。
func (c *Ctrl) handleSpoofCacheQuery(w http.ResponseWriter, r *http.Request) {
	wid := r.URL.Query().Get("worker_id")
	if wid == "" {
		http.Error(w, `{"error":"missing worker_id"}`, 400)
		return
	}

	var ip string
	c.mu.RLock()
	if n, ok := c.nodes[wid]; ok {
		ip = n.IP
	}
	c.mu.RUnlock()

	if ip == "" || ip == "127.0.0.1" {
		writeJSON(w, map[string]interface{}{"cached": false})
		return
	}

	canSpoof, ok := c.spoofCacheGet(ip)
	if !ok {
		writeJSON(w, map[string]interface{}{"cached": false, "ip": ip})
		return
	}
	writeJSON(w, map[string]interface{}{"cached": true, "ip": ip, "can_spoof": canSpoof})
}

// removeTag 移除标签
func removeTag(slice []string, item string) []string {
	out := slice[:0]
	for _, s := range slice {
		if s != item {
			out = append(out, s)
		}
	}
	return out
}

// appendIfNotExists 辅助函数：追加元素到切片（如果不存在）
func appendIfNotExists(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
