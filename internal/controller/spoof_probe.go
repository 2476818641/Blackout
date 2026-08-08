package controller

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
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
	verifiedWorkerID := ""

	if !exists {
		resp["can_spoof"] = false
		resp["message"] = "probe record expired or never registered"
	} else {
		if probe.Verified {
			delete(spoofProbes, nonce)
			resp["can_spoof"] = true
			resp["message"] = "IP spoofing verified successfully"
			verifiedWorkerID = probe.WorkerID
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

	if verifiedWorkerID != "" {
		// 验证成功 → 给节点打 spoof 标签
		c.mu.Lock()
		if node, exists := c.nodes[verifiedWorkerID]; exists {
			node.Tags = appendIfNotExists(node.Tags, "spoof")
		}
		c.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
