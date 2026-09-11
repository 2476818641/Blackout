package controller

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLWLockNoDeadlock 回归测试：非反射任务派发路径上
// "写锁内 RLock"（isLWNode）导致的 RWMutex 死锁。
// 死锁发生时 onlineWorkersAllAssigned 永久挂起 → 3s 超时即失败。
func TestLWLockNoDeadlock(t *testing.T) {
	c := &Ctrl{
		nodes: map[string]*NodeInfo{
			"lw-1": {WorkerID: "lw-1", Tags: []string{"lw"}, Status: "READY"},
			"go-1": {WorkerID: "go-1", Status: "READY"},
		},
		tasks: map[string]*TaskInfo{},
	}

	// 场景 1：非反射任务（http2_flood）→ 触发 isLWNode 分支（旧代码在此死锁）
	task := &TaskInfo{
		TaskID:  "t1",
		Method:  "http2_flood",
		Status:  "pending",
		Workers: map[string]*TaskStats{"go-1": {WorkerID: "go-1"}},
	}
	done := make(chan bool, 1)
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.onlineWorkersAllAssigned(task)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK: onlineWorkersAllAssigned hung (RLock inside write lock)")
	}

	// 场景 2：反射任务（lw 参与）→ 正常路径
	task2 := &TaskInfo{
		TaskID:  "t2",
		Method:  "dns_reflector",
		Status:  "pending",
		Workers: map[string]*TaskStats{"go-1": {WorkerID: "go-1"}},
	}
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.onlineWorkersAllAssigned(task2)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK: reflector task path hung")
	}
}

// TestLWCapableMethod：lw 能力范围必须与 Rust 端实现一致——
// dns_reflector（反射，优先）与 tcp_syn（伪源 SYN，回退）；
// 其余方法（含名字相近的 vse_reflector/cldap_reflector/tcp_syn_spoof）
// 都不允许派发给 lw，否则任务会永远等不到 lw 上报完成。
func TestLWCapableMethod(t *testing.T) {
	capable := []string{"dns_reflector", "tcp_syn"}
	for _, m := range capable {
		if !lwCapableMethod(m) {
			t.Errorf("%s should be lw-capable", m)
		}
	}
	incapable := []string{
		"vse_reflector", "cldap_reflector", "tcp_syn_spoof", "tcp_ack",
		"tcp_connect", "udp_stdhex", "http_flood", "http2_flood", "combo", "",
	}
	for _, m := range incapable {
		if lwCapableMethod(m) {
			t.Errorf("%s must NOT be lw-capable", m)
		}
	}
}

// lwHeartbeat 发起一次 lw 心跳并解析返回的任务。
func lwHeartbeat(t *testing.T, c *Ctrl, nodeID string) *lwTask {
	t.Helper()
	body := `{"token":"workertest","node_id":"` + nodeID + `"}`
	req := httptest.NewRequest("POST", "/api/lw/heartbeat", strings.NewReader(body))
	rec := httptest.NewRecorder()
	c.handleLWHeartbeat(rec, req)
	if rec.Code != 200 {
		t.Fatalf("heartbeat status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Task *lwTask `json:"task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad heartbeat json: %v body=%s", err, rec.Body.String())
	}
	return resp.Task
}

func newLWTestCtrl(tasks map[string]*TaskInfo, pending []string) *Ctrl {
	return &Ctrl{
		adminToken:  "admintest",
		workerToken: "workertest",
		nodes: map[string]*NodeInfo{
			"lw-1": {WorkerID: "lw-1", Tags: []string{"lw"}, Status: "READY"},
		},
		tasks:      tasks,
		pendingIDs: pending,
	}
}

// TestLWHeartbeatDispatchPriority：lw 支持反射与 tcp_syn，反射必须优先——
// 即使 tcp_syn 任务排在待派发队列更前面，也要先派 dns_reflector。
func TestLWHeartbeatDispatchPriority(t *testing.T) {
	tasks := map[string]*TaskInfo{
		"tsyn": {
			TaskID: "tsyn", Method: "tcp_syn", Target: "1.2.3.4:80",
			Duration: 60, Threads: 8, Status: "pending",
			Workers: map[string]*TaskStats{},
		},
		"tdns": {
			TaskID: "tdns", Method: "dns_reflector", Target: "1.2.3.4",
			Duration: 60, Threads: 8, Status: "pending",
			Workers: map[string]*TaskStats{},
		},
	}
	c := newLWTestCtrl(tasks, []string{"tsyn", "tdns"})

	got := lwHeartbeat(t, c, "lw-1")
	if got == nil {
		t.Fatal("expected a task, got nil")
	}
	if got.Method != "dns_reflector" || got.TaskID != "tdns" {
		t.Fatalf("reflector must win priority, got %s/%s", got.Method, got.TaskID)
	}
	// tcp_syn 任务必须仍在队列里（不能被丢弃）
	c.mu.RLock()
	stillPending := len(c.pendingIDs) == 1 && c.pendingIDs[0] == "tsyn"
	_, assigned := tasks["tsyn"].Workers["lw-1"]
	c.mu.RUnlock()
	if !stillPending || assigned {
		t.Fatalf("tcp_syn task should stay pending, pendingIDs=%v assigned=%v", c.pendingIDs, assigned)
	}
}

// TestLWHeartbeatFallbackTCPsyn：无反射任务时回退派发 tcp_syn，
// 且目标/时长/线程数正确透传（lw 需要自行解析目标端口）。
func TestLWHeartbeatFallbackTCPsyn(t *testing.T) {
	tasks := map[string]*TaskInfo{
		"tsyn": {
			TaskID: "tsyn", Method: "tcp_syn", Target: "5.6.7.8:443",
			Duration: 30, Threads: 4, Status: "pending",
			Workers: map[string]*TaskStats{},
		},
	}
	c := newLWTestCtrl(tasks, []string{"tsyn"})

	got := lwHeartbeat(t, c, "lw-1")
	if got == nil {
		t.Fatal("expected tcp_syn fallback task, got nil")
	}
	if got.Method != "tcp_syn" {
		t.Fatalf("method=%s, want tcp_syn", got.Method)
	}
	if got.Target != "5.6.7.8:443" || got.Duration != 30 || got.Threads != 4 {
		t.Fatalf("task fields not passed through: %+v", got)
	}
	c.mu.RLock()
	node := c.nodes["lw-1"]
	status := node.Status
	c.mu.RUnlock()
	if status != "ATTACKING" {
		t.Fatalf("lw node should be ATTACKING after dispatch, got %s", status)
	}
}

// TestLWHeartbeatSkipsUnsupportedMethod：lw 不支持的方法绝不能派发，
// 且任务必须保留在队列（不被静默丢弃）。
func TestLWHeartbeatSkipsUnsupportedMethod(t *testing.T) {
	tasks := map[string]*TaskInfo{
		"thttp": {
			TaskID: "thttp", Method: "http_flood", Target: "http://1.2.3.4/",
			Duration: 60, Threads: 8, Status: "pending",
			Workers: map[string]*TaskStats{},
		},
	}
	c := newLWTestCtrl(tasks, []string{"thttp"})

	if got := lwHeartbeat(t, c, "lw-1"); got != nil {
		t.Fatalf("http_flood must not be dispatched to lw, got %+v", got)
	}
	c.mu.RLock()
	kept := len(c.pendingIDs) == 1 && c.pendingIDs[0] == "thttp"
	_, assigned := tasks["thttp"].Workers["lw-1"]
	c.mu.RUnlock()
	if !kept || assigned {
		t.Fatalf("task must stay pending and unassigned, pendingIDs=%v assigned=%v", c.pendingIDs, assigned)
	}
}

// TestOnlineWorkersAllAssignedLWCapability：lw 节点只在 lw 支持的方法上
// 参与"全部领取"判定。tcp_syn 现在属于 lw 支持范围，缺 lw 上报时不得
// 提前翻转 running；非支持方法（http_flood）则忽略 lw 节点。
func TestOnlineWorkersAllAssignedLWCapability(t *testing.T) {
	c := &Ctrl{
		nodes: map[string]*NodeInfo{
			"lw-1": {WorkerID: "lw-1", Tags: []string{"lw"}, Status: "READY"},
			"go-1": {WorkerID: "go-1", Status: "READY"},
		},
		tasks: map[string]*TaskInfo{},
	}

	// tcp_syn：lw 参与 → 只派给 go-1 时未全部领取
	tsyn := &TaskInfo{TaskID: "tsyn", Method: "tcp_syn", Workers: map[string]*TaskStats{"go-1": {WorkerID: "go-1"}}}
	// http_flood：lw 不参与 → 只派给 go-1 即视为全部领取
	thttp := &TaskInfo{TaskID: "thttp", Method: "http_flood", Workers: map[string]*TaskStats{"go-1": {WorkerID: "go-1"}}}

	c.mu.Lock()
	tsynDone := c.onlineWorkersAllAssigned(tsyn)
	thttpDone := c.onlineWorkersAllAssigned(thttp)
	c.mu.Unlock()

	if tsynDone {
		t.Fatal("tcp_syn must wait for lw node (lw-capable method)")
	}
	if !thttpDone {
		t.Fatal("http_flood must ignore lw node and complete after go-1")
	}
}

// TestLWPeriodicReportKeepsNodeAlive：周期上报是 lw 存活证明。
// lw 在攻击循环里阻塞、不发心跳，长任务期间只能靠周期上报刷新心跳，
// 否则会被判离线（面板闪烁、任务重派）。
func TestLWPeriodicReportKeepsNodeAlive(t *testing.T) {
	c := &Ctrl{
		adminToken:  "admintest",
		workerToken: "workertest",
		nodes: map[string]*NodeInfo{
			"lw-1": {
				WorkerID:      "lw-1",
				Tags:          []string{"lw"},
				Status:        "OFFLINE",
				LastHeartbeat: time.Now().Add(-2 * time.Minute),
			},
		},
		tasks: map[string]*TaskInfo{
			"t1": {
				TaskID: "t1", Method: "tcp_syn", Status: "running",
				Workers: map[string]*TaskStats{"lw-1": {WorkerID: "lw-1"}},
			},
		},
	}

	req := httptest.NewRequest("POST", "/api/lw/report", strings.NewReader(
		`{"token":"workertest","node_id":"lw-1","task_id":"t1","packets":1234,"bytes":49360,"errors":0,"pps":600,"finished":false}`))
	rec := httptest.NewRecorder()
	c.handleLWReport(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	c.mu.RLock()
	node := c.nodes["lw-1"]
	task := c.tasks["t1"]
	st := task.Workers["lw-1"]
	c.mu.RUnlock()

	if time.Since(node.LastHeartbeat) > 5*time.Second {
		t.Fatalf("periodic report must refresh LastHeartbeat, got %v ago", time.Since(node.LastHeartbeat))
	}
	if node.Status != "ATTACKING" {
		t.Fatalf("node should be ATTACKING while running a task, got %s", node.Status)
	}
	if task.Status != "running" || st.Finished {
		t.Fatalf("periodic report must not finish task: status=%s finished=%v", task.Status, st.Finished)
	}
	if st.PacketsSent != 1234 || st.BytesSent != 49360 || st.CurrentPPS != 600 {
		t.Fatalf("periodic stats not applied: %+v", st)
	}
}

// TestLWNodeLocked 语义：locked 版本不拿锁，正确识别 lw 节点
func TestLWNodeLocked(t *testing.T) {
	if !isLWNodeLocked(&NodeInfo{Tags: []string{"lw"}}) {
		t.Fatal("lw tag node should be detected")
	}
	if isLWNodeLocked(&NodeInfo{Tags: []string{"vse"}}) {
		t.Fatal("non-lw node should not be detected")
	}
	if isLWNodeLocked(nil) {
		t.Fatal("nil node should not be detected")
	}
}

// TestLWReportFinishedSemantics：finished=false 周期上报只更新统计，
// 不得把任务提前标记完成；finished=true（或缺省字段=旧协议）才触发完成判定。
func TestLWReportFinishedSemantics(t *testing.T) {
	c := &Ctrl{
		adminToken:  "admintest",
		workerToken: "workertest",
		nodes: map[string]*NodeInfo{
			"lw-1": {WorkerID: "lw-1", Tags: []string{"lw"}, Status: "ATTACKING"},
		},
		tasks: map[string]*TaskInfo{
			"t1": {
				TaskID:  "t1",
				Method:  "dns_reflector",
				Status:  "running",
				Workers: map[string]*TaskStats{"lw-1": {WorkerID: "lw-1"}},
			},
		},
	}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/lw/report", strings.NewReader(body))
		rec := httptest.NewRecorder()
		c.handleLWReport(rec, req)
		return rec
	}

	// 周期上报（finished=false）：只更新统计，任务必须保持 running
	if rec := post(`{"token":"workertest","node_id":"lw-1","task_id":"t1","packets":200,"bytes":0,"errors":0,"pps":50,"finished":false}`); rec.Code != 200 {
		t.Fatalf("periodic report status=%d body=%s", rec.Code, rec.Body.String())
	}
	c.mu.RLock()
	after := c.tasks["t1"]
	stat := after.Workers["lw-1"]
	status := after.Status
	c.mu.RUnlock()
	if status != "running" {
		t.Fatalf("periodic report must not complete task, status=%s", status)
	}
	if stat.PacketsSent != 200 || stat.Finished {
		t.Fatalf("periodic report should update stats only, got packets=%d finished=%v", stat.PacketsSent, stat.Finished)
	}

	// 空 task_id 的周期上报：静默接受，不 404
	if rec := post(`{"token":"workertest","node_id":"lw-1","task_id":"","packets":0,"bytes":0,"errors":0,"pps":0,"finished":false}`); rec.Code != 200 {
		t.Fatalf("empty-task periodic report status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 完成上报（finished 字段缺省 = 旧协议）：任务 completed
	if rec := post(`{"token":"workertest","node_id":"lw-1","task_id":"t1","packets":5000,"bytes":0,"errors":0,"pps":0}`); rec.Code != 200 {
		t.Fatalf("finish report status=%d body=%s", rec.Code, rec.Body.String())
	}
	c.mu.RLock()
	final := c.tasks["t1"]
	c.mu.RUnlock()
	if final.Status != "completed" {
		t.Fatalf("finish report should complete task, status=%s", final.Status)
	}
	if st := final.Workers["lw-1"]; !st.Finished || st.PacketsSent != 5000 {
		t.Fatalf("finish report stats wrong: finished=%v packets=%d", st.Finished, st.PacketsSent)
	}
}

// TestLWReportCancellingAck：完成上报时任务处于 cancelling →
// 记为已确认取消并走 finishCancellingTask 收尾（重派未完成节点）。
func TestLWReportCancellingAck(t *testing.T) {
	c := &Ctrl{
		adminToken:  "admintest",
		workerToken: "workertest",
		nodes: map[string]*NodeInfo{
			"lw-1": {WorkerID: "lw-1", Tags: []string{"lw"}, Status: "ATTACKING"},
		},
		tasks: map[string]*TaskInfo{
			"t1": {
				TaskID:          "t1",
				Method:          "dns_reflector",
				Status:          "cancelling",
				CancelToRetry:   true,
				CancellingSince: time.Now(),
				Workers:         map[string]*TaskStats{"lw-1": {WorkerID: "lw-1"}},
			},
		},
		cancelIDs: []string{"t1"},
	}
	req := httptest.NewRequest("POST", "/api/lw/report", strings.NewReader(`{"token":"workertest","node_id":"lw-1","task_id":"t1","packets":10,"bytes":0,"errors":0,"pps":0,"finished":true}`))
	rec := httptest.NewRecorder()
	c.handleLWReport(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	c.mu.RLock()
	task := c.tasks["t1"]
	c.mu.RUnlock()
	// 唯一节点已自然完成（Finished=true）→ 取消重派直接收尾为 completed，
	// 不会把整个任务重跑一遍完整时长。
	if task.Status != "completed" {
		t.Fatalf("cancelled-for-retry with all workers finished should complete, got %s", task.Status)
	}
	if !task.Workers["lw-1"].Finished {
		t.Fatalf("lw-1 should be marked finished")
	}
}
