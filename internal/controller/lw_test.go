package controller

import (
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
		adminToken: "admintest",
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
