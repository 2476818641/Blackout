package controller

import (
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
