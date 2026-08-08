package attack

import (
	"log"
	"sync"
	"time"
)

// HotReflectorPool 攻击中的热反射器池，支持实时替换失效节点
type HotReflectorPool struct {
	active   []string          // 当前使用的反射器
	backup   []string          // 热备反射器
	failed   map[string]int    // 实时失败计数
	replaced map[string]string // 已替换记录 old->new

	mu       sync.Mutex
	stopChan chan struct{}
	stopOnce sync.Once
}

// NewHotReflectorPool 创建热池
func NewHotReflectorPool(reflectors []string) *HotReflectorPool {
	// 80% 作为 active，20% 作为 backup
	split := len(reflectors) * 4 / 5
	if split == 0 {
		split = len(reflectors)
	}

	return &HotReflectorPool{
		active:   reflectors[:split],
		backup:   reflectors[split:],
		failed:   make(map[string]int),
		replaced: make(map[string]string),
		stopChan: make(chan struct{}),
	}
}

// Start 启动健康检查（每30秒）
func (h *HotReflectorPool) Start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				h.HealthCheck()
			case <-h.stopChan:
				return
			}
		}
	}()
}

// Stop 停止热池（幂等，可多次调用）
func (h *HotReflectorPool) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopChan)
	})
}

// GetActive 获取当前活跃反射器列表
func (h *HotReflectorPool) GetActive() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]string, len(h.active))
	copy(result, h.active)
	return result
}

// RecordFailure 记录反射器失败
func (h *HotReflectorPool) RecordFailure(reflector string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failed[reflector]++
}

// RecordSuccess 记录反射器成功（重置失败计数）
func (h *HotReflectorPool) RecordSuccess(reflector string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failed, reflector)
}

// HealthCheck 健康检查，替换失效节点
func (h *HotReflectorPool) HealthCheck() {
	h.mu.Lock()
	defer h.mu.Unlock()

	replaced := 0
	for i, reflector := range h.active {
		failCount := h.failed[reflector]
		if failCount >= 10 {
			// 从 backup 中取一个替换
			if len(h.backup) > 0 {
				newReflector := h.backup[0]
				h.backup = h.backup[1:]

				h.active[i] = newReflector
				h.replaced[reflector] = newReflector
				delete(h.failed, reflector)

				replaced++
				log.Printf("[hot_pool] replaced failed reflector: %s -> %s (fails=%d)",
					reflector, newReflector, failCount)
			}
		}
	}

	if replaced > 0 {
		log.Printf("[hot_pool] health check: replaced %d reflectors, backup remaining: %d",
			replaced, len(h.backup))
	}
}

// GetStats 获取统计信息
func (h *HotReflectorPool) GetStats() (active, backup, failed, replaced int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.active), len(h.backup), len(h.failed), len(h.replaced)
}
