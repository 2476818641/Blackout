package attack

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimiterNoLimit 验证 limit<=0 时不做任何限流。
func TestRateLimiterNoLimit(t *testing.T) {
	l := newRateLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if !l.allow(1500) {
			t.Fatalf("unlimited limiter denied packet %d", i)
		}
	}
}

// TestRateLimiterPPSHighFrequency 是本次修复的核心回归测试。
// 旧实现每次调用都把 elapsed*limit 截断为 int64，在高频调用下
// 单次增量 <1 会被截成 0，时间被丢弃，导致令牌桶严重欠发放。
// 这里以远高于 PPS 上限的频率轮询 1 秒，放行数应接近上限而非趋近 0。
func TestRateLimiterPPSHighFrequency(t *testing.T) {
	const limitPPS = 1000
	l := newRateLimiter(limitPPS, 0)

	allowed := 0
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if l.allow(1) {
			allowed++
		}
		time.Sleep(50 * time.Microsecond) // ~20000 次/秒轮询，远高于 1000 PPS
	}

	// 初始桶满(1000) + 1 秒补充(1000) ≈ 2000，允许合理裕量。
	if allowed < 1500 {
		t.Fatalf("high-frequency polling under-provisioned: allowed=%d, want >=1500 (truncation bug regression)", allowed)
	}
	if allowed > 2600 {
		t.Fatalf("limiter over-provisioned: allowed=%d, want <=2600", allowed)
	}
}

// TestRateLimiterBPS 验证字节维度限流。
func TestRateLimiterBPS(t *testing.T) {
	const limitBPS = 100000 // 100 KB/s
	l := newRateLimiter(0, limitBPS)

	// 桶初始满，第一发 100000 字节应放行，之后立即再发应被拒。
	if !l.allow(limitBPS) {
		t.Fatal("first full-bucket packet should be allowed")
	}
	if l.allow(1) {
		t.Fatal("packet after bucket drained should be denied")
	}
}

// TestRateLimiterBothDimensions 验证任一维度耗尽都会拒绝，
// 且被拒绝时不扣减另一维度的令牌（避免漂移）。
func TestRateLimiterBothDimensions(t *testing.T) {
	// PPS 充足但 BPS 不足：应因 BPS 被拒。
	l := newRateLimiter(1000000, 500)
	if l.allow(1000) {
		t.Fatal("packet exceeding BPS budget should be denied")
	}
	// BPS 拒绝后 PPS 令牌不应被扣减，小包仍可放行。
	if !l.allow(100) {
		t.Fatal("small packet within both budgets should be allowed")
	}
}

// TestRateLimiterConcurrent 验证并发调用下计数不越界（用 -race 运行捕获数据竞争）。
func TestRateLimiterConcurrent(t *testing.T) {
	const limitPPS = 5000
	l := newRateLimiter(limitPPS, 0)

	var allowed int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(500 * time.Millisecond)

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if l.allow(1) {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()

	// 初始 5000 + 0.5 秒补充 2500 ≈ 7500，给足并发裕量上限。
	total := atomic.LoadInt64(&allowed)
	if total == 0 {
		t.Fatal("concurrent limiter allowed nothing")
	}
	if total > 9000 {
		t.Fatalf("concurrent limiter over-provisioned: allowed=%d, want <=9000", total)
	}
}
