package controller

import (
	"testing"

	"blackout/internal/attack"
)

// TestValidMethodsDerivedFromEngine 白名单必须与攻击引擎清单严格一致：
//   - 引擎支持的每个方法都必须在白名单（否则创建任务被拒 "unknown method"）
//   - 白名单不得包含引擎不支持的方法（否则任务创建成功但 worker 静默忽略）
//
// 该测试锁死"单一事实来源"约定（validMethods 由 attack.SupportedMethods 派生），
// 防止未来新增方法时再次出现清单脱节（历史事故：白名单漏 6 个方法、
// worker 分派漏 tcp_syn_spoof）。
func TestValidMethodsDerivedFromEngine(t *testing.T) {
	engine := attack.SupportedMethods()
	for _, m := range engine {
		if !isValidMethod(m) {
			t.Errorf("engine method %q missing from validMethods — task creation would be rejected", m)
		}
		if m == "combo" {
			t.Errorf("engine list must not contain combo (orchestrated separately)")
		}
	}
	// 白名单 = 引擎清单 + combo，不多不少
	if len(validMethods) != len(engine)+1 {
		t.Errorf("validMethods size %d != engine %d + combo; lists have diverged", len(validMethods), len(engine))
	}
	for m := range validMethods {
		if m == "combo" {
			continue
		}
		found := false
		for _, e := range engine {
			if e == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("validMethods contains %q but engine does not implement it — worker would ignore the task", m)
		}
	}
	if !isValidMethod("combo") {
		t.Error("combo must be valid")
	}
	if isValidMethod("not_a_real_method") {
		t.Error("bogus method should be rejected")
	}
}

// TestEveryMethodDispatchable 引擎清单里的每个方法都必须能被 StartMethod 分派
// （返回非 nil session），防止"清单里有但分派漏实现"。
func TestEveryMethodDispatchable(t *testing.T) {
	for _, m := range attack.SupportedMethods() {
		cfg := attack.AttackConfig{Target: "127.0.0.1:1", Method: m, Duration: 1, Threads: 1}
		s := attack.StartMethod(cfg)
		if s == nil {
			t.Errorf("method %q is advertised as supported but StartMethod returned nil", m)
			continue
		}
		s.Stop()
		<-s.DoneChan
	}
	if s := attack.StartMethod(attack.AttackConfig{Target: "x", Method: "bogus_method"}); s != nil {
		t.Error("unknown method should return nil session")
	}
}
