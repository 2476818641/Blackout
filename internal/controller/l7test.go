package controller

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"blackout/internal/attack"
)

// ============================================================
// L7 目标侦察与攻击推荐：
//   POST /api/l7/test  {"target":"https://example.com","timeout":5}
//
// 对目标做一次轻量指纹探测（HTTP/2 ALPN、响应头、CVE 版本表），
// 返回检测结果 + 按优先级排序的攻击推荐：
//   - 目标存在 CVE 脆弱点（Rapid Reset / CONTINUATION / HPACK Bomb）
//     → 对应 CVE 攻击排最前
//   - 否则推荐通用流量型（http_flood / post_flood / http2_flood）
// 前端可一键把推荐方法预填进攻击表单发起。
// ============================================================

// L7Recommendation 单个攻击推荐
type L7Recommendation struct {
	Method    string                 `json:"method"`
	ReasonKey string                 `json:"reason_key"` // 前端 i18n 键
	Priority  int                    `json:"priority"`   // 越大越优先
	Params    map[string]interface{} `json:"params"`     // 预填参数（threads 等）
}

// L7TestResponse 检测 + 推荐结果
type L7TestResponse struct {
	Fingerprint     *attack.L7Fingerprint `json:"fingerprint"`
	Recommendations []L7Recommendation    `json:"recommendations"`
}

// handleL7Test POST /api/l7/test
// 探测目标并返回推荐攻击列表。探测为单次轻量请求，不产生持续压力。
func (c *Ctrl) handleL7Test(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	var req struct {
		Target  string `json:"target"`
		Timeout int    `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid json"})
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeJSON(w, map[string]string{"error": "target is required"})
		return
	}
	// 无 scheme 时补 http://（FingerprintL7Target 需要完整 URL）
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second // 探测超时上限，防同步请求挂太久
	}

	fp := attack.FingerprintL7Target(target, timeout)

	// 80 端口探测不到 HTTP/2 时补一次 443 探测：
	// http://example.com 通常只有 h2c 才在 80 上支持（罕见），而 443 的
	// TLS+ALPN 才是绝大多数站点的 h2 入口。无 scheme 输入默认补 http://，
	// 若目标实际跑在 443 上，不补探测会漏掉全部 h2 CVE 推荐。
	if !fp.HTTP2 && !fp.HTTP2C && strings.HasPrefix(target, "http://") {
		httpsTarget := "https://" + strings.TrimPrefix(target, "http://")
		fp443 := attack.FingerprintL7Target(httpsTarget, timeout)
		if fp443.HTTP2 {
			fp.HTTP2 = true
			fp.Notes = append(fp.Notes, "HTTP/2 detected via HTTPS (443) ALPN probe")
		}
	}

	recs := buildL7Recommendations(fp)
	c.auditAction(r, "l7_test", target)
	writeJSON(w, L7TestResponse{Fingerprint: fp, Recommendations: recs})
}

// buildL7Recommendations 根据指纹结果生成推荐（CVE 优先，流量型兜底）。
// 排序保证：推荐的先后即前端展示顺序（已按 Priority 降序 push）。
func buildL7Recommendations(fp *attack.L7Fingerprint) []L7Recommendation {
	var recs []L7Recommendation
	h2 := fp != nil && (fp.HTTP2 || fp.HTTP2C)
	baseParams := func(threads int) map[string]interface{} {
		return map[string]interface{}{"threads": threads, "duration": 60}
	}

	// —— CVE 攻击（仅目标支持 HTTP/2 时推荐）——
	if h2 {
		// HPACK Bomb：IIS 内核态无修复，恒脆弱；其余未修复版本大概率脆弱。
		// 攻击端有自动门控（StartHTTP2BombEx 内部复检 BombVuln，误判自动
		// 降级 CONTINUATION Flood），推荐无风险。
		if fp.BombVuln {
			recs = append(recs, L7Recommendation{
				Method: "http2_bomb", ReasonKey: "l7_rec_bomb", Priority: 100,
				Params: baseParams(100),
			})
		}
		if fp.Vulnerable {
			recs = append(recs, L7Recommendation{
				Method: "http2_reset", ReasonKey: "l7_rec_reset", Priority: 90,
				Params: baseParams(100),
			})
		}
		if fp.ContinuationVuln {
			recs = append(recs, L7Recommendation{
				Method: "http2_continuation", ReasonKey: "l7_rec_cont", Priority: 80,
				Params: baseParams(100),
			})
		}
	}

	// —— 通用流量型（本次性能修复后的三种，不依赖目标特性）——
	recs = append(recs,
		L7Recommendation{
			Method: "http_flood", ReasonKey: "l7_rec_http", Priority: 60,
			Params: baseParams(50),
		},
		L7Recommendation{
			Method: "post_flood", ReasonKey: "l7_rec_post", Priority: 50,
			Params: baseParams(50),
		},
	)
	if h2 {
		recs = append(recs, L7Recommendation{
			Method: "http2_flood", ReasonKey: "l7_rec_h2", Priority: 40,
			Params: baseParams(50),
		})
	} else {
		// 目标探测不到 HTTP/2：仍可尝试（https ALPN 未暴露 / 明文 h2c 探测失败），
		// 但标注不确定，避免用户误以为必有效
		recs = append(recs, L7Recommendation{
			Method: "http2_flood", ReasonKey: "l7_rec_h2_noalpn", Priority: 40,
			Params: baseParams(50),
		})
	}
	return recs
}
