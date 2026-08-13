package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AuditEntry 操作审计条目：谁（角色/token）、何时、做了什么。
type AuditEntry struct {
	Time    int64  `json:"time"`
	Role    string `json:"role"`    // admin / worker
	TokenID string `json:"token_id"` // token 前 8 位（用于区分不同 worker，不泄露完整凭据）
	Action  string `json:"action"`
	Detail  string `json:"detail"`
}

// AuditLog 审计记录：内存环形缓冲（供 API 查询）+ JSON Lines 追加落盘
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	max     int
	file    string
}

func NewAuditLog(file string, max int) *AuditLog {
	os.MkdirAll("data", 0755)
	return &AuditLog{entries: make([]AuditEntry, 0, max), max: max, file: file}
}

// Add 追加一条审计记录（内存 + 落盘）
func (a *AuditLog) Add(role, tokenID, action, detail string) {
	e := AuditEntry{Time: time.Now().Unix(), Role: role, TokenID: tokenID, Action: action, Detail: detail}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	if len(a.entries) > a.max {
		a.entries = a.entries[len(a.entries)-a.max:]
	}
	a.mu.Unlock()

	line, _ := json.Marshal(e)
	f, err := os.OpenFile(a.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

// Recent 返回最近 limit 条（可选按 action 过滤）
func (a *AuditLog) Recent(limit int, action string) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	list := make([]AuditEntry, 0, len(a.entries))
	for _, e := range a.entries {
		if action != "" && e.Action != action {
			continue
		}
		list = append(list, e)
	}
	if len(list) > limit {
		list = list[len(list)-limit:]
	}
	// 倒序返回（最新在前）
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	return list
}

// audit 从 HTTP 请求识别调用者身份并记录审计（Controller 内部便捷入口）
func (c *Ctrl) audit(r *http.Request, action, detail string) {
	role, tokenID := c.requestIdentity(r)
	c.auditLog.Add(role, tokenID, action, detail)
}

// requestIdentity 解析请求 token 的角色与标识
func (c *Ctrl) requestIdentity(r *http.Request) (role, tokenID string) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return "unknown", ""
	}
	if token == c.adminToken {
		return "admin", "admin"
	}
	if token == c.workerToken {
		return "worker", "shared"
	}
	// per-worker token：记录前 8 位
	if len(token) > 8 {
		tokenID = token[:8]
	} else {
		tokenID = token
	}
	return "worker", tokenID
}

// handleAudit GET /api/audit?limit=200&action=xxx （仅 admin）
func (c *Ctrl) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"GET required"}`, 405)
		return
	}
	limit := 200
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	if limit < 1 || limit > 2000 {
		limit = 200
	}
	action := r.URL.Query().Get("action")
	list := c.auditLog.Recent(limit, action)
	writeJSON(w, map[string]interface{}{"logs": list, "total": len(list)})
}

// audit 记录点辅助：任务创建/停止等高频操作统一入口
func (c *Ctrl) auditAction(r *http.Request, action, detail string) {
	c.audit(r, action, detail)
	log.Printf("[audit] %s: %s", action, detail)
}
