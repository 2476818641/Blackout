package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TargetGuard 目标保护规则：防止误攻击内网/保留段/黑名单目标。
// 持久化在 data/target_guard.json（仅 admin 可修改）。
// 判定顺序：白名单（精确/CIDR/域名后缀）→ 黑名单（精确/CIDR/域名后缀）
// → 内网保留段（BlockPrivate）→ 放行。
type TargetGuard struct {
	Enabled       bool     `json:"enabled"`        // 总开关（默认 true）
	BlockPrivate  bool     `json:"block_private"`  // 禁止内网/保留地址段（默认 true）
	ResolveHosts  bool     `json:"resolve_hosts"`  // 域名目标解析后校验 IP（防 DNS 指向内网），默认 true
	BlockedIPs    []string `json:"blocked_ips"`    // 精确 IP 黑名单
	BlockedCIDR   []string `json:"blocked_cidr"`   // CIDR 黑名单
	BlockedDomains []string `json:"blocked_domains"` // 域名黑名单（子串匹配，如 "gov.cn"）
	AllowedIPs    []string `json:"allowed_ips"`    // 精确 IP 白名单（优先于黑名单/私有段）
	AllowedCIDR   []string `json:"allowed_cidr"`   // CIDR 白名单
	AllowedDomains []string `json:"allowed_domains"` // 域名后缀白名单（如 "example.com"；为空 = 不限制）
}

// defaultTargetGuard 出厂规则：全开，无黑白名单
func defaultTargetGuard() TargetGuard {
	return TargetGuard{Enabled: true, BlockPrivate: true, ResolveHosts: true}
}

// privateCIDRs 内网/保留/不可路由地址段（IPv4 + IPv6）
var privateCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

func loadTargetGuard(path string) TargetGuard {
	g := defaultTargetGuard()
	data, err := os.ReadFile(path)
	if err != nil {
		return g
	}
	if json.Unmarshal(data, &g) != nil {
		log.Printf("[guard] failed to parse %s, using defaults", path)
		return defaultTargetGuard()
	}
	return g
}

func (c *Ctrl) persistTargetGuard() {
	c.guardMu.RLock()
	data, err := json.MarshalIndent(c.guard, "", "  ")
	c.guardMu.RUnlock()
	if err != nil {
		return
	}
	tmp := c.guardFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("[guard] write error: %v", err)
		return
	}
	os.Remove(c.guardFile)
	if err := os.Rename(tmp, c.guardFile); err != nil {
		log.Printf("[guard] rename error: %v", err)
	}
}

// parseTargetHost 从目标字符串提取主机名（支持 IP:端口、URL、IPv6）
func parseTargetHost(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	// URL 形式：取 scheme 后部分
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	// 去掉路径
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if host, _, err := net.SplitHostPort(t); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(t, "[]")
}

// checkIP 按规则判定单个 IP 是否允许作为攻击目标
func (c *Ctrl) checkIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// 白名单优先
	for _, a := range c.guard.AllowedIPs {
		if strings.TrimSpace(a) != "" && ip.Equal(net.ParseIP(strings.TrimSpace(a))) {
			return nil
		}
	}
	for _, cidr := range c.guard.AllowedCIDR {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && n.Contains(ip) {
			return nil
		}
	}

	// 黑名单
	for _, a := range c.guard.BlockedIPs {
		if strings.TrimSpace(a) != "" && ip.Equal(net.ParseIP(strings.TrimSpace(a))) {
			return fmt.Errorf("target %s is blocked (blocked IP)", ipStr)
		}
	}
	for _, cidr := range c.guard.BlockedCIDR {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && n.Contains(ip) {
			return fmt.Errorf("target %s is blocked (blocked CIDR %s)", ipStr, cidr)
		}
	}

	// 内网/保留段
	if c.guard.BlockPrivate {
		for _, cidr := range privateCIDRs {
			if _, n, _ := net.ParseCIDR(cidr); n.Contains(ip) {
				return fmt.Errorf("target %s is in private/reserved range %s (blocked by target guard)", ipStr, cidr)
			}
		}
	}
	return nil
}

// validateTargets 校验一批目标；任一目标被拦截即返回错误（任务创建被拒绝）。
func (c *Ctrl) validateTargets(targets []string) error {
	c.guardMu.RLock()
	defer c.guardMu.RUnlock()

	if !c.guard.Enabled {
		return nil
	}

	for _, t := range targets {
		host := parseTargetHost(t)
		if host == "" {
			return fmt.Errorf("invalid target: %q", t)
		}
		// 域名黑名单（子串）
		hostLower := strings.ToLower(host)
		for _, d := range c.guard.BlockedDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" && strings.Contains(hostLower, d) {
				return fmt.Errorf("target %s is blocked (blocked domain rule: %s)", t, d)
			}
		}
		// 域名后缀白名单（非空时必须匹配）
		if len(c.guard.AllowedDomains) > 0 && net.ParseIP(host) == nil {
			matched := false
			for _, d := range c.guard.AllowedDomains {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" && (hostLower == d || strings.HasSuffix(hostLower, "."+d)) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("target %s is not in allowed domains", t)
			}
		}

		if ip := net.ParseIP(host); ip != nil {
			if err := c.checkIP(host); err != nil {
				return err
			}
			continue
		}

		// 域名目标：解析后校验（防 DNS 重绑定/域名解析到内网）
		if c.guard.ResolveHosts {
			ips, err := net.LookupIP(host)
			if err != nil {
				return fmt.Errorf("target %s: DNS resolution failed (%v)", t, err)
			}
			for _, ip := range ips {
				if err := c.checkIP(ip.String()); err != nil {
					return fmt.Errorf("target %s resolves to blocked address: %v", t, err)
				}
			}
		}
	}
	return nil
}

// handleGuard GET/PUT /api/guard
// GET → 当前规则（admin/worker 可见）；PUT → 更新规则（仅 admin）
func (c *Ctrl) handleGuard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.guardMu.RLock()
		g := c.guard
		c.guardMu.RUnlock()
		writeJSON(w, g)
	case "PUT", "POST":
		var g TargetGuard
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		// 校验规则合法性：CIDR 必须可解析
		for _, cidr := range append(append([]string{}, g.BlockedCIDR...), g.AllowedCIDR...) {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
				writeJSON(w, map[string]string{"error": "invalid CIDR: " + cidr})
				return
			}
		}
		c.guardMu.Lock()
		c.guard = g
		c.guardMu.Unlock()
		c.persistTargetGuard()
		c.audit(r, "guard_update", fmt.Sprintf("enabled=%v block_private=%v blocked_ips=%d allowed_ips=%d", g.Enabled, g.BlockPrivate, len(g.BlockedIPs), len(g.AllowedIPs)))
		log.Printf("[guard] rules updated: %+v", g)
		writeJSON(w, map[string]interface{}{"ok": true})
	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// guardLastBlock 记录最近一次拦截（供 UI 提示），避免审计日志刷屏
var guardBlockLogMu sync.Mutex

func guardBlockLog(msg string) {
	guardBlockLogMu.Lock()
	defer guardBlockLogMu.Unlock()
	log.Printf("[guard] BLOCKED: %s (at %s)", msg, time.Now().Format(time.RFC3339))
}
