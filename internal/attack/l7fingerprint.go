package attack

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// L7Fingerprint 目标 Web 组件指纹（L7 攻击前探测用）：
// 提取 Server/X-Powered-By 响应头、HTTP/2 支持（ALPN）、TLS 证书信息，
// 并对照 HTTP/2 DoS 版本表给出三套判定：
//   Vulnerable        — CVE-2023-44487 Rapid Reset
//   ContinuationVuln  — CVE-2024-27316 / CVE-2024-27983 / CVE-2023-45288 CONTINUATION Flood
//   BombVuln          — CVE-2026-49975 / CVE-2026-47774 HPACK Bomb（IIS 内核态无修复，恒脆弱）
type L7Fingerprint struct {
	Target     string   `json:"target"`
	Product    string   `json:"product"`      // nginx / apache / envoy / iis / ...
	Version    string   `json:"version"`      // 1.25.2
	ServerHeader string `json:"server_header"`
	XPoweredBy string   `json:"x_powered_by"`
	HTTP2      bool     `json:"http2"`        // 目标是否支持 HTTP/2
	HTTP2C     bool     `json:"http2c"`       // 明文 h2c（仅 http:// 目标）
	TLSIssuer  string   `json:"tls_issuer,omitempty"`
	Vulnerable     bool `json:"vulnerable"`       // Rapid Reset
	ContinuationVuln bool `json:"continuation_vuln"` // CONTINUATION Flood
	BombVuln       bool `json:"bomb_vuln"`         // HPACK Bomb
	// 能力探测（推荐扩展方法用）
	WS            bool   `json:"ws"`              // WebSocket 支持（Upgrade 返回 101）
	SlowApplicable bool  `json:"slow_applicable"` // 慢速适用：请求头无快速超时（>2s 不断开）
	StaticRange   bool   `json:"static_range"`    // 支持 Range 请求（静态资源/CDN）
	BodySize      int    `json:"body_size"`       // 首页响应体大小（bytes）
	Notes      []string `json:"notes"`
}

// fingerprintClient 探测用 HTTP 客户端（短超时，跳过证书校验）
var fingerprintClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// FingerprintL7Target 对目标做一次轻量探测（单个 GET，不产生持续压力）。
//   - https:// 目标：先 ALPN 探测 h2 支持（协商到 h2 → HTTP2=true）
//   - http:// 目标：尝试一次 h2c 前言探测（少见，失败不计）
//   - 提取 Server / X-Powered-By → 匹配产品版本 → CVE-2023-44487 脆弱判定
func FingerprintL7Target(target string, timeout time.Duration) *L7Fingerprint {
	fp := &L7Fingerprint{Target: target}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		fp.Notes = append(fp.Notes, "invalid target URL")
		return fp
	}
	host := u.Host
	if u.Scheme == "" {
		u.Scheme = "http"
	}

	// TLS 目标：ALPN 探测 h2 支持（一次性握手，顺带拿证书签发者）
	if u.Scheme == "https" {
		addr := host
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = host + ":443"
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err == nil {
			state := conn.ConnectionState()
			fp.HTTP2 = state.NegotiatedProtocol == "h2"
			if len(state.PeerCertificates) > 0 {
				fp.TLSIssuer = state.PeerCertificates[0].Issuer.CommonName
			}
			conn.Close()
		} else {
			fp.Notes = append(fp.Notes, "TLS handshake failed: "+err.Error())
		}
	}

	// HTTP 请求探测响应头
	req, err := http.NewRequest("GET", u.Scheme+"://"+host+"/", nil)
	if err != nil {
		return fp
	}
	req.Header.Set("User-Agent", "Blackout-Fingerprint/1.0")
	resp, err := fingerprintClient.Do(req)
	if err != nil {
		fp.Notes = append(fp.Notes, "HTTP probe failed: "+err.Error())
	} else {
		fp.ServerHeader = resp.Header.Get("Server")
		fp.XPoweredBy = resp.Header.Get("X-Powered-By")
		resp.Body.Close()
		if resp.ProtoMajor == 2 {
			fp.HTTP2 = true // https 已由 ALPN 判定；此处兼容 httptest 等
		}
	}

	// 明文 h2c 探测（仅 http:// 目标）：一次前言握手看是否回 SETTINGS
	if u.Scheme == "http" && !fp.HTTP2 {
		fp.HTTP2C = probeH2C(host, timeout)
	}

	// —— 扩展能力探测（为推荐更多攻击方法提供依据）——
	fp.probeCapabilities(u, host, timeout)

	fp.assessCVE44487()
	return fp
}

// probeCapabilities 轻量能力探测（每个探测只发 1-2 个小请求/短连接）：
//   - WebSocket 支持：Upgrade 请求是否回 101
//   - 慢速适用性：不完整请求头是否在 2s 内被目标断开（有请求头超时则 slowloris 效果差）
//   - Range/静态资源：Accept-Ranges 响应头
//   - 首页响应体大小（判断动态/静态站点）
func (fp *L7Fingerprint) probeCapabilities(u *url.URL, host string, timeout time.Duration) {
	base := u.Scheme + "://" + host

	// 1. WebSocket 支持（探测常见挂载路径；101 = 支持）
	wsPaths := []string{"/", "/ws", "/websocket", "/socket.io/"}
	for _, p := range wsPaths {
		req, err := http.NewRequest("GET", base+p, nil)
		if err != nil {
			break
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("User-Agent", "Blackout-Fingerprint/1.0")
		resp, err := fingerprintClient.Do(req)
		if err != nil {
			continue
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code == 101 {
			fp.WS = true
			fp.Notes = append(fp.Notes, "WebSocket endpoint detected at "+p+" (101 Upgrade)")
			break
		}
	}

	// 2. Range/静态资源 + 响应大小
	req, err := http.NewRequest("GET", base+"/", nil)
	if err == nil {
		req.Header.Set("Range", "bytes=0-1023")
		req.Header.Set("User-Agent", "Blackout-Fingerprint/1.0")
		resp, err := fingerprintClient.Do(req)
		if err == nil {
			if resp.Header.Get("Accept-Ranges") == "bytes" || resp.StatusCode == 206 {
				fp.StaticRange = true
				fp.Notes = append(fp.Notes, "supports Range requests (static/CDN content)")
			}
			resp.Body.Close()
		}
	}

	// 3. 慢速适用性：发不完整请求头，2s 内被断开 = 目标有请求头超时
	addr := host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if u.Scheme == "https" {
			addr = addr + ":443"
		} else {
			addr = addr + ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		// 不完整请求头（无结束空行）
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: Blackout-Fingerprint/1.0\r\n"))
		buf := make([]byte, 1)
		n, _ := conn.Read(buf)
		conn.Close()
		if n > 0 {
			// 目标主动回了数据（可能立即 400/断开）——需要区分：收到响应字节=有超时防护或已解析
			fp.SlowApplicable = false
			fp.Notes = append(fp.Notes, "server responds fast to partial headers (slowloris limited)")
		} else {
			// 2s 无响应：请求头等待中，slowloris/slow_post 适用
			fp.SlowApplicable = true
			fp.Notes = append(fp.Notes, "server holds partial headers (slowloris/slow POST applicable)")
		}
	}

	// 4. 首页响应体大小（复用第一次 GET 的结果，此处单独取一次）
	req2, err := http.NewRequest("GET", base+"/", nil)
	if err == nil {
		req2.Header.Set("User-Agent", "Blackout-Fingerprint/1.0")
		resp, err := fingerprintClient.Do(req2)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
			resp.Body.Close()
			fp.BodySize = len(body)
		}
	}
}

// probeH2C 尝试与目标建立明文 HTTP/2 连接（发 preface+SETTINGS，等 SETTINGS 回应）
func probeH2C(host string, timeout time.Duration) bool {
	addr := host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = host + ":80"
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	framer := newH2Framer(conn)
	// HTTP/2 客户端连接前言
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return false
	}
	if err := framer.WriteSettings(); err != nil {
		return false
	}
	// 服务器支持 h2c 时会在收到 preface 后主动回 SETTINGS 帧
	for i := 0; i < 4; i++ {
		f, err := framer.ReadFrame()
		if err != nil {
			return false
		}
		if _, ok := f.(*http2.SettingsFrame); ok {
			return true
		}
	}
	return false
}

// assessCVE44487 对照 HTTP/2 DoS 版本表判定：
//   - Vulnerable:      CVE-2023-44487 Rapid Reset（nginx<1.25.3 / apache<2.4.58 / envoy 分支）
//   - ContinuationVuln: CONTINUATION Flood（nginx<1.25.4 / apache<2.4.59 / envoy<1.27.2）
//   - BombVuln:        HPACK Bomb（IIS 恒脆弱；未做 2024 修复的版本大概率也脆弱）
func (fp *L7Fingerprint) assessCVE44487() {
	s := strings.ToLower(fp.ServerHeader)
	parse := func() (product, version string) {
		// 形如 "nginx/1.25.2"、"Apache/2.4.57 (Ubuntu)"、"envoy"、"Microsoft-IIS/10.0"
		parts := strings.Fields(s)
		if len(parts) == 0 {
			return "", ""
		}
		seg := strings.SplitN(parts[0], "/", 2)
		product = strings.ToLower(seg[0])
		if len(seg) > 1 {
			version = seg[1]
		}
		return product, version
	}
	product, version := parse()
	fp.Product = product
	fp.Version = version

	if product == "" {
		fp.Notes = append(fp.Notes, "no Server header (custom/obfuscated server)")
		return
	}

	// IIS：内核态 http.sys 处理 h2，header 累积进内核池且解压后检查缺失
	// → HPACK Bomb 恒脆弱（至今无公开修复）；Rapid Reset/Continuation 影响一般
	if strings.HasPrefix(product, "microsoft-iis") {
		fp.BombVuln = true
		fp.Notes = append(fp.Notes, "IIS (http.sys): HPACK Bomb VULNERABLE (no public fix, kernel-mode header pooling)")
		fp.Notes = append(fp.Notes, "IIS: Rapid Reset / Continuation have limited impact (kernel processing)")
		return
	}

	switch product {
	case "nginx":
		if version != "" {
			if versionLess(version, "1.25.3") {
				fp.Vulnerable = true
				fp.Notes = append(fp.Notes, "nginx < 1.25.3 VULNERABLE to CVE-2023-44487 (Rapid Reset)")
			} else {
				fp.Notes = append(fp.Notes, "nginx >= 1.25.3 (Rapid Reset patched, still adds pressure)")
			}
			if versionLess(version, "1.25.4") {
				fp.ContinuationVuln = true
				fp.BombVuln = true
				fp.Notes = append(fp.Notes, "nginx < 1.25.4 VULNERABLE to CONTINUATION Flood + likely HPACK Bomb (CVE-2026-47774)")
			} else {
				fp.Notes = append(fp.Notes, "nginx >= 1.25.4 (CONTINUATION patched, frame processing still costs)")
			}
		} else {
			fp.Notes = append(fp.Notes, "nginx version hidden")
		}
	case "apache":
		if version != "" {
			if versionLess(version, "2.4.58") {
				fp.Vulnerable = true
				fp.Notes = append(fp.Notes, "Apache < 2.4.58 VULNERABLE to CVE-2023-44487 (Rapid Reset, mod_http2)")
			} else {
				fp.Notes = append(fp.Notes, "Apache >= 2.4.58 (Rapid Reset patched)")
			}
			if versionLess(version, "2.4.59") {
				fp.ContinuationVuln = true
				fp.BombVuln = true
				fp.Notes = append(fp.Notes, "Apache < 2.4.59 VULNERABLE to CONTINUATION Flood (CVE-2024-27316) + likely HPACK Bomb (CVE-2026-49975)")
			} else {
				fp.Notes = append(fp.Notes, "Apache >= 2.4.59 (CONTINUATION patched)")
			}
		} else {
			fp.Notes = append(fp.Notes, "Apache version hidden")
		}
	case "envoy":
		if version != "" {
			vuln := versionLess(version, "1.24.9")
			if !vuln && strings.HasPrefix(version, "1.25.") {
				vuln = versionLess(version, "1.25.8")
			}
			if !vuln && strings.HasPrefix(version, "1.26.") {
				vuln = versionLess(version, "1.26.5")
			}
			if !vuln && strings.HasPrefix(version, "1.27.") {
				vuln = versionLess(version, "1.27.1")
			}
			if vuln {
				fp.Vulnerable = true
				fp.Notes = append(fp.Notes, "Envoy VULNERABLE to CVE-2023-44487 (fixed in 1.24.9/1.25.8/1.26.5/1.27.1)")
			} else {
				fp.Notes = append(fp.Notes, "Envoy patched (Rapid Reset)")
			}
			if versionLess(version, "1.27.2") {
				fp.ContinuationVuln = true
				fp.Notes = append(fp.Notes, "Envoy < 1.27.2 VULNERABLE to CONTINUATION Flood")
			} else {
				fp.Notes = append(fp.Notes, "Envoy >= 1.27.2 (CONTINUATION patched)")
			}
		}
	case "cloudflare", "cloudfront", "akamai", "fastly":
		fp.Notes = append(fp.Notes, "behind CDN edge ("+product+") — h2 DoS hits edge, not origin")
	default:
		fp.Notes = append(fp.Notes, "component "+product+" not in HTTP/2 DoS version tables")
	}

	if !fp.HTTP2 && !fp.HTTP2C {
		fp.Notes = append(fp.Notes, "target does not advertise HTTP/2 — h2 DoS not applicable")
	}
}

// versionLess 简单版本比较（a < b），按 . 分段数字比较；非数字段按 0 处理
func versionLess(a, b string) bool {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < 4; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			return va < vb
		}
	}
	return false
}

func parseVersion(v string) []int {
	// 去掉非数字后缀（"2.4.57 (Ubuntu)" → "2.4.57"）
	if idx := strings.IndexAny(v, " (/+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

// logFingerprint 输出指纹日志（供各 L7 攻击启动时调用）
func logFingerprint(fp *L7Fingerprint) {
	if fp == nil {
		return
	}
	h2 := "HTTP/1.1"
	if fp.HTTP2 {
		h2 = "HTTP/2"
	} else if fp.HTTP2C {
		h2 = "HTTP/2 (h2c)"
	}
	line := fmt.Sprintf("[l7] fingerprint %s: server=%q x-powered-by=%q proto=%s",
		fp.Target, fp.ServerHeader, fp.XPoweredBy, h2)
	if fp.TLSIssuer != "" {
		line += " tls=" + fp.TLSIssuer
	}
	if fp.Vulnerable {
		line += " ⚠ VULNERABLE to CVE-2023-44487"
	} else {
		line += " (patched/unknown)"
	}
	log.Printf("%s", line)
	for _, n := range fp.Notes {
		log.Printf("[l7]   - %s", n)
	}
}
