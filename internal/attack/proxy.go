package attack

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

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
				IdleConnTimeout:     5 * time.Second,
			},
		}
	})
	return sharedHTTPClient
}

func newProxyHTTPClient() *http.Client {
	proxyLock.RLock()
	defer proxyLock.RUnlock()

	if len(proxies) == 0 {
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     5 * time.Second,
			},
		}
	}

	// rand.Intn 顶层函数是并发安全的(内部加锁)，
	// 替代原先共享的非并发安全 *rand.Rand，消除数据竞争。
	proxyStr := proxies[rand.Intn(len(proxies))]
	return buildHTTPClientFromProxy(proxyStr)
}

func buildHTTPClientFromProxy(proxyStr string) *http.Client {
	u, err := url.Parse(proxyStr)
	if err != nil {
		return newHTTPClient()
	}

	switch u.Scheme {
	case "http", "https":
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(u),
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     5 * time.Second,
			},
		}
	case "socks5":
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{
				User:     u.User.Username(),
				Password: password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return newHTTPClient()
		}
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Dial:                dialer.Dial,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     5 * time.Second,
			},
		}
	default:
		return newHTTPClient()
	}
}
