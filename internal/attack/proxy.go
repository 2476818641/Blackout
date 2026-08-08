package attack

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	proxies             []string
	proxyLock           sync.RWMutex
	sharedHTTPClient    *http.Client
	sharedHTTPClientMu  sync.Once
)

func LoadProxies(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()

	var loaded []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		loaded = append(loaded, line)
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
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		loaded = append(loaded, line)
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
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout: 5 * time.Second,
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
				Proxy:           http.ProxyURL(u),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout: 5 * time.Second,
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
				Dial:            dialer.Dial,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout: 5 * time.Second,
			},
		}
	default:
		return newHTTPClient()
	}
}
