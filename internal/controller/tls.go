package controller

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
)

const (
	CertFile = "data/cert/server.crt"
	KeyFile  = "data/cert/server.key"
)

// certCache 磁盘证书缓存：GetCertificate 每次握手时读取，
// ReloadTLS 清空缓存后下次握手重新加载（证书热更新）。
var certCache atomic.Value // *tls.Certificate

// loadCert 加载证书（带缓存）。证书过期/损坏时返回错误 → 该次握手失败，
// 不影响已建立的连接；acme.sh 更新流程是"先写文件后发 HUP"，加载到的
// 必然是完整的新证书。
func loadCert() (*tls.Certificate, error) {
	if c, ok := certCache.Load().(*tls.Certificate); ok {
		return c, nil
	}
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return nil, err
	}
	certCache.Store(&cert)
	return &cert, nil
}

// ReloadTLS 清除证书缓存：SIGHUP（acme.sh reloadcmd / systemctl reload）时
// 调用，下一个 TLS 握手自动加载磁盘上的新证书。
func ReloadTLS() {
	certCache.Store((*tls.Certificate)(nil))
	log.Printf("✅ TLS certificate cache cleared, will reload on next handshake")
}

// LoadTLSConfig 尝试加载 data/cert/ 下的 TLS 证书
// 返回 nil 表示无证书（使用明文），返回 *tls.Config 表示启用 TLS。
// 证书通过 GetCertificate 动态加载（不持有静态副本），支持热更新。
func LoadTLSConfig() *tls.Config {
	certDir := "data/cert"
	certFile := CertFile
	keyFile := KeyFile

	// 确保 cert 目录存在
	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Printf("[!] Failed to create cert directory: %v", err)
		return nil
	}

	// 检查证书和密钥是否都存在
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if certErr != nil || keyErr != nil {
		log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Printf("⚠️  WARNING: TLS certificates not found")
		log.Printf("   Expected files:")
		log.Printf("     - %s", certFile)
		log.Printf("     - %s", keyFile)
		log.Printf("   Running in INSECURE mode (no TLS)")
		log.Printf("   ")
		log.Printf("   Generate certificates with:")
		log.Printf("     openssl req -x509 -newkey rsa:4096 -keyout %s -out %s -days 365 -nodes", keyFile, certFile)
		log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		return nil
	}

	// 首次加载校验证书可用（动态加载 + 缓存，见 loadCert）
	if _, err := loadCert(); err != nil {
		log.Printf("[!] Failed to load TLS certificate: %v", err)
		log.Printf("   Running in INSECURE mode")
		return nil
	}

	log.Printf("✅ TLS enabled: %s, %s (hot-reload via SIGHUP)", certFile, keyFile)
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return loadCert()
		},
		MinVersion: tls.VersionTLS12,
	}
}

// NewTLSCredentials 创建 gRPC TLS credentials
func NewTLSCredentials(config *tls.Config) credentials.TransportCredentials {
	return credentials.NewTLS(config)
}

// serveAutoTLS 在同一端口上同时支持 TLS 与明文 HTTP：
// 通过首字节嗅探区分协议，明文请求返回 301 重定向到 https://，
// 避免 "client sent an HTTP request to an HTTPS server" 日志刷屏
// （该错误此前对每个 http:// 访问与扫描器探测各打印一条）。
func serveAutoTLS(addr string, tlsConfig *tls.Config, handler http.Handler) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
		// 过滤无害的握手/连接噪音日志：TLS handshake error、HTTP/2 GOAWAY、
		// 扫描器 EOF 等。真正需要关注的错误仍会输出到 stderr。
		ErrorLog: log.New(noiseFilterWriter{}, "", 0),
	}

	err = srv.Serve(&autoTLSListener{Listener: lis, tlsConfig: tlsConfig})
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// autoTLSListener 在 Accept 时 peek 首字节：0x16 = TLS ClientHello → TLS 连接；
// 其余（'G'/'P'/'O' 等明文 HTTP 方法）→ 明文连接，由 handler 重定向到 https。
type autoTLSListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func (l *autoTLSListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 1)
		raw.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := raw.Read(buf)
		if err != nil || n == 0 {
			// 连接建立后无数据（扫描器/健康检查）：直接关闭，不产生任何日志
			raw.Close()
			continue
		}
		raw.SetReadDeadline(time.Time{})
		prefixed := &prefixedConn{Conn: raw, prefix: buf}
		if buf[0] == 0x16 {
			return tls.Server(prefixed, l.tlsConfig), nil
		}
		return prefixed, nil
	}
}

// prefixedConn 保存 Accept 时已读出的首字节，交给 http.Server 消费
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// noiseFilterWriter 过滤 http.Server 的噪音日志，其余透传 stderr
type noiseFilterWriter struct{}

func (noiseFilterWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) ||
		bytes.Contains(p, []byte("received GOAWAY")) ||
		bytes.Contains(p, []byte("tls: first record does not look like a TLS handshake")) {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}
