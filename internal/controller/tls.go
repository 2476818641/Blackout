package controller

import (
	"crypto/tls"
	"log"
	"os"

	"google.golang.org/grpc/credentials"
)

const (
	CertFile = "data/cert/server.crt"
	KeyFile  = "data/cert/server.key"
)

// LoadTLSConfig 尝试加载 data/cert/ 下的 TLS 证书
// 返回 nil 表示无证书（使用明文），返回 *tls.Config 表示启用 TLS
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

	// 加载证书
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("[!] Failed to load TLS certificate: %v", err)
		log.Printf("   Running in INSECURE mode")
		return nil
	}

	log.Printf("✅ TLS enabled: %s, %s", certFile, keyFile)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// NewTLSCredentials 创建 gRPC TLS credentials
func NewTLSCredentials(config *tls.Config) credentials.TransportCredentials {
	return credentials.NewTLS(config)
}
