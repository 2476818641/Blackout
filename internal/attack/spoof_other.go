//go:build !linux && !darwin

package attack

import (
	"net"
	"time"
)

func SupportsSpoofing() bool {
	return false
}

// outboundIPv4 非 raw socket 平台 stub：返回全零（tcp_syn 回退 Dial 模式）
func outboundIPv4() [4]byte {
	return [4]byte{}
}

// runRawSYNFlood 非 raw socket 平台 stub（不会被执行：SupportsSpoofing()=false）
func runRawSYNFlood(s *AttackSession, targets []string, threads int, dur time.Duration, srcIP [4]byte) {}

type SpoofConn struct{}

func NewSpoofConn(dstIP string, dstPort int) (*SpoofConn, error) {
	return nil, nil
}

func (c *SpoofConn) Send(srcIP string, dstIP string, dstPort int, payload []byte) error {
	return nil
}

func (c *SpoofConn) SendSYN(srcIP, dstIP string, dstPort, srcPort int) error {
	return nil
}

func (c *SpoofConn) SendSYNRaw(src [4]byte, dstIP string, dstPort, srcPort int) error {
	return nil
}

func (c *SpoofConn) Close() error {
	return nil
}

func SendSpoofedSYN(srcIP string, dstIP string, dstPort int, srcPort int) error {
	return nil
}

func SendSpoofedSYNRaw(src [4]byte, dstIP string, dstPort int, srcPort int) error {
	return nil
}

func tcpChecksumInternal(src, dst net.IP, tcpHdr, payload []byte) uint16 {
	return 0
}

func checksumInternal(data []byte) uint16 {
	return 0
}

func udpChecksumInternal(src, dst net.IP, udpHdr, payload []byte) uint16 {
	return 0
}
