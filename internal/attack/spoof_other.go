//go:build !linux && !darwin

package attack

import "net"

func SupportsSpoofing() bool {
	return false
}

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
