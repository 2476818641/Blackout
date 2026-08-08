package attack

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type Socks5UDPConn struct {
	proxyAddr string
	relayAddr *net.UDPAddr
	tcpConn   net.Conn
	udpConn   *net.UDPConn
}

func NewSocks5UDPConn(proxyAddr string, timeout time.Duration) (*Socks5UDPConn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial: %w", err)
	}

	// dialer.Timeout 只覆盖 Dial 阶段。给整个握手（两次 Read）设置 deadline，
	// 否则代理接受 TCP 却不回应握手时 conn.Read 会永久阻塞，导致 goroutine + fd 泄漏。
	conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth read: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", authResp)
	}

	udpAssoc := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(udpAssoc); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 udp assoc: %w", err)
	}

	// 先精确读 4 字节固定头 VER/REP/RSV/ATYP，再按 ATYP 读变长的 BND.ADDR+PORT，
	// 避免单次 Read 短读把合法响应误判为失败。
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 udp assoc read: %w", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 udp assoc failed: %x", head)
	}

	var relayIP net.IP
	var relayPort uint16
	switch head[3] {
	case 0x01: // IPv4：ADDR(4)+PORT(2)
		body := make([]byte, 6)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 udp assoc ipv4 read: %w", err)
		}
		relayIP = net.IP(append([]byte(nil), body[0:4]...))
		relayPort = binary.BigEndian.Uint16(body[4:6])
	case 0x04: // IPv6：ADDR(16)+PORT(2)
		body := make([]byte, 18)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 udp assoc ipv6 read: %w", err)
		}
		relayIP = net.IP(append([]byte(nil), body[0:16]...))
		relayPort = binary.BigEndian.Uint16(body[16:18])
	case 0x03: // 域名：LEN(1)+域名+PORT(2)
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 udp assoc domain len read: %w", err)
		}
		body := make([]byte, int(lenByte[0])+2)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 udp assoc domain read: %w", err)
		}
		// 域名形式的中继地址无法直接当 IP 用，回退逻辑（下方）会用 proxyAddr 解析。
		relayPort = binary.BigEndian.Uint16(body[len(body)-2:])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 udp assoc unsupported ATYP: %d", head[3])
	}

	// 很多代理返回 BND.ADDR=0.0.0.0（语义为“用你 TCP 连接的那个 IP”）。
	// 直接拿全零地址发 UDP 会失败，回退到 proxyAddr 解析出的 IP + 返回的端口。
	if relayIP == nil || relayIP.IsUnspecified() {
		host, _, splitErr := net.SplitHostPort(proxyAddr)
		if splitErr == nil {
			if resolved := net.ParseIP(host); resolved != nil {
				relayIP = resolved
			} else if ipAddr, resolveErr := net.ResolveIPAddr("ip", host); resolveErr == nil {
				relayIP = ipAddr.IP
			}
		}
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: int(relayPort)}

	// 握手完成，清除 TCP deadline，避免影响后续 UDP assoc 连接的存活维持。
	conn.SetDeadline(time.Time{})

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 udp listen: %w", err)
	}

	return &Socks5UDPConn{
		proxyAddr: proxyAddr,
		relayAddr: relayAddr,
		tcpConn:   conn,
		udpConn:   udpConn,
	}, nil
}

func (c *Socks5UDPConn) WriteToUDP(payload []byte, dst *net.UDPAddr) (int, error) {
	// SOCKS5 UDP 请求头：RSV(2)+FRAG(1)+ATYP(1)+ADDR+PORT(2)。
	if ip4 := dst.IP.To4(); ip4 != nil {
		pkt := make([]byte, 10+len(payload))
		pkt[0], pkt[1], pkt[2] = 0x00, 0x00, 0x00
		pkt[3] = 0x01
		copy(pkt[4:8], ip4)
		binary.BigEndian.PutUint16(pkt[8:10], uint16(dst.Port))
		copy(pkt[10:], payload)
		return c.udpConn.WriteToUDP(pkt, c.relayAddr)
	}
	// IPv6：ATYP=0x04，地址 16 字节，头长 22。
	ip6 := dst.IP.To16()
	if ip6 == nil {
		return 0, fmt.Errorf("socks5 udp invalid dst ip: %v", dst.IP)
	}
	pkt := make([]byte, 22+len(payload))
	pkt[0], pkt[1], pkt[2] = 0x00, 0x00, 0x00
	pkt[3] = 0x04
	copy(pkt[4:20], ip6)
	binary.BigEndian.PutUint16(pkt[20:22], uint16(dst.Port))
	copy(pkt[22:], payload)
	return c.udpConn.WriteToUDP(pkt, c.relayAddr)
}

func (c *Socks5UDPConn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 4 {
		return 0, addr, fmt.Errorf("socks5 udp response too short: %d", n)
	}
	// 按 ATYP 计算真实头长度后再剥离，域名/IPv6 头长不同于 IPv4 的 10 字节。
	var hdr int
	switch buf[3] {
	case 0x01: // IPv4：RSV(2)+FRAG(1)+ATYP(1)+ADDR(4)+PORT(2)
		hdr = 10
	case 0x04: // IPv6：ADDR(16)
		hdr = 22
	case 0x03: // 域名：ADDR = LEN(1)+域名
		if n < 5 {
			return 0, addr, fmt.Errorf("socks5 udp domain response too short: %d", n)
		}
		hdr = 4 + 1 + int(buf[4]) + 2
	default:
		return 0, addr, fmt.Errorf("socks5 udp response unknown ATYP: %d", buf[3])
	}
	if n < hdr {
		return 0, addr, fmt.Errorf("socks5 udp response too short for header %d: %d", hdr, n)
	}
	copy(buf, buf[hdr:n])
	return n - hdr, addr, nil
}

func (c *Socks5UDPConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *Socks5UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

func (c *Socks5UDPConn) Close() error {
	c.tcpConn.Close()
	return c.udpConn.Close()
}
