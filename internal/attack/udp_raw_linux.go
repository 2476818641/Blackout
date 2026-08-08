//go:build linux

package attack

import (
	"net"
	"syscall"
)

// udpConnFd 获取 UDP 连接的底层文件描述符。
func udpConnFd(conn *net.UDPConn) (int, error) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	var sysErr error
	err = sc.Control(func(s uintptr) {
		fd = int(s)
	})
	if err != nil {
		return -1, err
	}
	if sysErr != nil {
		return -1, sysErr
	}
	return fd, nil
}

// buildSockaddr 构建 syscall.SockaddrInet4。
func buildSockaddr(addr *net.UDPAddr) *syscall.SockaddrInet4 {
	ip4 := addr.IP.To4()
	sa := &syscall.SockaddrInet4{Port: addr.Port}
	copy(sa.Addr[:], ip4)
	return sa
}
