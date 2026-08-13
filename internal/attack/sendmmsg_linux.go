//go:build linux && (amd64 || arm64)

package attack

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const maxBatchSize = 256

// mmsgHdr 对应内核 struct mmsghdr：msghdr + msg_len(unsigned int) + 对齐填充。
// amd64/arm64 上 msghdr 为 56 字节、整体 8 字节对齐，故 Pad 为 4 字节。
type mmsgHdr struct {
	Hdr unix.Msghdr
	Len uint32
	Pad uint32
}

// sendBatchUDP 优先使用 sendmmsg 系统调用一次批量发送多个 UDP 包，
// 显著减少 syscall 次数（每批 1 次 vs 逐包 n 次），提高 PPS 上限。
// 部分成功或系统调用失败时回退到逐包发送，保证正确性。
func sendBatchUDP(conn *net.UDPConn, pkts [][]byte) (int, int) {
	if len(pkts) == 0 {
		return 0, 0
	}
	if len(pkts) > maxBatchSize {
		pkts = pkts[:maxBatchSize]
	}

	n, b, used, ok := sendmmsgBatch(conn, pkts)
	if ok {
		return n, b
	}
	if used > 0 {
		// sendmmsg 部分成功（如中途 EINTR）：剩余部分继续逐包
		sent, bytes := sendBatchUDPFallback(conn, pkts[used:])
		return n + sent, b + bytes
	}
	return sendBatchUDPFallback(conn, pkts)
}

// sendmmsgBatch 通过 raw fd 调用 sendmmsg。
// 返回 (成功数, 字节数, 实际发送数, 是否全部成功)。
func sendmmsgBatch(conn *net.UDPConn, pkts [][]byte) (int, int, int, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, 0, false
	}

	msgs := make([]mmsgHdr, len(pkts))
	iovecs := make([]unix.Iovec, len(pkts))
	for i, pkt := range pkts {
		iovecs[i].Base = &pkt[0]
		iovecs[i].SetLen(len(pkt))
		msgs[i].Hdr.Iov = &iovecs[i]
		msgs[i].Hdr.Iovlen = 1
	}

	sent := 0
	totalBytes := 0
	allOK := true

	err = raw.Write(func(fd uintptr) bool {
		n, _, errno := unix.RawSyscall6(unix.SYS_SENDMMSG, fd,
			uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
		// 注意：errno != 0 时 n 可能仍 > 0（部分成功，如 EINTR 中断一批）。
		// 此时必须保留 nSent——把 nSent 清零会让调用方整批回退重发，
		// 已发送的包重复、统计失真。
		nSent := int(n)
		for i := 0; i < nSent; i++ {
			sent++
			totalBytes += int(msgs[i].Len)
		}
		allOK = nSent == len(msgs) && errno == 0
		return true
	})

	if err != nil || !allOK {
		return sent, totalBytes, sent, false
	}
	return sent, totalBytes, sent, true
}

func sendBatchUDPFallback(conn *net.UDPConn, pkts [][]byte) (int, int) {
	sent := 0
	totalBytes := 0
	for _, pkt := range pkts {
		n, err := conn.Write(pkt)
		if err != nil {
			break
		}
		sent++
		totalBytes += n
	}
	return sent, totalBytes
}
