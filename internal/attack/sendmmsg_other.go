//go:build !(linux && (amd64 || arm64))

package attack

import "net"

const maxBatchSize = 256

func sendBatchUDP(conn *net.UDPConn, pkts [][]byte) (int, int) {
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
