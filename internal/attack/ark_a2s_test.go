package attack

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestBuildA2SQuery 验证查询字节格式：
//   - PLAYER 无 challenge: FF FF FF FF 55 (5B)
//   - RULES 带 challenge: FF FF FF FF 56 + 4B LE challenge (9B)
func TestBuildA2SQuery(t *testing.T) {
	// PLAYER 裸查
	q := buildA2SQuery(a2sQueryPlayer, 0)
	if len(q) != 5 {
		t.Fatalf("player bare query len = %d, want 5", len(q))
	}
	want := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x55}
	if !bytes.Equal(q, want) {
		t.Fatalf("player bare query = %X, want %X", q, want)
	}

	// RULES 裸查
	q = buildA2SQuery(a2sQueryRules, 0)
	if len(q) != 5 || q[4] != 0x56 {
		t.Fatalf("rules bare query = %X, want 0x56 header (5B)", q)
	}

	// PLAYER 带 challenge：0x01020304 必须按小端追加
	q = buildA2SQuery(a2sQueryPlayer, 0x01020304)
	if len(q) != 9 {
		t.Fatalf("player challenge query len = %d, want 9", len(q))
	}
	if !bytes.Equal(q[:5], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x55}) {
		t.Fatalf("player challenge header = %X", q[:5])
	}
	if got := binary.LittleEndian.Uint32(q[5:9]); got != 0x01020304 {
		t.Fatalf("challenge bytes = %08X, want 04030201 (LE of 0x01020304)", got)
	}
}

// mockA2SServer 模拟 A2S 服务器行为：
//   mode "challenge" → 对裸查返回 0x41+challenge；带正确 challenge 返回 0x44 数据
//   mode "direct"    → 对裸查直接返回 0x44 数据（免 challenge）
//   mode "silent"    → 不响应
func mockA2SServer(t *testing.T, mode string, challenge uint32) (addr string, closeFn func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		buf := make([]byte, 64)
		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// 检查是否是带 challenge 的查询（len 13）
			hasChallenge := n == 13 && binary.LittleEndian.Uint32(buf[9:13]) == challenge
			var resp []byte
			switch mode {
			case "challenge":
				if hasChallenge {
					resp = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}
				} else {
					resp = make([]byte, 9)
					copy(resp, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x41})
					binary.LittleEndian.PutUint32(resp[5:9], challenge)
				}
			case "direct":
				resp = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
			default: // silent
				continue
			}
			conn.WriteToUDP(resp, remote)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// TestProbeA2SQueryChallenge 需 challenge 服务器：裸查返回 0x41 + challenge
func TestProbeA2SQueryChallenge(t *testing.T) {
	addr, closeFn := mockA2SServer(t, "challenge", 0x12345678)
	defer closeFn()
	host, port, _ := net.SplitHostPort(addr)

	r := probeA2SQuery(host, atoi(port), a2sQueryPlayer, 2*time.Second)
	if !r.ok {
		t.Fatalf("probe failed: %+v", r)
	}
	if !r.needsChallenge {
		t.Fatalf("needsChallenge = false, want true")
	}
	if r.challenge != 0x12345678 {
		t.Fatalf("challenge = %08X, want 12345678", r.challenge)
	}
}

// TestProbeA2SQueryDirect 免 challenge 服务器：裸查直接返回数据
func TestProbeA2SQueryDirect(t *testing.T) {
	addr, closeFn := mockA2SServer(t, "direct", 0)
	defer closeFn()
	host, port, _ := net.SplitHostPort(addr)

	r := probeA2SQuery(host, atoi(port), a2sQueryPlayer, 2*time.Second)
	if !r.ok {
		t.Fatalf("probe failed: %+v", r)
	}
	if r.needsChallenge {
		t.Fatalf("needsChallenge = true, want false (direct server)")
	}
	if r.responseSize != 11 {
		t.Fatalf("responseSize = %d, want 11", r.responseSize)
	}
}

// TestProbeA2SQuerySilent 无响应服务器：ok=false
func TestProbeA2SQuerySilent(t *testing.T) {
	addr, closeFn := mockA2SServer(t, "silent", 0)
	defer closeFn()
	host, port, _ := net.SplitHostPort(addr)

	r := probeA2SQuery(host, atoi(port), a2sQueryPlayer, 300*time.Millisecond)
	if r.ok {
		t.Fatalf("probe succeeded on silent server: %+v", r)
	}
}

// TestLearnA2SChallenge 直连学习：challenge 服务器返回 challenge，direct 返回 0
func TestLearnA2SChallenge(t *testing.T) {
	addr, closeFn := mockA2SServer(t, "challenge", 0xABCDEF01)
	defer closeFn()
	uaddr, _ := net.ResolveUDPAddr("udp", addr)

	if c := learnA2SChallenge(uaddr, 2*time.Second); c != 0xABCDEF01 {
		t.Fatalf("challenge = %08X, want ABCDEF01", c)
	}

	addr2, closeFn2 := mockA2SServer(t, "direct", 0)
	defer closeFn2()
	uaddr2, _ := net.ResolveUDPAddr("udp", addr2)
	if c := learnA2SChallenge(uaddr2, 2*time.Second); c != 0 {
		t.Fatalf("direct server challenge = %08X, want 0", c)
	}
}

func atoi(s string) (n int) {
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
