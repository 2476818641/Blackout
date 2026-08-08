package attack

type FastRNG struct {
	state uint64
}

func NewFastRNG(seed int64) *FastRNG {
	r := &FastRNG{state: uint64(seed)}
	r.Uint64()
	return r
}

func (r *FastRNG) Uint64() uint64 {
	r.state ^= r.state << 13
	r.state ^= r.state >> 7
	r.state ^= r.state << 17
	return r.state
}

func (r *FastRNG) Uint32() uint32 {
	return uint32(r.Uint64())
}

func (r *FastRNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.Uint64() % uint64(n))
}

func (r *FastRNG) Read(p []byte) (int, error) {
	n := len(p)
	pos := 0
	for pos < n {
		v := r.Uint64()
		for i := 0; i < 8 && pos < n; i++ {
			p[pos] = byte(v)
			v >>= 8
			pos++
		}
	}
	return n, nil
}

func (r *FastRNG) RandomPublicIP() [4]byte {
	for {
		ip := r.Uint32()
		b1 := byte(ip >> 24)
		b2 := byte(ip >> 16)
		b3 := byte(ip >> 8)
		b4 := byte(ip)
		if b1 == 0 || b1 == 10 || b1 == 127 || b1 >= 224 {
			continue
		}
		if b1 == 100 && b2 >= 64 && b2 <= 127 {
			continue
		}
		if b1 == 169 && b2 == 254 {
			continue
		}
		if b1 == 172 && b2 >= 16 && b2 <= 31 {
			continue
		}
		if b1 == 192 && b2 == 168 {
			continue
		}
		return [4]byte{b1, b2, b3, b4}
	}
}

func (r *FastRNG) RandomPort() int {
	return r.Intn(65535-1024) + 1024
}
