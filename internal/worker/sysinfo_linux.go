//go:build linux

package worker

import (
	"os"
	"strconv"
	"strings"
)

type sysStats struct {
	CPUPercent int32
	MemoryMB   int64
}

var prevIdle, prevTotal uint64

func collectSystemStats() sysStats {
	var s sysStats
	s.CPUPercent = cpuPercent()
	s.MemoryMB = memoryMB()
	return s
}

func cpuPercent() int32 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0
		}
		var idle, total uint64
		for i := 1; i < len(fields); i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			total += v
			if i == 4 {
				idle = v
			} else if i == 5 {
				idle += v // iowait 属于空闲等待（磁盘/网络 IO），计入 idle
				// 避免 IO 等待被误算为繁忙导致 CPU 读数偏高
			}
		}
		if prevTotal == 0 {
			prevIdle, prevTotal = idle, total
			return 0
		}
		diffIdle := idle - prevIdle
		diffTotal := total - prevTotal
		prevIdle, prevTotal = idle, total
		if diffTotal == 0 {
			return 0
		}
		pct := int32(100 - (diffIdle*100)/diffTotal)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		return pct
	}
	return 0
}

func memoryMB() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}
