//go:build windows

package worker

import (
	"syscall"
	"time"
	"unsafe"
)

type sysStats struct {
	CPUPercent int32
	MemoryMB   int64
}

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	prevIdle, prevTotal      uint64
	prevSample               time.Time
)

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type processMemoryCounters struct {
	Size                    uint32
	PageFaultCount          uint32
	PeakWorkingSetSize      uint64
	WorkingSetSize          uint64
	QuotaPeakPagedPoolUsage uint64
	QuotaPagedPoolUsage     uint64
	QuotaPeakNonPagedPoolUsage uint64
	QuotaNonPagedPoolUsage     uint64
	PagefileUsage           uint64
	PeakPagefileUsage       uint64
}

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
)

func collectSystemStats() sysStats {
	var s sysStats
	s.CPUPercent = cpuPercent()
	s.MemoryMB = memoryMB()
	return s
}

// cpuPercent 使用 GetSystemTimes 统计整机（所有核聚合）CPU 使用率。
// 与 Linux 的 /proc/stat 聚合行（cpu ）口径一致：天然是 0-100 的多核总体利用率，
// 而不是单核或单进程利用率。
func cpuPercent() int32 {
	var idle, kernel, user filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return 0
	}

	idl := uint64(idle.HighDateTime)<<32 | uint64(idle.LowDateTime)
	krn := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	usr := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	total := krn + usr // kernel 时间已包含 idle

	now := time.Now()
	if prevSample.IsZero() {
		prevIdle, prevTotal, prevSample = idl, total, now
		return 0
	}

	diffIdle := idl - prevIdle
	diffTotal := total - prevTotal
	prevIdle, prevTotal, prevSample = idl, total, now

	if diffTotal == 0 {
		return 0
	}

	// 整机使用率 = 1 - idleDelta/totalDelta
	pct := int32(100 - (diffIdle*100)/diffTotal)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

func memoryMB() int64 {
	h, err := syscall.OpenProcess(processQueryInformation|processVMRead, false, uint32(syscall.Getpid()))
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(h)

	var pmc processMemoryCounters
	pmc.Size = uint32(unsafe.Sizeof(pmc))
	ret, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.Size))
	if ret == 0 {
		return 0
	}
	return int64(pmc.WorkingSetSize / 1024 / 1024)
}
