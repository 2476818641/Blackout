package worker

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func detectBandwidthMbps() int {
	if runtime.GOOS != "linux" {
		return 0
	}

	interfaces := []string{"eth0", "ens3", "ens4", "ens5", "enp0s3", "enp0s8", "eth1", "bond0"}
	for _, iface := range interfaces {
		data, err := os.ReadFile("/sys/class/net/" + iface + "/speed")
		if err != nil {
			continue
		}
		speed, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || speed <= 0 {
			continue
		}
		return speed
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		data, err := os.ReadFile("/sys/class/net/" + name + "/speed")
		if err != nil {
			continue
		}
		speed, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || speed <= 0 {
			continue
		}
		return speed
	}
	return 0
}

func formatBps(bps int64) string {
	if bps >= 1000000000 {
		return fmt.Sprintf("%.1f Gbps", float64(bps)/125000000)
	}
	if bps >= 1000000 {
		return fmt.Sprintf("%.1f Mbps", float64(bps)/125000)
	}
	return fmt.Sprintf("%d bps", bps)
}
