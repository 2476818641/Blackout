//go:build linux

package worker

import (
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

// ApplyNetTuning 洪水场景网卡调优（需 root，非 root 静默跳过）：
//   - txqueuelen 1000 → 10000：默认发送队列在内网高 PPS（2ms RTT 下
//     每线程数千包/s、多线程并发）时很容易溢出丢包，PPS 上不去；
//     调深队列让内核来得及排空，丢包显著减少。
//   - 网卡 ring buffer rx/tx 4096：洪水时环形缓冲区满会丢包。
//
// 只调整物理网卡（en*/eth*/bond*/team* 开头且处于 UP），跳过
// lo/docker/veth/br- 等虚拟接口。所有失败仅记日志不阻塞启动
// （无 ethtool、无权限、容器内等环境降级为不调优）。
func ApplyNetTuning() {
	if os.Geteuid() != 0 {
		log.Printf("[net-tune] not root, skipping NIC tuning (txqueuelen stays default)")
		return
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[net-tune] list interfaces failed: %v", err)
		return
	}
	tuned := 0
	for _, iface := range ifaces {
		if !isPhysicalIface(iface.Name) {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// 发送队列深度
		if out, err := exec.Command("ip", "link", "set", iface.Name, "txqueuelen", "10000").CombinedOutput(); err != nil {
			log.Printf("[net-tune] %s txqueuelen failed: %v (%s)", iface.Name, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[net-tune] %s txqueuelen -> 10000", iface.Name)
			tuned++
		}
		// 网卡环形缓冲区（ethtool 缺失时跳过）
		if out, err := exec.Command("ethtool", "-G", iface.Name, "rx", "4096", "tx", "4096").CombinedOutput(); err != nil {
			log.Printf("[net-tune] %s ring buffer: %v (%s)", iface.Name, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[net-tune] %s ring rx/tx -> 4096", iface.Name)
		}
	}
	if tuned > 0 {
		log.Printf("[net-tune] tuned %d NIC(s) for high-PPS flooding", tuned)
	}
}

// isPhysicalIface 判断是否为物理网卡（按常见命名前缀；虚拟接口
// lo/docker*/veth*/br-*/virbr*/tun*/tap*/wg* 一律跳过）。
func isPhysicalIface(name string) bool {
	for _, prefix := range []string{"lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "kube", "cni", "flannel"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	// 物理网卡常见前缀：en(ens/enp/enx/eno)、eth、bond、team
	for _, prefix := range []string{"en", "eth", "bond", "team"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
