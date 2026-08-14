package controller

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// InstallAutoStart 把 Controller 安装为开机自启服务：
//   - Linux → systemd unit（blackout-controller.service），日志进 systemd journal
//   - Windows → schtasks 计划任务（无持久日志，前台运行可见 stdout）
//
// 返回服务名（供调用方打印管理命令）。
// 注意：Controller 的 data/ 目录是相对路径（cwd），WorkingDirectory 必须与
// 二进制同目录；安装后若移动了二进制位置，需手动更新 unit 内的
// ExecStart / WorkingDirectory 并 daemon-reload。
func InstallAutoStart(grpcAddr, httpAddr string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	dir := filepath.Dir(exe)

	switch runtime.GOOS {
	case "linux":
		service := fmt.Sprintf(`[Unit]
Description=Blackout Controller
After=network.target

[Service]
Type=simple
ExecStart=%s -grpc %s -http %s
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
User=root
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, exe, grpcAddr, httpAddr, dir)

		const unitPath = "/etc/systemd/system/blackout-controller.service"
		if err := os.WriteFile(unitPath, []byte(service), 0600); err != nil {
			return "", fmt.Errorf("write service file: %v (are you root?)", err)
		}
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "blackout-controller").Run()
		// 安装后立即启动：否则 -install 分支退出后服务处于 enabled 但 inactive
		if out, err := exec.Command("systemctl", "start", "blackout-controller").CombinedOutput(); err != nil {
			log.Printf("[install] systemctl start failed: %v (%s)", err, string(out))
		}
		return "blackout-controller", nil

	case "windows":
		taskName := "BlackoutController"
		// schtasks 任务默认工作目录是 System32，而 Controller 的 data/ 是
		// 相对路径（cwd）——不切目录会让 token/证书写到 System32 且重启后
		// 找不到。用 cmd /c "cd /d <exe目录> && <exe> ..." 固定工作目录。
		cmd := fmt.Sprintf(
			`schtasks /create /tn "%s" /tr "cmd /c cd /d \"%s\" && \"%s\" -grpc %s -http %s" /sc onstart /ru SYSTEM /f`,
			taskName, dir, exe, grpcAddr, httpAddr,
		)
		output, err := exec.Command("cmd", "/c", cmd).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("schtasks failed: %s: %w", string(output), err)
		}
		// 安装后立即运行，节点立刻可用（开机自启依然生效）
		if out, err := exec.Command("cmd", "/c", `schtasks /run /tn "`+taskName+`"`).CombinedOutput(); err != nil {
			log.Printf("[install] schtasks /run failed: %v (%s)", err, string(out))
		}
		return taskName, nil

	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
