//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach 让子进程脱离当前会话/终端，SSH 断开后继续运行（等价于 setsid + nohup）
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
