//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// detach 让子进程脱离控制台：DETACHED_PROCESS 创建独立进程，
// CREATE_NO_WINDOW 禁止弹出新控制台窗口
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x08000000, // DETACHED_PROCESS | CREATE_NO_WINDOW
	}
}
