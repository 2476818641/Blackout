//go:build linux || darwin

package controller

import (
	"os"
	"syscall"
)

// controllerExecSelf Linux 用 syscall.Exec 原子替换进程镜像
func controllerExecSelf(exe string) error {
	return syscall.Exec(exe, append([]string{exe}, os.Args[1:]...), os.Environ())
}
