//go:build linux || darwin

package worker

import (
	"encoding/json"
	"io"
	"syscall"
)

// execSyscallExec Linux 用 syscall.Exec 原子替换进程镜像
func execSyscallExec(exe string, args []string, env []string) error {
	return syscall.Exec(exe, append([]string{exe}, args...), env)
}

// jsonNewDecoder 解码 JSON（避免直接引用 encoding/json 到 update.go 的模板）
func jsonNewDecoder(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

// FinishWindowsUpdate 非 Windows 平台无换身流程，直接返回 false
func FinishWindowsUpdate() bool { return false }

// CleanupUpdateTemp 非 Windows 平台无 .update 临时文件
func CleanupUpdateTemp() {}
