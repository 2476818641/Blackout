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
