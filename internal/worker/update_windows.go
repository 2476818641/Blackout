//go:build windows

package worker

import (
	"encoding/json"
	"io"
	"os/exec"
)

// execSyscallExec Windows 无 syscall.Exec，返回错误走 spawn 路径
func execSyscallExec(exe string, args []string, env []string) error {
	return &exec.Error{Name: exe, Err: errNotSupported}
}

type errNotSupportedT struct{}

func (errNotSupportedT) Error() string { return "syscall.Exec not supported on windows" }

var errNotSupported = errNotSupportedT{}

// jsonNewDecoder 解码 JSON
func jsonNewDecoder(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}
