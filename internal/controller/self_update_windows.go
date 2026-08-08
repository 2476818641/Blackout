//go:build windows

package controller

// controllerExecSelf Windows 无 syscall.Exec，返回错误走 spawn 路径
func controllerExecSelf(exe string) error {
	return errExecNotSupported
}

type errExecNotSupportedT struct{}

func (errExecNotSupportedT) Error() string { return "syscall.Exec not supported on windows" }

var errExecNotSupported = errExecNotSupportedT{}
