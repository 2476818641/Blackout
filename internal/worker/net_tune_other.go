//go:build !linux

package worker

// ApplyNetTuning 非 Linux 平台 stub（Windows 无 txqueuelen 概念）
func ApplyNetTuning() {}
