//go:build windows

package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
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

// applyUpdateWindows Windows 自更新（临时副本换身流程）：
// 下载与校验已完成（applyUpdate 内），这里完成公共收尾后拉起 tmp 副本
// 执行换身，自身立即退出。运行中的 exe 被独占锁定无法 rename，
// 换身必须由新进程（临时路径）完成。
func (w *Worker) applyUpdateWindows(exeAbs, tmp, targetVersion string) error {
	// 记录版本（换身成功后运行的就是新二进制，版本标记一致）
	if err := saveLocalVersion(targetVersion); err != nil {
		log.Printf("[update] version file write failed (ignored): %v", err)
	}

	w.preUpdateShutdown()

	cmd := exec.Command(tmp, os.Args[1:]...)
	cmd.Env = append(os.Environ(),
		"NETTOOL_UPDATE_PENDING=1",
		"NETTOOL_UPDATE_TARGET="+exeAbs)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn updater: %w", err)
	}
	log.Printf("[update] updater spawned (pid=%d) from %s, exiting", cmd.Process.Pid, tmp)
	os.Exit(0)
	return nil
}

// FinishWindowsUpdate 由带 NETTOOL_UPDATE_PENDING=1 标记的新进程
// （正在从临时路径运行）调用，在 worker 正常启动前完成换身：
//  1. 等待旧进程退出释放 exe 路径的独占锁（轮询复制，最长 60s）
//  2. 把自身（临时路径）复制到正式路径
//  3. 以清理后的环境拉起正式路径进程，自身退出
//
// 复制失败时降级为直接从临时路径运行（新版仍可用，下次更新再试）。
// 返回 true 表示消费了更新标记（调用方继续正常启动流程）。
func FinishWindowsUpdate() bool {
	if os.Getenv("NETTOOL_UPDATE_PENDING") != "1" {
		return false
	}
	target := os.Getenv("NETTOOL_UPDATE_TARGET")
	self, err := os.Executable()
	if err != nil || target == "" || self == "" {
		log.Printf("[update] swap aborted: missing env/self (%v)", err)
		return true
	}
	if strings.EqualFold(self, target) {
		// 已在正式路径：仅清标记，无需换身
		return true
	}

	log.Printf("[update] swapping: %s -> %s", self, target)
	deadline := time.Now().Add(60 * time.Second)
	var copyErr error
	for time.Now().Before(deadline) {
		if copyErr = copyFile(self, target); copyErr == nil {
			break
		}
		// 目标文件仍被旧进程锁定（Access is denied）：等待后重试
		time.Sleep(500 * time.Millisecond)
	}
	if copyErr != nil {
		log.Printf("[update] swap FAILED after 60s: %v (continuing from temp path)", copyErr)
		return true
	}

	// 拉起正式路径进程（清理更新标记，避免递归换身），自身退出
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "NETTOOL_UPDATE_") {
			continue
		}
		env = append(env, e)
	}
	cmd := exec.Command(target, os.Args[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("[update] spawn target failed: %v (continuing from temp path)", err)
		return true
	}
	log.Printf("[update] target process started (pid=%d), updater exiting", cmd.Process.Pid)
	os.Exit(0)
	return true
}

// CleanupUpdateTemp 清理 Windows 换身流程遗留的 .update 临时文件
// （正式路径进程启动时调用）。若当前进程自身正从 .update 路径运行
// （换身失败降级），跳过自删。
func CleanupUpdateTemp() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if strings.HasSuffix(strings.ToLower(exe), ".update") {
		return
	}
	os.Remove(exe + ".update")
}

// copyFile 复制文件（用于运行中二进制→正式路径的换身；源文件可读不受锁影响）
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
