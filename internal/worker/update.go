package worker

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// 云更新：Controller 通过 /api/deploy/update 配置目标版本+下载 URL，
// Worker 定期轮询 /api/deploy/version 对比本地版本，发现新版本时
// 自动下载 → 校验 → 原子替换 → 重启自身，无需逐台登录服务器。

const (
	updateVersionFile = "data/worker_version.txt"
	updateCheckEvery  = 60 * time.Second
	updateMinSize     = 1 << 20 // 1MB：小于此视为下载失败
)

// computeSelfVersion 返回当前运行二进制的版本标识（自身 SHA256 前 16 位）。
// Controller 下发目标版本后，Worker 用此值判断是否需要更新。
func computeSelfVersion() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	f, err := os.Open(exe)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// loadLocalVersion 读取本地已记录的版本（更新成功后写入）。
// 首次运行或文件不存在返回空串（视为"从未更新过"）。
func loadLocalVersion() string {
	data, err := os.ReadFile(updateVersionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveLocalVersion 更新成功后记录新版本，防止重启后重复更新。
func saveLocalVersion(version string) error {
	os.MkdirAll("data", 0755)
	return os.WriteFile(updateVersionFile, []byte(version), 0644)
}

// updateClient 允许自签证书（Controller 启用 TLS 时用自签证书）
var updateClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// fetchTargetVersion 从 Controller 拉取目标版本与下载 URL。
// 携带 worker_id：Controller 未配置自定义 URL 时，按 Worker 平台
// （Linux/Windows）返回对应的 GitHub Release 二进制地址。
func (w *Worker) fetchTargetVersion() (version, url string, err error) {
	apiURL := w.ctrlBaseURL() + "/api/deploy/version"
	if w.assignedID != "" {
		apiURL += "?worker_id=" + w.assignedID
	}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+w.authToken)

	resp, err := updateClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var v struct {
		Version string `json:"version"`
		URL     string `json:"url"`
	}
	if err := jsonNewDecoder(resp.Body, &v); err != nil {
		return "", "", err
	}
	return v.Version, v.URL, nil
}

// checkUpdate 轮询 Controller 检查是否需要更新，需要时执行更新。
func (w *Worker) checkUpdate() {
	targetVersion, url, err := w.fetchTargetVersion()
	if err != nil {
		log.Printf("[update] check failed: %v", err)
		return
	}
	if targetVersion == "" || url == "" {
		return // Controller 未配置更新
	}
	// 已更新判断：优先用本地版本文件（更新成功后写入，重启后仍有效）。
	// 二进制 hash 作为兜底（全新部署的二进制 hash 恰好等于目标版本时）。
	if local := loadLocalVersion(); local != "" {
		if local == targetVersion {
			return // 已是最新（本地已记录）
		}
	} else if targetVersion == w.selfVersion {
		return // 无本地记录但二进制 hash 匹配
	}

	log.Printf("[update] new version available: %s (local %s), downloading %s", targetVersion, w.selfVersion, url)
	if err := w.applyUpdate(url, targetVersion); err != nil {
		log.Printf("[update] FAILED: %v (will retry next check)", err)
	}
}

// applyUpdate 下载新二进制 → 校验 → 替换 → 记录版本 → 重启。
// 所有步骤失败均不修改当前文件，保证可回滚。
func (w *Worker) applyUpdate(url, targetVersion string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}
	exeAbs, err := filepath.Abs(exe)
	if err != nil {
		exeAbs = exe
	}

	// 1. 下载到临时文件（与 exe 同目录，保证同文件系统可 rename）
	tmp := exeAbs + ".update"
	os.Remove(tmp)
	if err := w.downloadBinary(url, tmp); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// 2. 校验
	if err := verifyBinary(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("verify: %w", err)
	}

	// 3. 原子替换：备份旧文件 → 新文件 rename 到位
	backup := exeAbs + ".bak"
	os.Remove(backup)
	if err := os.Rename(exeAbs, backup); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.Rename(tmp, exeAbs); err != nil {
		// 替换失败：回滚备份
		os.Rename(backup, exeAbs)
		os.Remove(tmp)
		return fmt.Errorf("replace: %w", err)
	}

	// 4. 记录版本（替换成功后写，重启后不再重复更新）
	if err := saveLocalVersion(targetVersion); err != nil {
		log.Printf("[update] version file write failed (ignored): %v", err)
	}

	log.Printf("[update] binary replaced, restarting...")
	w.restartSelf(exeAbs)
	return nil
}

// downloadBinary 下载新二进制到指定路径。
func (w *Worker) downloadBinary(url, path string) error {
	resp, err := updateClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(path)
		return err
	}
	if n < updateMinSize {
		os.Remove(path)
		return fmt.Errorf("binary too small (%d bytes)", n)
	}
	return out.Sync()
}

// verifyBinary 校验下载文件是否为当前平台的可执行文件。
func verifyBinary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		if magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
			return fmt.Errorf("not an ELF binary (% X)", magic)
		}
	case "windows":
		if magic[0] != 'M' || magic[1] != 'Z' {
			return fmt.Errorf("not a PE binary (% X)", magic)
		}
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if err := os.Chmod(path, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

// restartSelf 重启自身进程：
// Linux 用 syscall.Exec 直接替换镜像（保持 PID，systemd/daemon 场景最干净）；
// Windows 无法 exec，启动新进程后退出当前进程。
func (w *Worker) restartSelf(exe string) {
	args := os.Args[1:]
	env := os.Environ()

	if runtime.GOOS != "windows" {
		if err := execSyscallExec(exe, args, env); err != nil {
			log.Printf("[update] exec failed, falling back to spawn: %v", err)
		} else {
			return
		}
	}

	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("[update] spawn failed: %v", err)
		return
	}
	log.Printf("[update] new process started (pid=%d), exiting", cmd.Process.Pid)
	os.Exit(0)
}
