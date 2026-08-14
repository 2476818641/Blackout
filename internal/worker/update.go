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

// computeFileHash 计算文件的完整 SHA-256（hex，64 字符）
func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
// （Linux/Windows）返回对应的 GitHub Release 二进制地址，并附带该 asset
// 的 SHA-256（require_sha256=true 时 Worker 必须校验，防止供应链注入）。
func (w *Worker) fetchTargetVersion() (version, url, sha256 string, requireSHA256 bool, err error) {
	// 快照配置：此函数在独立更新 goroutine 中运行，assignedID/authToken
	// 可能被主循环（重注册/迁移）改写，先取快照避免数据竞争
	_, authToken, assignedID := w.getConfig()
	apiURL := w.ctrlBaseURL() + "/api/deploy/version"
	if assignedID != "" {
		apiURL += "?worker_id=" + assignedID
	}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", "", "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := updateClient.Do(req)
	if err != nil {
		return "", "", "", false, err
	}
	defer resp.Body.Close()

	var v struct {
		Version       string `json:"version"`
		URL           string `json:"url"`
		SHA256        string `json:"sha256"`
		RequireSHA256 bool   `json:"require_sha256"`
	}
	if err := jsonNewDecoder(resp.Body, &v); err != nil {
		return "", "", "", false, err
	}
	return v.Version, v.URL, v.SHA256, v.RequireSHA256, nil
}

// checkUpdate 轮询 Controller 检查是否需要更新，需要时执行更新。
func (w *Worker) checkUpdate() {
	targetVersion, url, sha256, requireSHA256, err := w.fetchTargetVersion()
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
	if err := w.applyUpdate(url, targetVersion, sha256, requireSHA256); err != nil {
		log.Printf("[update] FAILED: %v (will retry next check)", err)
	}
}

// applyUpdate 下载新二进制 → 校验（魔数 + SHA-256）→ 替换 → 记录版本 → 重启。
// 所有步骤失败均不修改当前文件，保证可回滚。
func (w *Worker) applyUpdate(url, targetVersion, sha256 string, requireSHA256 bool) error {
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

	// 2. 校验：魔数 + 大小
	if err := verifyBinary(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("verify: %w", err)
	}

	// 3. 供应链校验：下载产物 hash 必须与 Controller 下发的期望值一致。
	// require_sha256=true 且期望值为空 = Controller 未能获取官方 digest，
	// 拒绝更新（fail-closed），防止 ghproxy/中间人注入任意可执行文件。
	fileHash, err := computeFileHash(tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("hash: %w", err)
	}
	if requireSHA256 {
		if sha256 == "" {
			os.Remove(tmp)
			return fmt.Errorf("no SHA-256 configured by controller — update rejected (supply-chain protection)")
		}
		if !strings.EqualFold(fileHash, sha256) {
			os.Remove(tmp)
			return fmt.Errorf("SHA-256 mismatch (expected %s, got %s) — update rejected (supply-chain protection)", sha256, fileHash)
		}
		log.Printf("[update] SHA-256 verified: %s", fileHash)
	}

	// 4. 与运行中二进制完全相同（部署的产物已是最新 tag）：只记录版本，
	// 不替换不重启——避免新节点上线 10s 后无故重启一次
	if len(fileHash) >= 16 && fileHash[:16] == w.selfVersion {
		if err := saveLocalVersion(targetVersion); err != nil {
			log.Printf("[update] version file write failed (ignored): %v", err)
		}
		log.Printf("[update] binary identical to running version, marked %s (no restart)", targetVersion)
		os.Remove(tmp)
		return nil
	}

	// Windows 分支：运行中的 exe 被系统独占锁定，rename/覆盖必然失败
	// （"Access is denied"）。走"临时副本换身"流程：
	// ① 拉起 tmp 副本（带 BLACKOUT_UPDATE_PENDING 标记）→ 自身退出
	// ② tmp 副本等旧进程退出释放锁后，把自身复制到 exe 路径
	// ③ tmp 副本拉起正式路径进程并退出，正式进程启动时清理 .update 残留
	if runtime.GOOS == "windows" {
		return w.applyUpdateWindows(exeAbs, tmp, targetVersion)
	}

	// 5. 原子替换：备份旧文件 → 新文件 rename 到位
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

	// 6. 记录版本（替换成功后写，重启后不再重复更新）。
	// 必须在替换成功之后：先写版本文件会让"替换失败但版本已记录"的
	// 场景永久跳过更新——运行旧二进制且无任何告警。
	if err := saveLocalVersion(targetVersion); err != nil {
		log.Printf("[update] version file write failed (ignored): %v", err)
	}

	// 7. 重启前上报进行中任务的完成状态 + 注销旧节点条目：
	// 注销旧条目是为了防止 Controller 节点表里旧 ID（如 xxx-node1）仍在线
	// （Linux exec 保持 PID 或 Windows spawn 时旧进程尚未退出），新进程注册
	// 时被分配 node2/node3，出现"更新后两个节点"的僵尸条目。
	// 上报必须先于 stopAllAttacks/restartSelf 完成：stopAllAttacks 会关闭
	// 攻击会话（流式完成推送可能因连接即将关闭而失败），而 restartSelf 用
	// exec 立即替换进程镜像会杀掉一切 in-flight HTTP 请求——只有这里
	// 预先同步上报，Controller 才不会把任务挂成 running 直到 Duration+120s
	// 超时重试。
	w.preUpdateShutdown()

	log.Printf("[update] binary replaced, restarting...")
	if err := w.restartSelf(exeAbs); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return nil
}

// preUpdateShutdown 更新重启前的公共收尾（Unix rename 与 Windows 换身共用）：
// 上报进行中任务完成 → 停攻击 → 注销节点条目。
func (w *Worker) preUpdateShutdown() {
	log.Printf("[update] reporting active tasks complete...")
	w.reportActiveTasksComplete()
	w.stopAllAttacks()
	w.deregister()
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
// exec 与 spawn 均失败时返回错误（调用方保留 .bak 供人工恢复，且不写版本文件，
// 下次轮询可重试——避免"版本已记录但旧二进制仍在跑"的永久跳过）。
func (w *Worker) restartSelf(exe string) error {
	args := os.Args[1:]
	env := os.Environ()

	if runtime.GOOS != "windows" {
		if err := execSyscallExec(exe, args, env); err != nil {
			log.Printf("[update] exec failed, falling back to spawn: %v", err)
		} else {
			return nil
		}
	}

	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn failed: %w", err)
	}
	log.Printf("[update] new process started (pid=%d), exiting", cmd.Process.Pid)
	os.Exit(0)
	return nil
}
