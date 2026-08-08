package controller

import (
	"crypto/tls"
	"encoding/json"
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

// Controller 自更新检测与手动更新：
//   - GET  /api/update/check    检测 GitHub 最新 Release（版本/说明/跳转链接），不自动更新
//   - POST /api/update/controller 手动选择后更新 Controller 自身（下载→校验→替换→重启）
//   - POST /api/update/workers    手动选择后把 Worker 云更新目标设为最新版本

// ReleaseInfo GitHub Releases API 的 latest 响应
type ReleaseInfo struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

const githubAPIBase = "https://api.github.com"

// updateClient 允许自签证书（Controller 启用 TLS 时 API 经 ghproxy 也是 https）
var updateCheckClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// fetchLatestRelease 查询 GitHub 最新 Release。未配置仓库时返回 nil。
// 配置了 ghProxy 时经代理访问（国内服务器直连 api.github.com 慢）。
func (c *Ctrl) fetchLatestRelease() (*ReleaseInfo, error) {
	if c.build.GitRepo == "" {
		return nil, fmt.Errorf("git repo not configured")
	}
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", githubAPIBase, c.build.GitRepo)
	if c.build.GhProxy != "" {
		apiURL = strings.TrimSuffix(c.build.GhProxy, "/") + "/" + apiURL
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NetTool-Controller/"+c.build.Version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := updateCheckClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // 无 Release
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// versionNewer 判断 target 是否比 current 新（按 vX.Y.Z 数字比较，dev 视为最旧）
func versionNewer(current, target string) bool {
	cur, ok1 := parseVersion(current)
	tgt, ok2 := parseVersion(target)
	if !ok2 {
		return false
	}
	if !ok1 {
		return true // current 非版本号（如 dev）且 target 是版本号 → 有新版本
	}
	for i := 0; i < 3; i++ {
		if tgt[i] > cur[i] {
			return true
		}
		if tgt[i] < cur[i] {
			return false
		}
	}
	return false
}

// parseVersion 解析 v1.2.3 / 1.2.3 → [1,2,3]
func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			break
		}
		n := 0
		for _, ch := range parts[i] {
			if ch < '0' || ch > '9' {
				return [3]int{}, false
			}
			n = n*10 + int(ch-'0')
		}
		out[i] = n
	}
	return out, true
}

// handleUpdateCheck GET /api/update/check
// 检测是否有新版本，返回版本对比 + Release 说明 + 跳转链接。不做任何更新。
func (c *Ctrl) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	rel, err := c.fetchLatestRelease()
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"current_version": c.build.Version,
			"error":           err.Error(),
		})
		return
	}

	resp := map[string]interface{}{
		"current_version": c.build.Version,
		"repo":            c.build.GitRepo,
		"checkable":       c.build.GitRepo != "" && c.build.Version != "dev",
	}
	if rel == nil {
		resp["latest_version"] = ""
		resp["has_update"] = false
		writeJSON(w, resp)
		return
	}

	resp["latest_version"] = rel.TagName
	resp["release_name"] = rel.Name
	resp["release_url"] = rel.HTMLURL
	resp["published_at"] = rel.PublishedAt
	// 截断说明，避免 UI 拉大 JSON
	notes := rel.Body
	if len(notes) > 2000 {
		notes = notes[:2000] + "..."
	}
	resp["notes"] = notes
	resp["has_update"] = versionNewer(c.build.Version, rel.TagName)
	writeJSON(w, resp)
}

// handleUpdateController POST /api/update/controller
// 手动选择后：下载最新 Controller 二进制 → 校验 → 替换 → 重启自身。
// 立即返回 ok，替换/重启在后台 goroutine 执行（延迟 1s 让响应先发出）。
func (c *Ctrl) handleUpdateController(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	rel, err := c.fetchLatestRelease()
	if err != nil || rel == nil {
		writeJSON(w, map[string]interface{}{"error": "no release available"})
		return
	}
	if !versionNewer(c.build.Version, rel.TagName) {
		writeJSON(w, map[string]interface{}{"error": "already up to date"})
		return
	}

	// 目标二进制名（与 Release 产物一致）
	binName := "controller-linux-amd64"
	if runtime.GOOS == "windows" {
		binName = "controller-windows-amd64.exe"
	}
	dlURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", c.build.GitRepo, rel.TagName, binName)
	if c.build.GhProxy != "" {
		dlURL = strings.TrimSuffix(c.build.GhProxy, "/") + "/" + dlURL
	}

	writeJSON(w, map[string]interface{}{"ok": true, "version": rel.TagName, "url": dlURL})
	log.Printf("[self-update] updating controller to %s from %s", rel.TagName, dlURL)

	go func() {
		time.Sleep(1 * time.Second)
		if err := c.applyControllerUpdate(dlURL); err != nil {
			log.Printf("[self-update] FAILED: %v", err)
		}
	}()
}

// handleUpdateWorkers POST /api/update/workers
// 手动选择后：把 Worker 云更新目标设为最新版本（复用 /api/deploy/update 的默认逻辑）。
func (c *Ctrl) handleUpdateWorkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	rel, err := c.fetchLatestRelease()
	if err != nil || rel == nil {
		writeJSON(w, map[string]interface{}{"error": "no release available"})
		return
	}

	// 版本用最新 tag；URL 留空 = 各 Worker 按平台取默认 GitHub Release 地址
	c.updateMu.Lock()
	c.updateVersion = rel.TagName
	c.updateURL = ""
	c.updateMu.Unlock()
	payload, _ := json.Marshal(map[string]string{"version": rel.TagName, "url": ""})
	if err := os.WriteFile(c.updateFile, payload, 0644); err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	log.Printf("[self-update] workers update target set to %s", rel.TagName)
	writeJSON(w, map[string]interface{}{"ok": true, "version": rel.TagName})
}

// applyControllerUpdate 下载新 Controller → 校验 → 替换 → 重启
func (c *Ctrl) applyControllerUpdate(dlURL string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}
	exeAbs, err := filepath.Abs(exe)
	if err != nil {
		exeAbs = exe
	}

	tmp := exeAbs + ".update"
	os.Remove(tmp)
	if err := downloadUpdateBinary(dlURL, tmp); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := verifyUpdateBinary(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("verify: %w", err)
	}

	backup := exeAbs + ".bak"
	os.Remove(backup)
	if err := os.Rename(exeAbs, backup); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.Rename(tmp, exeAbs); err != nil {
		os.Rename(backup, exeAbs)
		os.Remove(tmp)
		return fmt.Errorf("replace: %w", err)
	}

	log.Printf("[self-update] controller binary replaced, restarting...")
	c.restartController(exeAbs)
	return nil
}

// restartController 重启自身：Linux 用 syscall.Exec 保持 PID，Windows spawn 新进程
func (c *Ctrl) restartController(exe string) {
	if runtime.GOOS != "windows" {
		if err := controllerExecSelf(exe); err != nil {
			log.Printf("[self-update] exec failed, falling back to spawn: %v", err)
		} else {
			return
		}
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("[self-update] spawn failed: %v", err)
		return
	}
	log.Printf("[self-update] new process started (pid=%d), exiting", cmd.Process.Pid)
	os.Exit(0)
}

// downloadUpdateBinary 下载新二进制到指定路径
func downloadUpdateBinary(url, path string) error {
	resp, err := updateCheckClient.Get(url)
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
	if n < 1<<20 { // 小于 1MB 视为下载失败
		os.Remove(path)
		return fmt.Errorf("binary too small (%d bytes)", n)
	}
	return out.Sync()
}

// verifyUpdateBinary 校验下载文件是否为当前平台可执行文件
func verifyUpdateBinary(path string) error {
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
	}

	if err := os.Chmod(path, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}
