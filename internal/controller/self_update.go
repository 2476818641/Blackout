package controller

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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

// githubAuthToken 返回已配置的 GitHub Token（空 = 未认证）
func (c *Ctrl) githubAuthToken() string {
	c.githubTokenMu.RLock()
	defer c.githubTokenMu.RUnlock()
	return c.githubToken
}

// githubRequest 构造带认证的 GitHub API 请求
func (c *Ctrl) githubRequest(method, apiPath string) (*http.Request, error) {
	apiURL := githubAPIBase + apiPath
	if c.build.GhProxy != "" {
		apiURL = strings.TrimSuffix(c.build.GhProxy, "/") + "/" + apiURL
	}
	req, err := http.NewRequest(method, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NetTool-Controller/"+c.build.Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := c.githubAuthToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, nil
}

// fetchLatestRelease 查询 GitHub 最新 Release（按发布时间排序，不依赖
// /releases/latest 端点——该端点按创建时间判定且可能被代理缓存返回旧版本）。
// 未配置仓库时返回 nil。配置了 ghProxy 时经代理访问。
func (c *Ctrl) fetchLatestRelease() (*ReleaseInfo, error) {
	rels, err := c.fetchReleases()
	if err != nil {
		return nil, err
	}
	if len(rels) == 0 {
		return nil, nil
	}
	return &rels[0], nil
}

// fetchReleaseByTag 查询指定 tag 的 Release；不存在返回 nil
func (c *Ctrl) fetchReleaseByTag(tag string) (*ReleaseInfo, error) {
	if c.build.GitRepo == "" {
		return nil, fmt.Errorf("git repo not configured")
	}
	req, err := c.githubRequest("GET", "/repos/"+c.build.GitRepo+"/releases/tags/"+tag)
	if err != nil {
		return nil, err
	}

	resp, err := updateCheckClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
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

// fetchReleases 查询 Release 列表（最多 30 个），并按发布时间倒序排列。
// GitHub API 默认按创建时间排序（release 创建 vs 发布时间可能不一致，
// 且 Actions 编译完成后才发布，创建时间可能早于其他 release），
// 因此显式按 published_at 排序保证"最新发布"排在最前。
func (c *Ctrl) fetchReleases() ([]ReleaseInfo, error) {
	if c.build.GitRepo == "" {
		return nil, fmt.Errorf("git repo not configured")
	}
	req, err := c.githubRequest("GET", "/repos/"+c.build.GitRepo+"/releases?per_page=30")
	if err != nil {
		return nil, err
	}

	resp, err := updateCheckClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rels []ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&rels); err != nil {
		return nil, err
	}

	// 按发布时间倒序（published_at 为 RFC3339，字符串比较即可）
	sort.SliceStable(rels, func(i, j int) bool {
		return rels[i].PublishedAt > rels[j].PublishedAt
	})
	return rels, nil
}

// handleUpdateCheck GET /api/update/check[?version=v1.0.5]
// 检测是否有新版本，返回版本对比 + Release 说明 + 跳转链接 + 可用版本列表。
// 指定 version 参数时查询该版本（用于回退到旧版本）。不做任何更新。
func (c *Ctrl) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"current_version": c.build.Version,
		"repo":            c.build.GitRepo,
		"checkable":       c.build.GitRepo != "" && c.build.Version != "dev",
		"authenticated":   c.githubAuthToken() != "",
	}

	// 版本列表（供 UI 选择任意版本）
	if rels, err := c.fetchReleases(); err == nil {
		list := make([]map[string]interface{}, 0, len(rels))
		for _, rel := range rels {
			notes := rel.Body
			if len(notes) > 500 {
				notes = notes[:500] + "..."
			}
			list = append(list, map[string]interface{}{
				"version":      rel.TagName,
				"name":         rel.Name,
				"published_at": rel.PublishedAt,
				"notes":        notes,
			})
		}
		resp["releases"] = list
	}

	// 指定版本（回退/选择旧版本）
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		rel, err := c.fetchReleaseByTag(v)
		if err != nil {
			resp["error"] = err.Error()
			writeJSON(w, resp)
			return
		}
		if rel == nil {
			resp["error"] = "release not found: " + v
			writeJSON(w, resp)
			return
		}
		notes := rel.Body
		if len(notes) > 2000 {
			notes = notes[:2000] + "..."
		}
		resp["latest_version"] = rel.TagName
		resp["release_name"] = rel.Name
		resp["release_url"] = rel.HTMLURL
		resp["published_at"] = rel.PublishedAt
		resp["notes"] = notes
		// 指定版本时：只要不是当前版本即可更新/回退
		resp["has_update"] = c.build.Version != rel.TagName
		writeJSON(w, resp)
		return
	}

	// 默认：最新版本
	rel, err := c.fetchLatestRelease()
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, resp)
		return
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
	// 用 tag 是否一致判断"有更新"：GitHub releases/latest 按发布时间返回，
	// 无需数字版本比较（非标准递增标签如 v1.0.75 vs v1.0.8 会误判）。
	// dev 视为未发布版本，永远可更新到正式版。
	resp["has_update"] = c.build.Version != rel.TagName
	writeJSON(w, resp)
}

// handleUpdateToken GET/PUT /api/update/token
// 管理 GitHub Token：认证后 API 速率 5000/小时（未认证 60/小时），
// 并支持拉取版本列表选择任意版本。
func (c *Ctrl) handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, map[string]interface{}{
			"configured": c.githubAuthToken() != "",
			"masked":     maskToken(c.githubAuthToken()),
		})
	case "PUT", "POST":
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		token := strings.TrimSpace(body.Token)
		// 拒绝前端占位符：用户没修改就点保存时，字面量 ********
		// 会把真实 token 覆盖掉，导致 GitHub 认证失效
		if token == "********" {
			http.Error(w, `{"error":"placeholder token rejected"}`, 400)
			return
		}

		c.githubTokenMu.Lock()
		c.githubToken = token
		c.githubTokenMu.Unlock()

		if err := os.WriteFile(c.githubTokenFile, []byte(token), 0600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if token != "" {
			log.Printf("[update] GitHub token saved (authenticated API)")
		} else {
			log.Printf("[update] GitHub token cleared (unauthenticated API)")
		}
		c.auditAction(r, "github_token_set", map[bool]string{true: "saved", false: "cleared"}[token != ""])
		writeJSON(w, map[string]interface{}{"ok": true})
	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// handleUpdateController POST /api/update/controller[?version=v1.0.5]
// 手动选择后：下载指定版本（默认最新）Controller 二进制 → 校验 → 替换 → 重启自身。
// 立即返回 ok，替换/重启在后台 goroutine 执行（延迟 1s 让响应先发出）。
func (c *Ctrl) handleUpdateController(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	rel, err := c.resolveRelease(r)
	if err != nil || rel == nil {
		writeJSON(w, map[string]interface{}{"error": "no release available"})
		return
	}
	// 目标 tag 与当前版本一致才拒绝（数字版本比较会误判非标准标签如 v1.0.75）
	if rel.TagName == c.build.Version {
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

	// 供应链校验：先取官方 asset digest，取不到即拒绝更新（fail-closed）
	selfSHA256 := c.fetchAssetSHA256(rel.TagName, binName)
	if selfSHA256 == "" {
		writeJSON(w, map[string]interface{}{"error": "failed to fetch release asset SHA-256; update rejected (supply-chain protection)"})
		return
	}

	writeJSON(w, map[string]interface{}{"ok": true, "version": rel.TagName, "url": dlURL})
	log.Printf("[self-update] updating controller to %s from %s", rel.TagName, dlURL)
	c.auditAction(r, "update_controller", rel.TagName)

	go func() {
		time.Sleep(1 * time.Second)
		if err := c.applyControllerUpdate(dlURL, selfSHA256); err != nil {
			log.Printf("[self-update] FAILED: %v", err)
		}
	}()
}

// resolveRelease 根据 query 参数 version 解析目标 Release（缺省 = 最新）
func (c *Ctrl) resolveRelease(r *http.Request) (*ReleaseInfo, error) {
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		return c.fetchReleaseByTag(v)
	}
	return c.fetchLatestRelease()
}

// fetchAssetSHA256 查询指定 tag 的 Release 中目标 asset 的 SHA-256
// （GitHub API 的 digest 字段，形如 "sha256:<hex64>"）。
// 供应链校验用：下载的二进制必须与官方发布产物 digest 一致。
// 获取失败返回空串（调用方决定 fail-closed 或告警）。
func (c *Ctrl) fetchAssetSHA256(tag, assetName string) string {
	if c.build.GitRepo == "" || assetName == "" {
		return ""
	}
	req, err := c.githubRequest("GET", "/repos/"+c.build.GitRepo+"/releases/tags/"+tag)
	if err != nil {
		return ""
	}
	resp, err := updateCheckClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return ""
	}
	for _, a := range rel.Assets {
		if a.Name == assetName {
			d := strings.TrimPrefix(a.Digest, "sha256:")
			if len(d) == 64 {
				return d
			}
		}
	}
	return ""
}

// sha256File 计算文件 SHA-256（hex）
func sha256File(path string) (string, error) {
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

// handleUpdateWorkers POST /api/update/workers[?version=v1.0.5]
// 手动选择后：把 Worker 云更新目标设为指定版本（默认最新），
// 复用 /api/deploy/update 的默认逻辑。
func (c *Ctrl) handleUpdateWorkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	rel, err := c.resolveRelease(r)
	if err != nil || rel == nil {
		writeJSON(w, map[string]interface{}{"error": "no release available"})
		return
	}

	// 版本用指定 tag；URL 留空 = 各 Worker 按平台取默认 GitHub Release 地址。
	// 同时拉取双平台 asset digest 供供应链校验（worker 下载后强制比对）。
	sha256linux := c.fetchAssetSHA256(rel.TagName, "worker-linux-amd64")
	sha256windows := c.fetchAssetSHA256(rel.TagName, "worker-windows-amd64.exe")
	if sha256linux == "" && sha256windows == "" {
		log.Printf("[update] WARNING: failed to fetch asset SHA-256 for %s — workers will REJECT the update (supply-chain protection)", rel.TagName)
	}

	c.updateMu.Lock()
	c.updateVersion = rel.TagName
	c.updateURL = ""
	c.updateSHA256Linux = sha256linux
	c.updateSHA256Windows = sha256windows
	c.updateMu.Unlock()
	payload, _ := json.Marshal(map[string]string{"version": rel.TagName, "url": "", "sha256_linux": sha256linux, "sha256_windows": sha256windows})
	if err := os.WriteFile(c.updateFile, payload, 0644); err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	log.Printf("[self-update] workers update target set to %s", rel.TagName)
	c.auditAction(r, "update_workers", rel.TagName)
	writeJSON(w, map[string]interface{}{"ok": true, "version": rel.TagName})
}

// handleUpdateAll POST /api/update/all[?version=v1.0.5]
// 整体升级：先设置 Workers 云更新目标（约 60s 内自动更新），
// 再升级 Controller 自身（下载→校验→替换→重启）。
// 顺序设计：先让 Worker 拿到新版本目标并开始下载，Controller 重启
// 造成短暂断连不影响 Worker 更新流程（Worker 更新走 HTTP + 独立下载）；
// Controller 重启后 Worker 心跳自动恢复，随后完成更新重启。
func (c *Ctrl) handleUpdateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	rel, err := c.resolveRelease(r)
	if err != nil || rel == nil {
		writeJSON(w, map[string]interface{}{"error": "no release available"})
		return
	}
	if rel.TagName == c.build.Version {
		writeJSON(w, map[string]interface{}{"error": "already up to date"})
		return
	}

	// 1. 设置 Workers 更新目标（含双平台 digest 供应链校验）
	sha256linux := c.fetchAssetSHA256(rel.TagName, "worker-linux-amd64")
	sha256windows := c.fetchAssetSHA256(rel.TagName, "worker-windows-amd64.exe")
	if sha256linux == "" && sha256windows == "" {
		log.Printf("[update] WARNING: failed to fetch asset SHA-256 for %s — workers will REJECT the update (supply-chain protection)", rel.TagName)
	}

	c.updateMu.Lock()
	c.updateVersion = rel.TagName
	c.updateURL = ""
	c.updateSHA256Linux = sha256linux
	c.updateSHA256Windows = sha256windows
	c.updateMu.Unlock()
	payload, _ := json.Marshal(map[string]string{"version": rel.TagName, "url": "", "sha256_linux": sha256linux, "sha256_windows": sha256windows})
	if err := os.WriteFile(c.updateFile, payload, 0644); err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	log.Printf("[self-update] ALL upgrade to %s: workers target set", rel.TagName)

	// 2. 目标二进制名（与 Release 产物一致）
	binName := "controller-linux-amd64"
	if runtime.GOOS == "windows" {
		binName = "controller-windows-amd64.exe"
	}
	dlURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", c.build.GitRepo, rel.TagName, binName)
	if c.build.GhProxy != "" {
		dlURL = strings.TrimSuffix(c.build.GhProxy, "/") + "/" + dlURL
	}
	// Controller 自身二进制的 digest（下载后强制比对）
	selfSHA256 := c.fetchAssetSHA256(rel.TagName, binName)
	if selfSHA256 == "" {
		log.Printf("[self-update] WARNING: failed to fetch controller asset SHA-256 for %s — controller self-update ABORTED (supply-chain protection)", rel.TagName)
		writeJSON(w, map[string]interface{}{"error": "failed to fetch controller asset SHA-256; update rejected (supply-chain protection)"})
		return
	}

	// 3. 延迟 3s 后升级 Controller（让响应先发出，Worker 先收到目标）
	go func() {
		time.Sleep(3 * time.Second)
		log.Printf("[self-update] ALL upgrade: updating controller to %s", rel.TagName)
		if err := c.applyControllerUpdate(dlURL, selfSHA256); err != nil {
			log.Printf("[self-update] controller update FAILED: %v", err)
		}
	}()

	writeJSON(w, map[string]interface{}{"ok": true, "version": rel.TagName})
	c.auditAction(r, "update_all", rel.TagName)
}

// applyControllerUpdate 下载新 Controller → 校验（魔数 + SHA-256）→ 替换 → 重启。
// updateApplyMu 串行化整个流程：并发更新写同一临时文件会撕裂二进制、
// 破坏备份恢复（可能导致 Controller 起不来）。
func (c *Ctrl) applyControllerUpdate(dlURL, expectedSHA256 string) error {
	c.updateApplyMu.Lock()
	defer c.updateApplyMu.Unlock()

	// Windows 上运行中的 exe 被 OS 独占锁定，rename 必然失败：
	// 直接明确报错，避免产生 .update 残留与必败重试
	if runtime.GOOS == "windows" {
		return fmt.Errorf("controller self-update on Windows is not supported (running exe is locked); replace the binary manually")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}
	exeAbs, err := filepath.Abs(exe)
	if err != nil {
		exeAbs = exe
	}

	// 唯一临时文件名：并发/重复更新互不干扰
	tmp := fmt.Sprintf("%s.update.%d", exeAbs, time.Now().UnixNano())
	defer os.Remove(tmp)
	if err := downloadUpdateBinary(dlURL, tmp); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := verifyUpdateBinary(tmp); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	// 供应链校验：下载产物必须与官方 Release digest 一致
	if expectedSHA256 != "" {
		got, err := sha256File(tmp)
		if err != nil {
			return fmt.Errorf("hash: %w", err)
		}
		if !strings.EqualFold(got, expectedSHA256) {
			return fmt.Errorf("SHA-256 mismatch (expected %s, got %s) — update rejected (supply-chain protection)", expectedSHA256, got)
		}
		log.Printf("[self-update] SHA-256 verified: %s", got)
	} else {
		return fmt.Errorf("no SHA-256 configured for target binary — update rejected (supply-chain protection)")
	}

	backup := exeAbs + ".bak"
	os.Remove(backup)
	if err := os.Rename(exeAbs, backup); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.Rename(tmp, exeAbs); err != nil {
		os.Rename(backup, exeAbs)
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
