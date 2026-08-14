package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 环境迁移：把整套部署（数据 + worker 连接）从旧 controller 搬到新 controller。
//
// 三个环节：
//  1. GET /api/migrate/export    （旧 controller）打包 data/ 业务数据为 tar.gz
//  2. POST /api/migrate/import   （新 controller）解压导入（备份冲突文件后重启）
//  3. POST /api/migrate/start    （旧 controller）推送数据 + 进入迁移模式：
//     心跳响应携带 reconfigure_controller，worker 逐个自动切换连接
//
// 迁移后旧 controller 即可下线；worker 机器无需任何手动操作。

// migrateInclude 导出清单：data/ 下的业务文件（相对路径）。
// 明确排除：auth/admin.token、auth/worker.token（保留新 controller 自身的
// 管理口令）、*.tmp 临时文件。auth/workers/*.token 必须包含（worker 凭据
// 随迁移过去，否则 worker 切到新 controller 后注册会被拒）。
var migrateExcludePrefixes = []string{
	"auth/admin.token",
	"auth/worker.token",
	"worker.log",
	"worker.pid",
	"kicked",
}

// walkDataFiles 递归收集 data/ 下需要导出的文件（跳过目录与排除项）
func walkDataFiles() []string {
	var files []string
	filepath.WalkDir("data", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		// 顶层排除文件（auth/workers/*.token 等子目录文件保留）
		for _, p := range migrateExcludePrefixes {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				return nil
			}
		}
		if strings.HasSuffix(path, ".tmp") {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	return files
}

// handleMigrateExport GET /api/migrate/export
// 打包 data/ 业务文件为 tar.gz 下载。
func (c *Ctrl) handleMigrateExport(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if !c.exportToBuffer(&buf) {
		writeJSON(w, map[string]string{"error": "export failed"})
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=blackout-migrate.tar.gz")
	w.Write(buf.Bytes())
	log.Printf("[migrate] export complete (%d bytes)", buf.Len())
}

// handleMigrateImport POST /api/migrate/import
// 接收迁移包：备份同名文件到 data/migrate_bak_<ts>/ 后解压写入，
// 随后自动重启 controller 使 SQLite 连接/内存状态全部重新加载。
// 管理口令（auth/admin.token、auth/worker.token）不在包内，保持不变。
func (c *Ctrl) handleMigrateImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20)) // 上限 256MB
	if err != nil {
		writeJSON(w, map[string]string{"error": "read body: " + err.Error()})
		return
	}

	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		writeJSON(w, map[string]string{"error": "not a gzip archive: " + err.Error()})
		return
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	backupDir := fmt.Sprintf("data/migrate_bak_%d", time.Now().Unix())
	os.MkdirAll(backupDir, 0755)

	imported := 0
	totalRead := int64(0)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, map[string]string{"error": "tar read error: " + err.Error()})
			return
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name == "" {
			continue
		}
		// 路径穿越防护：只允许 data/ 前缀且不含 ..
		// 安全加固：拒绝 auth/ 目录（admin/worker 凭据只属于各自 controller），
		// 防止低权限方借 import 覆盖管理员口令
		if !strings.HasPrefix(hdr.Name, "data/") || strings.Contains(hdr.Name, "..") ||
			strings.HasPrefix(hdr.Name, "data/auth/") {
			log.Printf("[migrate] import skipped unsafe path: %s", hdr.Name)
			continue
		}

		// 防 gzip 炸弹：单条目解压上限 64MB，总量上限 512MB
		entry, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			writeJSON(w, map[string]string{"error": "read entry " + hdr.Name + ": " + err.Error()})
			return
		}
		if len(entry) >= 64<<20 {
			writeJSON(w, map[string]string{"error": "entry too large: " + hdr.Name + " (max 64MB)"})
			return
		}
		totalRead += int64(len(entry))
		if totalRead > 512<<20 {
			writeJSON(w, map[string]string{"error": "archive too large (max 512MB decompressed)"})
			return
		}

		// 备份现有文件（若存在）：rename 到备份目录
		if _, statErr := os.Stat(hdr.Name); statErr == nil {
			if err := os.Rename(hdr.Name, filepath.Join(backupDir, filepath.Base(hdr.Name))); err != nil {
				// Windows 上运行中的 SQLite 等文件可能被占用，记录但继续
				log.Printf("[migrate] backup %s failed: %v", hdr.Name, err)
			}
		}
		if err := os.WriteFile(hdr.Name, entry, 0644); err != nil {
			writeJSON(w, map[string]string{"error": "write " + hdr.Name + ": " + err.Error()})
			return
		}
		imported++
		log.Printf("[migrate] imported: %s (%d bytes)", hdr.Name, len(entry))
	}

	if imported == 0 {
		writeJSON(w, map[string]string{"error": "no files imported (empty archive?)"})
		return
	}

	// 热加载 worker tokens（其他配置重启后生效）
	c.loadWorkerTokens()

	log.Printf("[migrate] import complete: %d files, restarting controller in 2s", imported)
	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"imported": imported,
		"backup":   backupDir,
		"restart":  true,
	})

	go func() {
		time.Sleep(2 * time.Second)
		exe, err := os.Executable()
		if err != nil {
			log.Printf("[migrate] restart failed: %v", err)
			return
		}
		c.restartController(exe)
	}()
}

// handleMigrateStart POST /api/migrate/start（在旧 controller 上操作）
// body: {"target_http":"http://2.2.2.2:8080","target_admin_token":"...",
//        "target_grpc":"2.2.2.2:9090","worker_token":""}
// 1. 导出本机数据 → 推送到新 controller 导入
// 2. 进入迁移模式：心跳携带新地址，worker 逐个自动切换
func (c *Ctrl) handleMigrateStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	var req struct {
		TargetHTTP      string `json:"target_http"`
		TargetAdminToken string `json:"target_admin_token"`
		TargetGRPC      string `json:"target_grpc"`
		WorkerToken     string `json:"worker_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid json"})
		return
	}
	req.TargetHTTP = strings.TrimSpace(req.TargetHTTP)
	req.TargetGRPC = strings.TrimSpace(req.TargetGRPC)
	if req.TargetHTTP == "" || req.TargetGRPC == "" || req.TargetAdminToken == "" {
		writeJSON(w, map[string]string{"error": "target_http, target_grpc and target_admin_token required"})
		return
	}

	// 1. 导出并推送数据到新 controller
	var buf bytes.Buffer
	exportOK := c.exportToBuffer(&buf)
	if !exportOK {
		writeJSON(w, map[string]string{"error": "export failed"})
		return
	}

	pushURL := strings.TrimSuffix(req.TargetHTTP, "/") + "/api/migrate/import"
	httpReq, err := http.NewRequest("POST", pushURL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	httpReq.Header.Set("Content-Type", "application/gzip")
	httpReq.Header.Set("Authorization", "Bearer "+req.TargetAdminToken)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		writeJSON(w, map[string]string{"error": "push to target failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		writeJSON(w, map[string]string{"error": fmt.Sprintf("target import http %d: %s", resp.StatusCode, string(respBody))})
		return
	}
	var importResp struct {
		Ok      bool   `json:"ok"`
		Backup  string `json:"backup"`
		Restart bool   `json:"restart"`
	}
	json.Unmarshal(respBody, &importResp)
	log.Printf("[migrate] data pushed to %s (imported, backup: %s)", req.TargetHTTP, importResp.Backup)

	// 2. 进入迁移模式：所有心跳携带新 controller 地址，worker 自动切换
	c.migrateMu.Lock()
	c.migrateTarget = req.TargetGRPC
	c.migrateToken = req.WorkerToken
	c.migrateMu.Unlock()

	c.mu.RLock()
	workerCount := 0
	for _, n := range c.nodes {
		if n.Status != "OFFLINE" {
			workerCount++
		}
	}
	c.mu.RUnlock()

	log.Printf("[migrate] migration mode ON: %d online workers will switch to %s", workerCount, req.TargetGRPC)
	c.auditAction(r, "migrate_start", req.TargetGRPC)
	writeJSON(w, map[string]interface{}{
		"ok":           true,
		"migrating":    true,
		"target_grpc":  req.TargetGRPC,
		"online_workers": workerCount,
	})
}

// handleMigrateStop POST /api/migrate/stop
// 撤销迁移模式：心跳不再携带 reconfigure，worker 保持当前连接。
// （误触发迁移时在旧 controller 尚未下线前可反悔）
func (c *Ctrl) handleMigrateStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, 405)
		return
	}
	c.migrateMu.Lock()
	c.migrateTarget = ""
	c.migrateToken = ""
	c.migrateMu.Unlock()
	log.Printf("[migrate] migration mode OFF")
	c.auditAction(r, "migrate_stop", "")
	writeJSON(w, map[string]interface{}{"ok": true})
}

// exportToBuffer 把 data/ 业务文件打包到 buf（与 handleMigrateExport 共用）。
// 递归遍历 data/（含 auth/workers/ 子目录），仅排除 migrateExcludePrefixes。
func (c *Ctrl) exportToBuffer(buf *bytes.Buffer) bool {
	gz := gzip.NewWriter(buf)
	tw := tar.NewWriter(gz)

	files := walkDataFiles()
	if len(files) == 0 {
		log.Printf("[migrate] export: no files to export")
	}
	for _, rel := range files {
		data, err := os.ReadFile(rel)
		if err != nil {
			continue
		}
		hdr := &tar.Header{Name: rel, Mode: 0644, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return false
		}
		tw.Write(data)
		log.Printf("[migrate] export: %s (%d bytes)", rel, len(data))
	}
	tw.Close()
	gz.Close()
	return true
}
