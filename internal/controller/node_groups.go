package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// 节点分组：组名 → 节点 ID 列表。
// 分组只是节点的快捷多选（任务派发时展开为 workers），不改变节点本身属性。
// 持久化在 data/node_groups.json（原子替换）。

// loadNodeGroups 从磁盘加载节点分组
func loadNodeGroups(path string) map[string][]string {
	groups := make(map[string][]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return groups
	}
	if json.Unmarshal(data, &groups) == nil && len(groups) > 0 {
		log.Printf("[node-groups] loaded %d groups from %s", len(groups), path)
	}
	return groups
}

// persistNodeGroups 落盘分组（调用方不得持有 nodeGroupsMu）
func (c *Ctrl) persistNodeGroups() {
	c.nodeGroupsMu.RLock()
	data, err := json.Marshal(c.nodeGroups)
	c.nodeGroupsMu.RUnlock()
	if err != nil {
		log.Printf("[node-groups] marshal error: %v", err)
		return
	}
	tmp := c.nodeGroupsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[node-groups] write error: %v", err)
		return
	}
	os.Remove(c.nodeGroupsFile)
	if err := os.Rename(tmp, c.nodeGroupsFile); err != nil {
		log.Printf("[node-groups] rename error: %v", err)
	}
}

// handleNodeGroups /api/node-groups
// GET  → 全部分组；PUT → 创建/覆盖分组（body: {"name":"x","workers":["id1",...]})
// DELETE ?name=x → 删除分组
func (c *Ctrl) handleNodeGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		c.nodeGroupsMu.RLock()
		groups := make(map[string][]string, len(c.nodeGroups))
		for k, v := range c.nodeGroups {
			groups[k] = append([]string(nil), v...)
		}
		c.nodeGroupsMu.RUnlock()
		writeJSON(w, groups)
	case "PUT", "POST":
		var req struct {
			Name    string   `json:"name"`
			Workers []string `json:"workers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, `{"error":"group name required"}`, 400)
			return
		}
		// 校验节点都存在（允许空组，方便先建组后加节点）
		if len(req.Workers) > 0 {
			c.mu.RLock()
			for _, wid := range req.Workers {
				if _, ok := c.nodes[wid]; !ok {
					c.mu.RUnlock()
					writeJSON(w, map[string]string{"error": "unknown worker: " + wid})
					return
				}
			}
			c.mu.RUnlock()
		}
		c.nodeGroupsMu.Lock()
		c.nodeGroups[req.Name] = append([]string(nil), req.Workers...)
		c.nodeGroupsMu.Unlock()
		c.persistNodeGroups()
		log.Printf("[node-groups] saved group %q (%d members)", req.Name, len(req.Workers))
		writeJSON(w, map[string]interface{}{"ok": true})
	case "DELETE":
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, `{"error":"group name required"}`, 400)
			return
		}
		c.nodeGroupsMu.Lock()
		_, existed := c.nodeGroups[name]
		delete(c.nodeGroups, name)
		c.nodeGroupsMu.Unlock()
		c.persistNodeGroups()
		writeJSON(w, map[string]interface{}{"ok": true, "deleted": existed})
	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// resolveTaskGroups 把请求中的节点分组展开为 worker ID 列表。
// 与显式 workers 并存时取并集去重。返回 (展开结果, 错误消息)。
func (c *Ctrl) resolveTaskGroups(groups []string, workers []string) ([]string, string) {
	c.nodeGroupsMu.RLock()
	defer c.nodeGroupsMu.RUnlock()

	seen := make(map[string]bool)
	var out []string
	for _, g := range groups {
		members, ok := c.nodeGroups[g]
		if !ok {
			return nil, "unknown node group: " + g
		}
		for _, wid := range members {
			if !seen[wid] {
				seen[wid] = true
				out = append(out, wid)
			}
		}
	}
	for _, wid := range workers {
		if !seen[wid] {
			seen[wid] = true
			out = append(out, wid)
		}
	}
	return out, ""
}
