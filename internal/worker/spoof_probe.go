package worker

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"newtool/internal/attack"
)

// SpoofProbeResponse Controller → Worker HTTP 响应
type SpoofProbeResponse struct {
	CanSpoof bool   `json:"can_spoof"`
	Message  string `json:"message"`
}

// spoofCapabilityTTL 伪造能力缓存有效期：超过该时间重新探测
const spoofCapabilityTTL = 24 * time.Hour

// probeIPSpoofing 探测本机是否支持 IP 伪造（两阶段协议）
// 1. POST 注册 nonce/claim_ip 到 Controller（注册成功后才发包，避免竞态）
// 2. 发送伪造源 IP 的 UDP 探测包到 Controller:9091
// 3. 轮询 result 端点获取验证结果
// 返回 (结果, 是否可靠)。reliable=false 表示探测未能完整执行
// （平台/权限不支持、注册失败、网络抖动等），此时不应把 false 当作
// "验证为不支持"写入缓存。
func (w *Worker) probeIPSpoofing() (bool, bool) {
	// 如果是 Windows，直接返回 false（Windows 通常不支持原始套接字伪造）
	if w.isWindows {
		log.Printf("[spoof-probe] skipped: Windows does not support IP spoofing")
		return false, false
	}

	// 检查 attack 包是否支持伪造
	if !attack.SupportsSpoofing() {
		log.Printf("[spoof-probe] skipped: platform does not support spoofing")
		return false, false
	}

	// raw socket 需要 root
	if !IsRoot() {
		log.Printf("[spoof-probe] skipped: raw socket requires root/admin privileges")
		return false, false
	}

	// 生成随机 nonce（16 字节）
	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	// 生成一个伪造的源 IP（使用私有地址段，确保不会真实路由）
	claimIP := "10.99.88.77"
	controllerHost := w.controllerHost()

	// 允许自签证书：Controller 启用 TLS 时使用自签证书
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 1. 注册探测请求（Controller 立即返回，不再阻塞等待 UDP）
	// 注意用 w.assignedID（注册完成后的最终 ID），确保 spoof 标签打到正确节点
	regURL := fmt.Sprintf("%s/api/worker/spoof-probe?worker_id=%s&claim_ip=%s&nonce=%s",
		w.ctrlBaseURL(), w.assignedID, claimIP, nonce)

	req, err := http.NewRequest("POST", regURL, nil)
	if err != nil {
		log.Printf("[spoof-probe] register request create failed: %v", err)
		return false, false
	}
	req.Header.Set("Authorization", "Bearer "+w.authToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[spoof-probe] register request failed: %v", err)
		return false, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[spoof-probe] register status %d", resp.StatusCode)
		return false, false
	}

	log.Printf("[spoof-probe] registered: claim_ip=%s nonce=%s controller=%s", claimIP, nonce, controllerHost)

	// 2. 注册成功后再发送伪造源 IP 的 UDP 探测包（保证 Controller 已就绪，消除时序竞态）
	spoof, err := attack.NewSpoofConn(controllerHost, 9091)
	if err != nil {
		log.Printf("[spoof-probe] failed to create raw socket: %v", err)
		return false, false
	}
	defer spoof.Close()

	payload := []byte("SPOOF_PROBE:" + nonce)
	for i := 0; i < 3; i++ {
		if err := spoof.Send(claimIP, controllerHost, 9091, payload); err != nil {
			log.Printf("[spoof-probe] UDP send failed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 3. 轮询验证结果（最多 4 秒，Controller 验证窗口 5 秒）
	resultURL := fmt.Sprintf("%s/api/worker/spoof-probe/result?nonce=%s", w.ctrlBaseURL(), nonce)
	deadline := time.Now().Add(4 * time.Second)

	for {
		req, err := http.NewRequest("GET", resultURL, nil)
		if err != nil {
			log.Printf("[spoof-probe] result request create failed: %v", err)
			return false, false
		}
		req.Header.Set("Authorization", "Bearer "+w.authToken)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[spoof-probe] result request failed: %v", err)
			return false, false
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("[spoof-probe] result read failed: %v", err)
			return false, false
		}

		var probeResp SpoofProbeResponse
		var poll struct {
			Pending bool `json:"pending"`
		}
		if err := json.Unmarshal(body, &poll); err == nil && poll.Pending {
			// 仍在等待窗口内，稍后重试
			if time.Now().After(deadline) {
				log.Printf("[spoof-probe] result timeout after 4s")
				return false, false
			}
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if err := json.Unmarshal(body, &probeResp); err != nil {
			log.Printf("[spoof-probe] response decode failed: %v", err)
			return false, false
		}

		log.Printf("[spoof-probe] result: can_spoof=%v message=%s", probeResp.CanSpoof, probeResp.Message)
		return probeResp.CanSpoof, true
	}
}

// queryControllerSpoofCache 查询 Controller 的伪造能力缓存（按 IP 持久化）。
// 同 IP 的 worker 重新上线时直接复用历史结果，跳过重复探测。
// 返回 (结果, 是否命中)。命中时上报状态确保 Controller 节点标记同步。
func (w *Worker) queryControllerSpoofCache() (bool, bool) {
	url := w.ctrlBaseURL() + "/api/worker/spoof-cache?worker_id=" + w.assignedID
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Authorization", "Bearer "+w.authToken)

	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[spoof-probe] cache query failed: %v", err)
		return false, false
	}
	defer resp.Body.Close()

	var r struct {
		Cached   bool   `json:"cached"`
		CanSpoof bool   `json:"can_spoof"`
		IP       string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, false
	}
	if !r.Cached {
		return false, false
	}
	// 命中缓存：上报状态让 Controller 节点标记同步（防 Controller 重启丢失标记）
	w.reportSpoofStatus()
	return r.CanSpoof, true
}

// reportSpoofStatus 把本机伪造能力探测结果上报给 Controller，
// 使节点表的 CanSpoof/SpoofTested 反映真实能力（探测失败也会上报为 false，
// 避免 Controller 端停留在"待检测"或乐观的默认值）。
func (w *Worker) reportSpoofStatus() {
	url := w.ctrlBaseURL() + "/api/worker/spoof-status"
	body := fmt.Sprintf(`{"worker_id":"%s","can_spoof":%v}`,
		w.assignedID, w.canSpoofIP)
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		log.Printf("[spoof-probe] status report request create failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.authToken)

	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[spoof-probe] status report failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[spoof-probe] status report http %d", resp.StatusCode)
		return
	}
	log.Printf("[spoof-probe] reported status to controller: can_spoof=%v", w.canSpoofIP)
}

// saveSpoofCapability 保存伪造能力到本地数据库（含探测时间戳，用于 TTL 过期）
func (w *Worker) saveSpoofCapability(canSpoof bool) error {
	if w.localPool == nil || w.localPool.db == nil {
		return fmt.Errorf("local pool not initialized")
	}

	value := "false"
	if canSpoof {
		value = "true"
	}

	_, err := w.localPool.db.Exec(`
		INSERT INTO worker_config (key, value)
		VALUES ('can_spoof_ip', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, value)
	if err != nil {
		return err
	}

	_, err = w.localPool.db.Exec(`
		INSERT INTO worker_config (key, value)
		VALUES ('can_spoof_ip_tested_at', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, strconv.FormatInt(time.Now().Unix(), 10))

	return err
}

// loadSpoofCapability 从本地数据库加载伪造能力缓存
// 返回 (能力值, 探测时间)。兼容旧格式数据（无 tested_at 时间戳，视为过期）。
func (w *Worker) loadSpoofCapability() (bool, time.Time, error) {
	if w.localPool == nil || w.localPool.db == nil {
		return false, time.Time{}, fmt.Errorf("local pool not initialized")
	}

	var value string
	err := w.localPool.db.QueryRow(`
		SELECT value FROM worker_config WHERE key = 'can_spoof_ip'
	`).Scan(&value)
	if err != nil {
		return false, time.Time{}, err
	}

	var ts string
	err = w.localPool.db.QueryRow(`
		SELECT value FROM worker_config WHERE key = 'can_spoof_ip_tested_at'
	`).Scan(&ts)
	if err == sql.ErrNoRows {
		// 旧格式缓存：无时间戳 → 视为过期，返回零值时间
		return value == "true", time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}

	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false, time.Time{}, err
	}

	return value == "true", time.Unix(secs, 0), nil
}
