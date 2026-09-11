package attack

import (
	"net/http"
	"testing"
	"time"
)

// 测试辅助：本地回环请求的瞬时错误重试。
//
// Windows 上跑完整套件（尤其 -race）时，回环临时端口会被前序洪泛测试耗尽，
// 表现为 "Only one usage of each socket address"；这属于环境噪声而非产品缺陷。
// 生产代码已对瞬时错误重试（isTransientNetErr），测试侧再兜一层，
// 持续失败则 t.Skip 并说明原因，避免用环境噪声制造假失败。

// getWithRetry 发一次 GET；瞬时本地错误重试，持续失败则跳过测试。
func getWithRetry(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		resp, err := client.Get(url)
		if err == nil {
			return resp
		}
		lastErr = err
		if !isTransientNetErr(err) {
			t.Fatalf("request failed: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Skipf("loopback request unavailable (transient local socket error): %v", lastErr)
	return nil
}
