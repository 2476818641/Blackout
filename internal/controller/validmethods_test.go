package controller

import "testing"

// TestValidMethodsComplete 方法白名单完整性回归：
// 攻击引擎支持的所有方法必须都在 Controller 的 validMethods 白名单里，
// 否则创建任务会被 "unknown method" 拒绝（v1.3.0 曾漏掉 6 个新方法）。
// 新增攻击方法时若忘更新白名单，此测试直接失败。
func TestValidMethodsComplete(t *testing.T) {
	all := []string{
		"vse", "vse_reflector", "dns_reflector", "cldap_reflector",
		"udp_stdhex", "udp_plain", "udp_bypass", "udp_burst",
		"tcp_syn", "tcp_ack", "tcp_connect", "tcp_tcpbypass",
		"tcp_syn_spoof",
		"http_flood", "head_flood", "range_flood", "post_flood",
		"http2_flood", "http2_reset", "http2_continuation", "http2_bomb",
		"h2_ping", "tls_handshake",
		"slowloris", "slow_post",
		"ws_flood", "ws_slow",
		"https_bypass",
		"minecraft_handshake", "minecraft_login", "game_udp",
		"combo",
	}
	for _, m := range all {
		if !isValidMethod(m) {
			t.Errorf("method %q missing from validMethods whitelist — tasks using it are rejected with 'unknown method'", m)
		}
	}
	// 反例：垃圾方法必须被拒绝
	if isValidMethod("not_a_real_method") {
		t.Error("bogus method should be rejected")
	}
}
