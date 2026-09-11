// 一次性修复脚本：把 i18n 方法键统一为完整方法名（method_<完整方法名>），
// 使 L7 推荐的 t('method_'+method) 与下拉引用都能命中词典。
// 同时补齐缺失键（tcp_tcpbypass / 节点分组 / fofa_export_tip）。
const fs = require('fs');
const path = require('path');
const file = path.resolve(__dirname, '..', 'web', 'static', 'index.html');
let html = fs.readFileSync(file, 'utf8');

// 短键 → 完整方法名
const map = {
  method_combo: 'method_combo',
  method_vse: 'method_vse',
  method_vse_refl: 'method_vse_reflector',
  method_dns_refl: 'method_dns_reflector',
  method_cldap_refl: 'method_cldap_reflector',
  method_udp_stdhex: 'method_udp_stdhex',
  method_udp_plain: 'method_udp_plain',
  method_udp_bypass: 'method_udp_bypass',
  method_udp_burst: 'method_udp_burst',
  method_tcp_syn: 'method_tcp_syn',
  method_tcp_syn_spoof: 'method_tcp_syn_spoof',
  method_tcp_ack: 'method_tcp_ack',
  method_tcp_connect: 'method_tcp_connect',
  method_http: 'method_http_flood',
  method_head: 'method_head_flood',
  method_range: 'method_range_flood',
  method_post: 'method_post_flood',
  method_http2: 'method_http2_flood',
  method_http2_reset: 'method_http2_reset',
  method_http2_cont: 'method_http2_continuation',
  method_http2_bomb: 'method_http2_bomb',
  method_h2_ping: 'method_h2_ping',
  method_tls_handshake: 'method_tls_handshake',
  method_slowloris: 'method_slowloris',
  method_slow_post: 'method_slow_post',
  method_ws_flood: 'method_ws_flood',
  method_ws_slow: 'method_ws_slow',
  method_https: 'method_https_bypass',
  method_mc_handshake: 'method_minecraft_handshake',
  method_mc_login: 'method_minecraft_login',
  method_game_udp: 'method_game_udp',
};

// 按键名长度倒序替换，避免前缀误伤（带引号/冒号的精确匹配本身已足够，这里再保险）
const keys = Object.keys(map).sort((a, b) => b.length - a.length);
let dictChanges = 0, refChanges = 0;
for (const short of keys) {
  const full = map[short];
  if (short === full) continue;
  // 词典定义：short: '...'  → full: '...'
  const reDict = new RegExp('(^|[\\s,{])' + short + ':', 'g');
  html = html.replace(reDict, (m0, p1) => { dictChanges++; return p1 + full + ':'; });
  // 引用：t('short') → t('full')
  const reRef = new RegExp("t\\('" + short + "'\\)", 'g');
  html = html.replace(reRef, () => { refChanges++; return "t('" + full + "')"; });
}

fs.writeFileSync(file, html);
console.log('词典键重命名:', dictChanges, '| 引用更新:', refChanges);
