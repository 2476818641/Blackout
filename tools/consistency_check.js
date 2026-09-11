// 交叉一致性检查：攻击方法清单（后端/前端）+ i18n 键完整性
// 用法: node tools/consistency_check.js
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

let problems = [];

// ---------- 1. 方法清单 ----------
const worker = read('internal/worker/worker.go');
const combo = read('internal/attack/combo.go');
const controller = read('internal/controller/controller.go');
const indexHtml = read('web/static/index.html');

// worker startTask switch 里的方法（case "x", "y":）
const extractCases = (src, marker) => {
  const start = src.indexOf(marker);
  if (start < 0) return [];
  // 从 marker 起到函数结束（下一个 "\nfunc " 或 "\n}" 顶层）
  let end = src.indexOf('\nfunc ', start + 10);
  if (end < 0) end = src.length;
  const block = src.slice(start, end);
  const out = new Set();
  const re = /case\s+((?:"[^"]+"\s*,?\s*)+):/g;
  let m;
  while ((m = re.exec(block))) {
    (m[1].match(/"([^"]+)"/g) || []).forEach((q) => out.add(q.replace(/"/g, '')));
  }
  return [...out];
};

const workerMethods = new Set(extractCases(worker, 'switch method {'));
const comboMethods = new Set(extractCases(combo, 'switch cfg.Method {'));
const validMethodsBlock = controller.slice(
  controller.indexOf('var validMethods = map[string]bool{'),
  controller.indexOf('func isValidMethod')
);
const validMethods = new Set((validMethodsBlock.match(/"([^"]+)":\s*true/g) || []).map((s) => s.match(/"([^"]+)"/)[1]));

// 前端下拉（主表单 + combo 子攻击）
const uiMethods = new Set((indexHtml.match(/<option value="[a-z0-9_]+"/g) || [])
  .map((s) => s.match(/value="([^"]+)"/)[1])
  .filter((v) => /^[a-z0-9_]+$/.test(v)));

// combo 子攻击下拉单独提取（在 sub_attacks select 区块内）
const subBlock = indexHtml.slice(indexHtml.indexOf('form.sub_attacks'), indexHtml.indexOf('no_sub_attacks'));
const subMethods = new Set((subBlock.match(/<option value="([a-z0-9_]+)"/g) || [])
  .map((s) => s.match(/value="([^"]+)"/)[1]));

console.log('=== 方法清单 ===');
console.log('worker 分派:', workerMethods.size, '| combo 分派:', comboMethods.size, '| validMethods:', validMethods.size, '| 前端下拉:', uiMethods.size, '| 子攻击下拉:', subMethods.size);

// worker 支持但 controller 白名单缺失
for (const m of workerMethods) {
  if (!validMethods.has(m)) problems.push(`[严重] worker 支持 ${m} 但 controller validMethods 缺失 → 创建任务被拒 "unknown method"`);
}
// worker 支持但 combo 分派缺失（combo 无法用该方法）
for (const m of workerMethods) {
  if (!comboMethods.has(m) && m !== 'combo') problems.push(`[中等] worker 支持 ${m} 但 combo 子攻击分派缺失 → 组合攻击无法使用`);
}
// worker 支持但前端主下拉缺失
for (const m of workerMethods) {
  if (!uiMethods.has(m) && m !== 'combo') problems.push(`[中等] worker 支持 ${m} 但前端方法下拉缺失 → 面板无法选择`);
}
// worker 支持但前端子攻击下拉缺失
for (const m of workerMethods) {
  if (!subMethods.has(m) && m !== 'combo') problems.push(`[轻微] 前端 combo 子攻击下拉缺少 ${m}`);
}
// controller 白名单有但 worker 不支持
for (const m of validMethods) {
  if (!workerMethods.has(m) && m !== 'combo') problems.push(`[中等] validMethods 含 ${m} 但 worker 未实现 → 任务创建成功但 worker 忽略("unknown method")`);
}

// ---------- 2. i18n 键完整性 ----------
const trStart = indexHtml.indexOf('const TR = {');
const trEnd = indexHtml.indexOf('return {', trStart);
const trBlock = indexHtml.slice(trStart, trEnd);
const enStart = trBlock.indexOf('en: {');
const zhStart = trBlock.indexOf('zh: {');
const enBlock = trBlock.slice(enStart, zhStart);
const zhBlock = trBlock.slice(zhStart);

const keysOf = (block) => {
  const out = new Set();
  const re = /(?:^|[,{\s])([a-z0-9_]+)\s*:/g;
  let m;
  while ((m = re.exec(block))) out.add(m[1]);
  return out;
};
const enKeys = keysOf(enBlock);
const zhKeys = keysOf(zhBlock);

console.log('=== i18n ===');
console.log('en 键:', enKeys.size, '| zh 键:', zhKeys.size);

for (const k of enKeys) if (!zhKeys.has(k)) problems.push(`[中等] i18n 键 ${k} 只在 en 存在，zh 缺失`);
for (const k of zhKeys) if (!enKeys.has(k)) problems.push(`[中等] i18n 键 ${k} 只在 zh 存在，en 缺失`);

// 代码中 t('xxx') 引用的键必须存在
const usedKeys = new Set();
const reUse = /t\(['"]([a-z0-9_]+)['"]\)/g;
let m;
while ((m = reUse.exec(indexHtml))) usedKeys.add(m[1]);
const dynamicPrefixes = /t\('method_' \+|t\('method_'\+/;
for (const k of usedKeys) {
  if (!enKeys.has(k)) problems.push(`[中等] 前端引用了不存在的 i18n 键 t('${k}') → 界面显示原始键名`);
}
// 方法标签 method_<method> 必须齐全
for (const mm of workerMethods) {
  const key = 'method_' + mm;
  if (mm === 'combo') continue;
  if (!enKeys.has(key)) problems.push(`[中等] 缺少 i18n 键 ${key}（en）→ 方法名显示为原始键`);
  if (!zhKeys.has(key)) problems.push(`[中等] 缺少 i18n 键 ${key}（zh）→ 方法名显示为原始键`);
}
// L7 推荐 reason_key 必须齐全
const l7test = read('internal/controller/l7test.go');
const reasonKeys = [...new Set((l7test.match(/"(l7_rec_[a-z0-9_]+)"/g) || []).map((s) => s.replace(/"/g, '')))];
for (const rk of reasonKeys) {
  if (!enKeys.has(rk)) problems.push(`[中等] L7 推荐键 ${rk} 在 en 词典缺失`);
  if (!zhKeys.has(rk)) problems.push(`[中等] L7 推荐键 ${rk} 在 zh 词典缺失`);
}
console.log('L7 推荐 reason 键:', reasonKeys.length);

// ---------- 报告 ----------
console.log('\n=== 问题清单 (' + problems.length + ') ===');
problems.forEach((p) => console.log(p));
if (!problems.length) console.log('未发现一致性问题 ✅');
