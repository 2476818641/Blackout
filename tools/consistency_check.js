// 交叉一致性检查：攻击方法清单（引擎/白名单/前端）+ i18n 键完整性
//
// 单一事实来源：internal/attack/dispatch.go
//   - StartMethod()        worker 单任务执行 + combo 子攻击(委托) 的分派表
//   - SupportedMethods()   Controller validMethods 白名单由此派生
// 本脚本校验所有派生点与 Rust lw-worker、前端下拉、i18n 词典保持一致。
//
// 用法: node tools/consistency_check.js   （退出码 1 = 存在问题）
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

const problems = [];
const add = (sev, msg) => problems.push(`[${sev}] ${msg}`);

// ---------- 工具 ----------
// Go: switch 的所有 case 字面量（marker 起到函数结束）
const switchCases = (src, marker) => {
  const start = src.indexOf(marker);
  if (start < 0) return [];
  let end = src.indexOf('\nfunc ', start + 10);
  if (end < 0) end = src.length;
  const out = new Set();
  const re = /case\s+((?:"[^"]+"\s*,?\s*)+):/g;
  let m;
  while ((m = re.exec(src.slice(start, end)))) {
    (m[1].match(/"([^"]+)"/g) || []).forEach((q) => out.add(q.replace(/"/g, '')));
  }
  return [...out];
};
const namedFuncBody = (src, sig) => {
  const i = src.indexOf(sig);
  if (i < 0) return '';
  const open = src.indexOf('{', i);
  const close = src.indexOf('\n}', open);
  return src.slice(open, close < 0 ? src.length : close);
};
const diff = (a, b) => [...a].filter((x) => !b.has(x));

// ---------- 1. 引擎清单（单一事实来源） ----------
const dispatch = read('internal/attack/dispatch.go');
const workerBlock = read('internal/worker/worker.go');
const combo = read('internal/attack/combo.go');
const controller = read('internal/controller/controller.go');
const lwGo = read('internal/controller/lw.go');
const lwRust = read('lw-worker/src/heartbeat.rs');
const indexHtml = read('web/static/index.html');
const poolHtml = read('web/static/pool.html');

const dispatchMethods = new Set(switchCases(dispatch, 'switch cfg.Method {'));
const supBody = namedFuncBody(dispatch, 'func SupportedMethods()');
const supported = new Set((supBody.match(/"([a-z0-9_]+)"/g) || []).map((s) => s.replace(/"/g, '')));

console.log('=== 引擎清单 ===');
console.log('dispatch.go 可执行:', dispatchMethods.size, '| SupportedMethods():', supported.size);

for (const m of diff(dispatchMethods, supported)) {
  add('严重', `dispatch.go 可执行 ${m} 但 SupportedMethods() 未列出 → Controller 白名单缺失，创建任务被拒 "unknown method"`);
}
for (const m of diff(supported, dispatchMethods)) {
  add('严重', `SupportedMethods() 列出 ${m} 但 dispatch.go 无分派 → 创建任务成功但 worker 静默不执行`);
}

// worker 单任务必须走统一分派（否则新增方法会漏）
if (!/attack\.StartMethod\(/.test(workerBlock)) {
  add('严重', 'worker.go 未调用 attack.StartMethod → 单任务分派可能再次漏方法');
}

// ---------- 2. Controller 白名单 ----------
let validMethods;
const validDecl = /var validMethods = func\(\)[\s\S]*?\}\(\)/.exec(controller);
if (validDecl && validDecl[0].includes('attack.SupportedMethods()')) {
  validMethods = new Set([...supported, 'combo']); // 派生：与引擎清单恒等
} else {
  add('严重', 'controller validMethods 未由 attack.SupportedMethods() 派生 → 硬编码清单会与引擎脱节');
  validMethods = new Set((controller.match(/"([a-z0-9_]+)":\s*true/g) || []).map((s) => s.match(/"([^"]+)"/)[1]));
}

// ---------- 3. combo 子攻击分派 ----------
const comboDelegates = /func subAttackMethodToFunc[\s\S]*?StartMethod\(/.test(combo);
if (!comboDelegates) {
  add('严重', 'combo.subAttackMethodToFunc 未委托 attack.StartMethod → 组合攻击会漏新方法');
}
const comboMethods = new Set(comboDelegates ? supported : switchCases(combo, 'switch cfg.Method {'));

// ---------- 4. lw（Rust）能力范围 ----------
const lwGoBlock = namedFuncBody(lwGo, 'func lwCapableMethod');
const lwGoMethods = new Set((lwGoBlock.match(/==\s*"([a-z0-9_]+)"/g) || []).map((s) => s.match(/"([^"]+)"/)[1]));
const rustBlock = namedFuncBody(lwRust, 'fn run_task');
const lwRustMethods = new Set((rustBlock.match(/method\s*!=\s*"([a-z0-9_]+)"/g) || []).map((s) => s.match(/"([^"]+)"/)[1]));

console.log('=== lw 能力 ===');
console.log('controller 认定:', [...lwGoMethods].join(',') || '(无)', '| lw-worker 实现:', [...lwRustMethods].join(',') || '(无)');

for (const m of diff(lwGoMethods, lwRustMethods)) {
  add('严重', `Controller 会把 ${m} 派给 lw 节点，但 lw-worker 不支持 → 任务永远等不到该节点上报完成`);
}
for (const m of diff(lwRustMethods, lwGoMethods)) {
  add('中等', `lw-worker 支持 ${m} 但 Controller 不会派发 → 能力浪费`);
}
for (const m of lwGoMethods) {
  if (!dispatchMethods.has(m)) add('严重', `lwCapableMethod 含 ${m} 但引擎无此分派`);
}

// ---------- 5. 前端下拉 ----------
const selectBlock = (html, selector) => {
  const i = html.indexOf(selector);
  if (i < 0) return '';
  const end = html.indexOf('</select>', i);
  return html.slice(i, end < 0 ? html.length : end);
};
const optsIn = (block) => new Set((block.match(/<option value="([a-z0-9_]+)"/g) || []).map((s) => s.match(/value="([^"]+)"/)[1]));
const uiMethods = optsIn(selectBlock(indexHtml, '<select x-model="form.method">'));
const uiSubMethods = optsIn(selectBlock(indexHtml, '<select x-model="sub.method"'));

console.log('=== 前端清单 ===');
console.log('主下拉:', uiMethods.size, '| 子攻击下拉:', uiSubMethods.size, '| i18n 引用:', (indexHtml.match(/t\('/g) || []).length);

for (const m of diff(supported, uiMethods)) {
  add('中等', `引擎支持 ${m} 但前端主下拉缺失 → 面板无法选择该方法`);
}
for (const m of diff(uiMethods, new Set([...supported, 'combo']))) {
  add('严重', `前端主下拉含 ${m} 但引擎不支持 → 选择后创建任务被拒或静默不执行`);
}
for (const m of diff(supported, uiSubMethods)) {
  add('中等', `引擎支持 ${m} 但前端 combo 子攻击下拉缺失 → 组合攻击无法配置该方法`);
}

// ---------- 6. i18n 键完整性 ----------
const trStart = indexHtml.indexOf('const TR = {');
const trBlock = indexHtml.slice(trStart, indexHtml.indexOf('return {', trStart));
// 按大括号配对提取某个语言词典（避免把 `zh: {` 自身的 zh 当成词条）
const dictBody = (block, name) => {
  const i = block.indexOf(`${name}: {`);
  if (i < 0) return '';
  const open = block.indexOf('{', i);
  let depth = 0;
  for (let j = open; j < block.length; j++) {
    if (block[j] === '{') depth++;
    else if (block[j] === '}') {
      depth--;
      if (depth === 0) return block.slice(open + 1, j);
    }
  }
  return block.slice(open + 1);
};
// 提取顶层键名：必须跳过字符串字面量，否则 "Attack failed:" / "gRPC port:"
// 这类值里的 "word:" 会被误判成词条（历史误报：failed/port/target/users）。
const keysOf = (block) => {
  const out = new Set();
  const isWord = (c) => c !== undefined && /[A-Za-z0-9_]/.test(c);
  let depth = 0;
  let i = 0;
  while (i < block.length) {
    const ch = block[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      i++;
      while (i < block.length) {
        if (block[i] === '\\') { i += 2; continue; }
        if (block[i] === ch) { i++; break; }
        i++;
      }
      continue;
    }
    if (ch === '{' || ch === '[') { depth++; i++; continue; }
    if (ch === '}' || ch === ']') { depth--; i++; continue; }
    if (depth === 0 && /[a-z]/i.test(ch) && !isWord(block[i - 1])) {
      let j = i;
      while (j < block.length && isWord(block[j])) j++;
      const name = block.slice(i, j);
      let k = j;
      while (k < block.length && /\s/.test(block[k])) k++;
      if (block[k] === ':') out.add(name);
      i = j;
      continue;
    }
    i++;
  }
  return out;
};
const enKeys = keysOf(dictBody(trBlock, 'en'));
const zhKeys = keysOf(dictBody(trBlock, 'zh'));

console.log('=== i18n ===');
console.log('en 键:', enKeys.size, '| zh 键:', zhKeys.size);

for (const k of diff(enKeys, zhKeys)) add('中等', `i18n 键 ${k} 只在 en 存在，zh 缺失`);
for (const k of diff(zhKeys, enKeys)) add('中等', `i18n 键 ${k} 只在 zh 存在，en 缺失`);

// 代码引用（静态 t('key')）必须在词典里存在。
// 前置断言排除 createElement('a') 里的 "t('a')" 这类误匹配。
const refsOf = (html) =>
  new Set((html.match(/(?<![A-Za-z0-9_$.])t\(['"]([a-z0-9_]+)['"]\)/g) || []).map((s) => s.match(/['"]([a-z0-9_]+)['"]/)[1]));
const checkRefs = (html, label, en, zh) => {
  for (const k of refsOf(html)) {
    if (!en.has(k) && !zh.has(k)) add('中等', `${label} 引用不存在的 i18n 键 t('${k}') → 界面显示原始键名`);
  }
};
checkRefs(indexHtml, 'index.html', enKeys, zhKeys);

// pool.html 独立词典（历史事故：t('refreshing') 键不存在）
const poolTrStart = poolHtml.indexOf('const TR = {');
const poolTr = poolHtml.slice(poolTrStart, poolHtml.indexOf('return {', poolTrStart));
const poolKeys = new Set([...keysOf(dictBody(poolTr, 'en')), ...keysOf(dictBody(poolTr, 'zh'))]);
for (const k of refsOf(poolHtml)) {
  if (!poolKeys.has(k)) add('中等', `pool.html 引用不存在的 i18n 键 t('${k}') → 界面显示原始键名`);
}

// 方法标签 method_<method> 必须齐全（两种语言）
for (const m of supported) {
  const key = 'method_' + m;
  if (!enKeys.has(key)) add('中等', `缺少 i18n 键 ${key}（en）→ 方法名显示为原始键`);
  if (!zhKeys.has(key)) add('中等', `缺少 i18n 键 ${key}（zh）→ 方法名显示为原始键`);
}
// 前端下拉里出现的 value 也必须有标签键（防止下拉漏翻译）
for (const m of uiMethods) {
  if (m === 'combo') continue;
  if (!enKeys.has('method_' + m)) add('中等', `主下拉 ${m} 缺少 i18n 键 method_${m}`);
}

// L7 推荐 reason_key 必须齐全
const l7test = read('internal/controller/l7test.go');
const reasonKeys = [...new Set((l7test.match(/"(l7_rec_[a-z0-9_]+)"/g) || []).map((s) => s.replace(/"/g, '')))];
for (const rk of reasonKeys) {
  if (!enKeys.has(rk)) add('中等', `L7 推荐键 ${rk} 在 en 词典缺失`);
  if (!zhKeys.has(rk)) add('中等', `L7 推荐键 ${rk} 在 zh 词典缺失`);
}
console.log('L7 推荐 reason 键:', reasonKeys.length);

// ---------- 报告 ----------
console.log('\n=== 问题清单 (' + problems.length + ') ===');
problems.forEach((p) => console.log(p));
if (!problems.length) console.log('未发现一致性问题 ✅');
process.exit(problems.length ? 1 : 0);
