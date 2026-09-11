// 前端静态检查：内联 JS 语法 + 无外部 CDN 依赖 + 本地资源引用存在
//
// 背景：
//   - 面板是单文件 Alpine 应用，内联 <script> 语法错误会让整个界面白屏，
//     而 Go 侧编译与 go test 都发现不了（HTML 只是被 embed 的字符串）。
//   - dashboard 已改为自托管前端依赖（web/static/vendor），任何重新引入的
//     公网 <script>/<link> 都是供应链风险，必须在此拦住。
//
// 用法: node tools/check_frontend.js   （退出码 1 = 存在问题）
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const pages = ['web/static/index.html', 'web/static/pool.html'];
const problems = [];

for (const page of pages) {
  const html = fs.readFileSync(path.join(root, page), 'utf8');

  // 1. 内联脚本语法
  const inline = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g;
  let m;
  let n = 0;
  while ((m = inline.exec(html))) {
    n++;
    if (!m[1].trim()) continue;
    try {
      new vm.Script(m[1], { filename: `${page}#inline${n}` });
    } catch (e) {
      problems.push(`[严重] ${page} 内联脚本 #${n} 语法错误: ${e.message}`);
    }
  }

  // 2. 不得再有公网依赖（自托管后必须全部同源）
  const remote = /(?:src|href)\s*=\s*["'](https?:)?\/\//g;
  while ((m = remote.exec(html))) {
    problems.push(`[严重] ${page} 引用外部资源（供应链/可用性风险，应自托管）: ${m[0]}`);
  }

  // 3. 本地引用必须真实存在
  const localRef = /(?:src|href)\s*=\s*["'](\/[^"'?#]+)/g;
  const seen = new Set();
  while ((m = localRef.exec(html))) {
    const urlPath = m[1];
    if (seen.has(urlPath)) continue;
    seen.add(urlPath);
    if (urlPath.startsWith('/api/') || urlPath === '/ws' || urlPath === '/pool') continue;
    const file = path.join(root, 'web/static', urlPath.replace(/^\//, ''));
    if (!fs.existsSync(file)) {
      problems.push(`[中等] ${page} 引用了不存在的本地资源: ${urlPath}`);
    }
  }
}

console.log('=== 前端检查 (' + pages.length + ' 个页面) ===');
console.log('已检查：内联 JS 语法 / 外部依赖 / 本地资源引用');
problems.forEach((p) => console.log(p));
if (!problems.length) console.log('未发现问题 ✅');
process.exit(problems.length ? 1 : 0);
