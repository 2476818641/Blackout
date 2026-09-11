// 检查 .layout 容器的闭合位置：面板是否落在 grid 容器之外
const fs = require('fs');
const lines = fs.readFileSync(require('path').resolve(__dirname, '..', 'web', 'static', 'index.html'), 'utf8').split('\n');
let depth = 0, started = false, startLine = 0;
for (let i = 0; i < lines.length; i++) {
  const l = lines[i];
  if (!started && l.includes('class="layout"')) { started = true; startLine = i + 1; }
  if (!started) continue;
  const opens = (l.match(/<div/g) || []).length;
  const closes = (l.match(/<\/div>/g) || []).length;
  depth += opens - closes;
  if (opens || closes) {
    if (depth <= 0) {
      console.log('layout 闭合于第', i + 1, '行 (开于', startLine, '):', l.trim().substring(0, 70));
      break;
    }
  }
}
console.log('--- 关键面板起始行 ---');
lines.forEach((l, i) => {
  if (l.includes('<!-- Attack Logs') || l.includes('<!-- Operation Audit') || l.includes('<!-- Tasks') || l.includes('<!-- Nodes') || l.includes('<!-- Target Guard')) {
    console.log(i + 1, ':', l.trim());
  }
});
