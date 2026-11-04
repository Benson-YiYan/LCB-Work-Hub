const assert = require('node:assert/strict');
const fs = require('node:fs');

const source = fs.readFileSync('app.js', 'utf8');
const start = source.indexOf('function exportCSV(');
const end = source.indexOf('\nasync function fetchBackupRows', start);
assert.ok(start >= 0 && end > start, 'CSV export function must exist');
const exportSource = source.slice(start, end);

assert.match(exportSource, /const head = \['csv\.no', 'csv\.title', 'csv\.client'/, 'matter title must be the second CSV column');
assert.match(exportSource, /m\.no, LCBMatterCompletion\.exportTitle\(L\(m\.title\), m, t\('csv\.completedPrefix'\)\), L\(m\.client\)/, 'CSV row values must follow the reordered headers and prefix the completion marker');

console.log('CSV export column order and completed-title tests passed');
