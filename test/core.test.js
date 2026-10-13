import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, validateConfig, ConfigError, globRe } from '../src/core.js';

const tool = { name: 'x-sentinel', version: '1.0.0', rules: { 'r-high': { severity: 'high', title: 'High rule', group: 'g' }, 'r-low': { severity: 'low', title: 'Low rule', group: 'g' } } };
const raw = () => [{ target: 'a.txt', raw: [{ rule: 'r-high', message: 'bad thing', location: 'a.txt:3', file: 'a.txt', line: 3, fix: 'fix it', evidence: 'evil' }, { rule: 'r-low', message: 'meh' }] }];
const NOW = '2026-10-14T00:00:00Z';

test('core: default severities, counts and exit codes', () => {
  const r = buildReport(tool, raw(), { now: NOW });
  assert.equal(r.findings.length, 2);
  assert.equal(r.counts.high, 1); assert.equal(r.counts.low, 1);
  assert.equal(exceeds(r, 'high'), true); assert.equal(exceeds(r, 'critical'), false); assert.equal(exceeds(r, 'none'), false);
  assert.equal(exitCode(r, 'high'), 1); assert.equal(exitCode(r, 'critical'), 0);
  assert.equal(exitCode(buildReport(tool, [{ target: 'z', fatal: true, raw: [], errors: ['boom'] }], { now: NOW }), 'none'), 2);
});

test('core: per-rule severity override and off', () => {
  const r = buildReport(tool, raw(), { now: NOW, severity: { 'r-high': 'critical', 'r-low': 'off' } });
  assert.deepEqual(r.findings.map((f) => [f.rule, f.severity]), [['r-high', 'critical']]);
});

test('core: allowlist suppresses, expires and reports unused', () => {
  let r = buildReport(tool, raw(), { now: NOW, allow: [{ rule: 'r-high', match: 'evil', reason: 'accepted', expires: '2027-01-01' }] });
  assert.equal(r.suppressed.length, 1); assert.equal(r.suppressed[0].allowedBy.reason, 'accepted');
  assert.ok(!r.findings.some((f) => f.rule === 'r-high'));
  r = buildReport(tool, raw(), { now: NOW, allow: [{ rule: 'r-*', target: 'a.txt', reason: 'old', expires: '2026-01-01' }] });
  assert.ok(r.findings.some((f) => f.rule === 'allow-expired'));
  assert.ok(r.findings.some((f) => f.rule === 'r-high'));
  r = buildReport(tool, raw(), { now: NOW, allow: [{ rule: 'nothing', reason: 'x' }] });
  assert.ok(r.findings.some((f) => f.rule === 'allow-unused'));
});

test('core: config validation', () => {
  assert.throws(() => validateConfig({ allow: [{ rule: 'x' }] }), ConfigError);
  assert.throws(() => validateConfig({ allow: [{ rule: 'x', reason: 'y', expires: '14/10/2026' }] }), ConfigError);
  assert.throws(() => validateConfig({ severity: { nope: 'high' } }, tool.rules), ConfigError);
  assert.throws(() => validateConfig({ severity: { 'r-high': 'urgent' } }, tool.rules), ConfigError);
  assert.throws(() => validateConfig({ failOn: 'bad' }), ConfigError);
  assert.doesNotThrow(() => validateConfig({ allow: [{ rule: 'r-*', reason: 'ok', expires: '2030-01-01' }], severity: { 'r-low': 'off' }, failOn: 'none' }, tool.rules));
  assert.ok(globRe('a*.txt').test('abc.txt')); assert.ok(!globRe('a?.txt').test('abc.txt'));
});

test('core: formatters', () => {
  const r = buildReport(tool, raw(), { now: NOW });
  assert.match(formatText(r, { failOn: 'high' }), /HIGH\s+a\.txt:3 {2}bad thing \[r-high\][\s\S]*Failing/);
  assert.equal(JSON.parse(formatJson(r)).findings.length, 2);
  const s = JSON.parse(formatSarif(r, tool));
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
  assert.ok(s.runs[0].tool.driver.rules.some((x) => x.id === 'allow-expired'));
  const md = formatMarkdown(r, { failOn: 'critical' });
  assert.match(md, /\| high \| `a\.txt:3` \| `r-high` \|/); assert.match(md, /Passing/);
});
