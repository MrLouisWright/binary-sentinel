// Shared report engine: rules, policy (allowlist with expiry, per-rule severity), formatters and exit codes.
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const rank = (s) => { const i = SEVERITIES.indexOf(s); return i === -1 ? 99 : i; };
export class ConfigError extends Error {}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
export function globRe(g) {
  if (g === undefined || g === null || g === '') return /^.*$/s;
  return new RegExp('^' + String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'is');
}

/** Validate a config object's shared keys (allow, severity, failOn). Throws ConfigError. */
export function validateConfig(cfg, rules) {
  if (cfg === null || typeof cfg !== 'object' || Array.isArray(cfg)) throw new ConfigError('config must be a JSON object');
  if (cfg.allow !== undefined) {
    if (!Array.isArray(cfg.allow)) throw new ConfigError('"allow" must be an array');
    cfg.allow.forEach((a, i) => {
      if (!a || typeof a !== 'object') throw new ConfigError(`allow[${i}] must be an object`);
      if (!a.rule) throw new ConfigError(`allow[${i}] needs a "rule" (glob ok)`);
      if (!a.reason) throw new ConfigError(`allow[${i}] needs a "reason"`);
      if (a.expires !== undefined && !DATE.test(String(a.expires))) throw new ConfigError(`allow[${i}].expires must be YYYY-MM-DD`);
    });
  }
  if (cfg.severity !== undefined) {
    if (typeof cfg.severity !== 'object' || Array.isArray(cfg.severity)) throw new ConfigError('"severity" must be an object of rule -> severity');
    for (const [k, v] of Object.entries(cfg.severity)) {
      if (rules && !rules[k]) throw new ConfigError(`severity: unknown rule "${k}"`);
      if (v !== 'off' && !SEVERITIES.includes(v)) throw new ConfigError(`severity.${k}: "${v}" is not one of ${SEVERITIES.join(', ')}, off`);
    }
  }
  if (cfg.failOn !== undefined && cfg.failOn !== 'none' && !SEVERITIES.includes(cfg.failOn)) throw new ConfigError(`failOn: invalid severity "${cfg.failOn}"`);
  return cfg;
}

export const ALLOW_RULES = {
  'allow-expired': { severity: 'medium', title: 'Allowlist entry has expired', group: 'policy' },
  'allow-unused': { severity: 'info', title: 'Allowlist entry matched nothing', group: 'policy' },
};

/**
 * Build a report from raw per-target results.
 * results: [{ target, summary?, raw: [finding], errors?: [string], fatal?: bool, data?: any }]
 * finding: { rule, severity?, target?, location?, file?, line?, message, fix?, evidence? }
 */
export function buildReport(tool, results, opts = {}) {
  const rules = { ...tool.rules, ...ALLOW_RULES };
  const now = opts.now ? new Date(opts.now) : new Date();
  const today = now.toISOString().slice(0, 10);
  const allow = (opts.allow || []).map((a) => ({ ...a, used: false, expired: !!(a.expires && a.expires < today) }));
  const sev = opts.severity || {};
  const pick = (rule, dflt) => (sev[rule] && sev[rule] !== 'off' ? sev[rule] : dflt);
  const findings = []; const suppressed = []; const targets = [];
  for (const t of results) {
    const out = [];
    for (const raw of t.raw || []) {
      if (sev[raw.rule] === 'off') continue;
      const f = { ...raw, target: raw.target ?? t.target, severity: pick(raw.rule, raw.severity || rules[raw.rule]?.severity || 'medium') };
      const hay = [f.target, f.location, f.file, f.evidence, f.value].filter((x) => x !== undefined).map(String);
      const a = allow.find((x) => globRe(x.rule).test(f.rule) && (!x.target || globRe(x.target).test(String(f.target))) && (!x.match || hay.some((h) => globRe(x.match).test(h))));
      if (a && !a.expired) { a.used = true; suppressed.push({ ...f, allowedBy: { reason: a.reason, ...(a.expires ? { expires: a.expires } : {}) } }); continue; }
      if (a && a.expired) {
        a.used = true;
        if (sev['allow-expired'] !== 'off') out.push({ rule: 'allow-expired', severity: pick('allow-expired', 'medium'), target: f.target, location: f.location, message: `Allowlist entry for ${a.rule}${a.match ? ` (${a.match})` : ''} expired on ${a.expires} ("${a.reason}")`, fix: 'Re-review the finding, then fix it or extend "expires".' });
      }
      out.push(f);
    }
    out.sort((x, y) => rank(x.severity) - rank(y.severity) || x.rule.localeCompare(y.rule) || (x.line ?? 0) - (y.line ?? 0));
    findings.push(...out);
    targets.push({ target: t.target, ...(t.fatal ? { fatal: true } : {}), ...(t.summary ? { summary: t.summary } : {}), ...(t.data !== undefined ? { data: t.data } : {}), findings: out, errors: t.errors || [] });
  }
  if (opts.reportUnusedAllow !== false && sev['allow-unused'] !== 'off') {
    for (const a of allow) if (!a.used) {
      const f = { rule: 'allow-unused', severity: pick('allow-unused', 'info'), target: a.target || '*', message: `Allowlist entry for ${a.rule}${a.match ? ` (${a.match})` : ''} matched nothing`, fix: 'Remove the stale entry from the config.' };
      findings.push(f); (targets[0] || { findings: [] }).findings.push(f);
    }
  }
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return {
    tool: tool.name, version: tool.version, generatedAt: now.toISOString(),
    ...(opts.meta || {}),
    targets, findings, suppressed, counts,
    errors: targets.flatMap((t) => t.errors.map((e) => ({ target: t.target, error: e }))),
  };
}

export function exceeds(report, failOn = 'high') {
  if (!failOn || failOn === 'none') return false;
  return report.findings.some((f) => rank(f.severity) <= rank(failOn));
}
export function exitCode(report, failOn) {
  if (report.targets.some((t) => t.fatal)) return 2;
  return exceeds(report, failOn) ? 1 : 0;
}

const C = { critical: '\x1b[35;1m', high: '\x1b[31;1m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[2m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m' };
const countLine = (counts) => SEVERITIES.filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(', ') || 'no findings';
const loc = (f) => f.location || (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
function summaryLines(s) {
  if (!s) return [];
  return Object.entries(s).filter(([, v]) => v !== undefined && v !== null && !(Array.isArray(v) && !v.length)).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : v}`);
}

export function formatText(r, { color = false, failOn, fixes = true } = {}) {
  const c = (k, s) => (color ? `${C[k]}${s}${C.reset}` : s);
  const l = [c('bold', `${r.tool} — ${r.targets.length} target(s)`), ''];
  for (const t of r.targets) {
    l.push(c('bold', t.target));
    for (const o of summaryLines(t.summary)) l.push(c('dim', `  ${o}`));
    for (const e of t.errors) l.push(c('red', `  ✖ ${e}`));
    for (const f of t.findings) {
      const where = loc(f);
      l.push(`  ${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${where ? `${where}  ` : ''}${f.message} [${f.rule}]`);
      if (f.evidence) l.push(c('dim', `           ↳ ${String(f.evidence).slice(0, 200)}`));
      if (fixes && f.fix) l.push(c('dim', `           ↳ fix: ${f.fix}`));
    }
    if (!t.findings.length && !t.errors.length) l.push(c('green', '  ✔ no findings'));
    l.push('');
  }
  if (r.suppressed.length) l.push(c('dim', `${r.suppressed.length} finding(s) suppressed by allowlist`));
  l.push(countLine(r.counts));
  if (failOn) l.push(exceeds(r, failOn) ? c('red', `✖ Failing (fail-on: ${failOn}).`) : c('green', `✔ Passing (fail-on: ${failOn}).`));
  return l.join('\n') + '\n';
}

export const formatJson = (r) => JSON.stringify(r, null, 2) + '\n';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE = { critical: '9.5', high: '7.5', medium: '5.0', low: '3.0', info: '1.0' };
const isFileish = (s) => s && !/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/\s/.test(s);
export function formatSarif(r, tool) {
  const rules = { ...tool.rules, ...ALLOW_RULES };
  const ids = Object.keys(rules);
  const uri = `https://github.com/MrLouisWright/${tool.name}`;
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: tool.name, version: tool.version, informationUri: uri, rules: ids.map((id) => ({ id, name: id.replace(/(^|-)(\w)/g, (_, __, ch) => ch.toUpperCase()), shortDescription: { text: rules[id].title }, helpUri: `${uri}#rules`, defaultConfiguration: { level: LEVEL[rules[id].severity] }, properties: { tags: ['security', rules[id].group || tool.name], 'security-severity': SCORE[rules[id].severity] } })) } },
      results: r.findings.map((f) => {
        const file = f.file || (isFileish(f.target) ? f.target : undefined);
        const physical = file ? { artifactLocation: { uri: String(file).replace(/\\/g, '/').replace(/^\.\//, '') }, ...(f.line ? { region: { startLine: f.line } } : {}) } : { artifactLocation: { uri: String(f.target) } };
        return { ruleId: f.rule, ruleIndex: Math.max(0, ids.indexOf(f.rule)), level: LEVEL[f.severity], message: { text: `${f.message}${f.fix ? `. Fix: ${f.fix}` : ''}` }, locations: [{ physicalLocation: physical, ...(f.location ? { logicalLocations: [{ name: String(f.location) }] } : {}) }], partialFingerprints: { [`${tool.name}/v1`]: `${f.rule}:${f.target}:${f.location ?? f.line ?? ''}:${f.evidence ?? ''}`.slice(0, 500) }, properties: { severity: f.severity, 'security-severity': SCORE[f.severity] } };
      }),
    }],
  }, null, 2) + '\n';
}

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ').replace(/</g, '&lt;');
export function formatMarkdown(r, { failOn, title, emoji = '🛡️' } = {}) {
  const l = [`## ${emoji} ${title || r.tool}`, '', `Checked **${r.targets.length}** target(s): ${countLine(r.counts)}.`];
  if (failOn) l.push('', exceeds(r, failOn) ? `❌ Failing at \`--fail-on ${failOn}\`.` : `✅ Passing at \`--fail-on ${failOn}\`.`);
  for (const t of r.targets) {
    l.push('', `### ${esc(t.target)}`, '');
    for (const e of t.errors) l.push(`> ⚠️ ${esc(e)}`);
    if (t.findings.length) {
      l.push('| Severity | Location | Rule | Finding | Fix |', '|---|---|---|---|---|');
      for (const f of t.findings) l.push(`| ${f.severity} | ${loc(f) ? `\`${esc(loc(f))}\`` : ''} | \`${f.rule}\` | ${esc(f.message)} | ${esc(f.fix)} |`);
    } else if (!t.errors.length) l.push('✅ No findings.');
    const o = summaryLines(t.summary);
    if (o.length) l.push('', '<details><summary>Summary</summary>', '', ...o.map((x) => `- ${esc(x)}`), '', '</details>');
  }
  if (r.suppressed.length) l.push('', `_${r.suppressed.length} finding(s) suppressed by allowlist._`);
  return l.join('\n') + '\n';
}

export function format(r, tool, fmt, { color, failOn, fixes, title, emoji } = {}) {
  switch (fmt) {
    case 'json': return formatJson(r);
    case 'sarif': return formatSarif(r, tool);
    case 'markdown': case 'md': return formatMarkdown(r, { failOn, title, emoji });
    default: return formatText(r, { color, failOn, fixes });
  }
}
