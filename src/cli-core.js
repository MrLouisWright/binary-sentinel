// Shared CLI plumbing: common flags, config loading, output files and exit codes.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { SEVERITIES, ConfigError, validateConfig, format, exitCode, ALLOW_RULES } from './core.js';

export const COMMON_HELP = `Policy and output
  -c, --config <file>        JSON config (default .{NAME}.json if present)
  -f, --format <fmt>         text (default) | json | sarif | markdown
      --json/--sarif/--markdown <file>  Also write that format to a file
      --fail-on <sev>        critical | high | medium | low | info | none (default {FAILON})
      --list-rules           Print rules and default severities
      --no-color             Disable colours
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage error or a target could not be checked.`;

export const list = (v) => (Array.isArray(v) ? v : v === undefined ? [] : [v]).flatMap((x) => String(x).split(',')).map((x) => x.trim()).filter(Boolean);

/**
 * tool: { name, version, rules, title, emoji, defaultFailOn }
 * spec: { help, options, run(values, positionals, cfg, ctx) -> report | { report?, output?, exit? } }
 */
export async function runCli(tool, spec, argv = process.argv.slice(2), io = { stdout: process.stdout, stderr: process.stderr }) {
  const usage = (msg) => { io.stderr.write(`${tool.name}: ${msg}\nRun with --help for usage.\n`); return 2; };
  let a;
  try {
    a = parseArgs({ args: argv, allowPositionals: true, strict: true, options: {
      config: { type: 'string', short: 'c' }, format: { type: 'string', short: 'f' }, json: { type: 'string' }, sarif: { type: 'string' }, markdown: { type: 'string' },
      'fail-on': { type: 'string' }, 'list-rules': { type: 'boolean' }, 'no-color': { type: 'boolean' }, version: { type: 'boolean', short: 'v' }, help: { type: 'boolean', short: 'h' },
      ...spec.options,
    } });
  } catch (e) { return usage(e.message); }
  const { values: o, positionals } = a;
  const dfo = tool.defaultFailOn || 'high';
  if (o.help) { io.stdout.write(spec.help.replace('{COMMON}', COMMON_HELP).replaceAll('{NAME}', tool.name).replace('{FAILON}', dfo).replace('{VERSION}', tool.version) + '\n'); return 0; }
  if (o.version) { io.stdout.write(tool.version + '\n'); return 0; }
  if (o['list-rules']) {
    for (const [id, r] of Object.entries({ ...tool.rules, ...ALLOW_RULES })) io.stdout.write(`${id.padEnd(30)} ${r.severity.padEnd(9)} ${(r.group || '').padEnd(12)} ${r.title}\n`);
    return 0;
  }
  let cfg = {};
  const cfgPath = o.config || (existsSync(`.${tool.name}.json`) ? `.${tool.name}.json` : null);
  if (cfgPath) {
    try { cfg = JSON.parse(readFileSync(cfgPath, 'utf8')); } catch (e) { return usage(`Cannot read config ${cfgPath}: ${e.message}`); }
  }
  try { validateConfig(cfg, { ...tool.rules, ...ALLOW_RULES }); } catch (e) { return usage(`Config error: ${e.message}`); }
  const failOn = o['fail-on'] || cfg.failOn || dfo;
  if (failOn !== 'none' && !SEVERITIES.includes(failOn)) return usage(`Invalid --fail-on: ${failOn}`);
  const fmt = o.format || 'text';
  if (!['text', 'json', 'sarif', 'markdown', ...(spec.formats || [])].includes(fmt)) return usage(`Invalid --format: ${fmt}`);
  const color = !o['no-color'] && io.stdout.isTTY && !process.env.NO_COLOR;
  let res;
  try { res = await spec.run(o, positionals, cfg, { failOn, format: fmt, color, io }); } catch (e) {
    if (e instanceof ConfigError || e?.usage) return usage(e.message);
    throw e;
  }
  if (typeof res === 'number') return res;
  const report = res.report ?? res;
  const opts = { color, failOn, title: tool.title, emoji: tool.emoji };
  if (res.output !== undefined) io.stdout.write(res.output);
  else io.stdout.write(format(report, tool, fmt, opts));
  if (report && report.targets) {
    if (o.json) writeFileSync(o.json, format(report, tool, 'json', opts));
    if (o.sarif) writeFileSync(o.sarif, format(report, tool, 'sarif', opts));
    if (o.markdown) writeFileSync(o.markdown, format(report, tool, 'markdown', opts));
  }
  if (res.exit !== undefined) return res.exit;
  return exitCode(report, failOn);
}

export class UsageError extends Error { constructor(m) { super(m); this.usage = true; } }
