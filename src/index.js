import { readFileSync, statSync, readdirSync, openSync, readSync, closeSync } from 'node:fs';
import { join, relative } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { parsePE, parseELF, parseBinary, detectType, entropy, hashes, PACKER_SECTIONS } from './binfmt.js';
import { capabilities, CAPABILITIES } from './capabilities.js';
import { analyzeBuffer, peChecksum } from './analyze.js';

export { parsePE, parseELF, parseBinary, detectType, entropy, hashes, PACKER_SECTIONS, capabilities, CAPABILITIES, analyzeBuffer, peChecksum, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'binary-sentinel', version: VERSION, rules: RULES, title: 'binary-sentinel', emoji: '🧬', defaultFailOn: 'high' };
export const PROFILES = {
  triage: {},
  hardening: { 'no-aslr': 'high', 'no-nx': 'high', 'no-relro': 'medium', 'no-canary': 'medium', 'no-cfg': 'low', 'unsafe-rpath': 'high', 'rwx-section': 'high', 'suspicious-imports': 'info', 'injection-imports': 'info', 'checksum-mismatch': 'info', 'timestamp-anomaly': 'info', overlay: 'info' },
};
const MAX = 512 * 1024 * 1024;
const SKIP = new Set(['.git', 'node_modules']);
function walk(p, out = []) {
  const st = statSync(p);
  if (st.isDirectory()) { for (const e of readdirSync(p).sort()) if (!SKIP.has(e)) walk(join(p, e), out); } else if (st.isFile()) out.push(p);
  return out;
}
function magicOf(f) { const fd = openSync(f, 'r'); const b = Buffer.alloc(0x200); const n = readSync(fd, b, 0, 0x200, 0); closeSync(fd); return b.subarray(0, n); }
const isExe = (b) => b.length >= 4 && (b.toString('latin1', 0, 2) === 'MZ' || b.toString('latin1', 0, 4) === '\x7fELF' || [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(b.readUInt32BE(0)));

/**
 * Triage files or directories. Directories are searched for PE/ELF/Mach-O files by magic bytes.
 * @param {(string|{name:string,buffer:Uint8Array})[]} inputs
 */
export function triage(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const profile = PROFILES[opts.profile || 'triage'];
  if (!profile) throw new ConfigError(`Unknown profile "${opts.profile}" (have ${Object.keys(PROFILES).join(', ')})`);
  const results = [];
  for (const inp of inputs) {
    if (typeof inp === 'object') { results.push(one(inp.name, Buffer.from(inp.buffer))); continue; }
    let files, dir;
    try { dir = statSync(inp).isDirectory(); files = walk(inp); } catch (e) { results.push({ target: inp, fatal: true, raw: [], errors: [`Cannot read ${inp}: ${e.code || e.message}`] }); continue; }
    for (const f of files) {
      if (dir && !isExe(magicOf(f))) continue;
      if (statSync(f).size > MAX) { results.push({ target: f, raw: [], errors: ['larger than 512 MB, skipped'] }); continue; }
      const r = one(relative(process.cwd(), f) || f, readFileSync(f));
      if (!(dir && r.skipped)) results.push(r);
    }
  }
  function one(name, buf) {
    const a = analyzeBuffer(buf, name, opts);
    return { target: name, summary: a.summary, data: opts.details ? a.info : undefined, raw: a.raw, errors: [], skipped: a.skipped };
  }
  return buildReport(TOOL, results, { ...opts, severity: { ...profile, ...(opts.severity || {}) } });
}
