// capa-style capability rules: a YAML subset parser, a loader and a file-scope matcher.
// Supported features: api, import, export, string, substring, section, format, os, arch, characteristic (embedded pe),
// match (other rules by name or namespace), combined with and / or / not / optional / "N or more". Unsupported features (bytes, number, mnemonic, offset, match...)
// never match and are listed in rule.unsupported. All scopes are evaluated at file level.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

/** Parse the YAML subset used by capa rules (block maps and lists, scalars, quotes, comments, '---' documents). */
export function parseYaml(text) {
  const docs = String(text).replace(/\r\n?/g, '\n').split(/^---[ \t]*$/m);
  return docs.map(parseDoc).filter((d) => d != null);
}
function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) { const c = s[i]; if (q) { if (c === q) q = null; continue; } if (c === '"' || c === "'") q = c; else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i); }
  return s;
}
function scalar(v) {
  v = v.trim();
  if (/^".*"$/.test(v)) return JSON.parse(v.replace(/\\(?!["\\/bfnrtu])/g, '\\\\'));
  if (/^'.*'$/.test(v)) return v.slice(1, -1).replace(/''/g, "'");
  if (v === 'true') return true; if (v === 'false') return false; if (v === 'null' || v === '~' || v === '') return v === '' ? '' : null;
  if (/^-?\d+$/.test(v)) return Number(v);
  if (/^\[.*\]$/.test(v)) return v.slice(1, -1).split(',').map((x) => scalar(x)).filter((x) => x !== '');
  return v;
}
function parseDoc(doc) {
  const lines = doc.split('\n').map((l) => stripComment(l).replace(/\s+$/, '')).map((l) => ({ ind: l.match(/^ */)[0].length, t: l.trim() })).filter((l) => l.t);
  if (!lines.length) return null;
  let i = 0;
  const block = (ind) => (lines[i].t.startsWith('- ') || lines[i].t === '-' ? list(ind) : map(ind));
  const keyval = (t) => { const m = t.match(/^((?:"[^"]*"|'[^']*'|[^:])+?):(?:\s+(.*))?$/); return m ? [scalar(m[1]), m[2]] : null; };
  function map(ind) {
    const o = {};
    while (i < lines.length && lines[i].ind === ind && !lines[i].t.startsWith('- ')) {
      const kv = keyval(lines[i].t); if (!kv) throw new Error(`YAML: cannot parse "${lines[i].t}"`); i++;
      const [k, v] = kv;
      if (v != null && v !== '') o[k] = scalar(v);
      else if (i < lines.length && (lines[i].ind > ind || (lines[i].ind === ind && lines[i].t.startsWith('- ')))) o[k] = block(lines[i].ind);
      else o[k] = null;
    }
    return o;
  }
  function list(ind) {
    const a = [];
    while (i < lines.length && lines[i].ind === ind && (lines[i].t.startsWith('- ') || lines[i].t === '-')) {
      const rest = lines[i].t.slice(1).trim(); const inner = ind + 2;
      if (!rest) { i++; a.push(i < lines.length && lines[i].ind > ind ? block(lines[i].ind) : null); continue; }
      const kv = keyval(rest);
      if (!kv || /^["']/.test(rest) && !kv) { a.push(scalar(rest)); i++; continue; }
      // "- key: value" starts a map whose other keys sit at ind+2
      lines[i] = { ind: inner, t: rest };
      a.push(map(inner));
    }
    return a;
  }
  return block(lines[0].ind);
}

const COMBINATORS = new Set(['and', 'or', 'not', 'optional']);
const SUPPORTED = new Set(['api', 'import', 'export', 'string', 'substring', 'section', 'format', 'os', 'arch', 'characteristic', 'description', 'match']);

/** Normalise a rule document ({ rule: { meta, features } }) into a matcher-ready object. */
export function compileRule(doc, source = '') {
  const r = doc?.rule ?? doc; if (!r?.meta?.name || !r.features) throw new Error(`${source}: rule needs meta.name and features`);
  const meta = r.meta; const unsupported = new Set();
  const attack = [].concat(meta['att&ck'] || meta.attack || []).map(String);
  const node = (f) => {
    if (typeof f !== 'object' || f == null) throw new Error(`${source}: bad feature ${JSON.stringify(f)}`);
    const keys = Object.keys(f).filter((k) => k !== 'description'); const k = keys[0];
    if (!k) return null;
    const v = f[k];
    if (COMBINATORS.has(k)) return { op: k, kids: [].concat(v || []).map(node).filter(Boolean) };
    const nm = String(k).match(/^(\d+) or more$/); if (nm) return { op: 'count', n: Number(nm[1]), kids: [].concat(v || []).map(node).filter(Boolean) };
    if (k === 'count' || /^count\(/.test(k)) { unsupported.add('count'); return { op: 'never' }; }
    if (!SUPPORTED.has(k)) { unsupported.add(k); return { op: 'never' }; }
    let val = typeof v === 'string' ? v.replace(/\s+=\s+.*$/, (m) => (k === 'string' || k === 'substring' ? m : '')) : v;
    if (k === 'string' && typeof val === 'string') { const re = val.match(/^\/(.*)\/([a-z]*)$/s); if (re) return { op: 'feature', k: 'regex', re: new RegExp(re[1], re[2].replace(/[^imsu]/g, '')) }; }
    return { op: 'feature', k, v: String(val) };
  };
  const features = [].concat(r.features).map(node).filter(Boolean);
  const root = features.length === 1 ? features[0] : { op: 'and', kids: features };
  return { name: String(meta.name), id: String(meta.id || meta.name), namespace: meta.namespace || null, attack, techniques: attack.map((a) => a.match(/\[(T\d{4}(?:\.\d{3})?)\]/)?.[1]).filter(Boolean), severity: meta.severity || null, scope: meta.scopes?.static || meta.scope || 'file', root, unsupported: [...unsupported], source };
}

/** Load rules from YAML/JSON text. */
export function parseRules(text, source = 'rules') {
  const docs = /^\s*[[{]/.test(text) ? [].concat(JSON.parse(text)) : parseYaml(text);
  return docs.filter((d) => d && (d.rule || d.meta)).map((d) => compileRule(d, source));
}
/** Load rules from a file or a directory (recursive, *.yml / *.yaml / *.json). */
export function loadRules(path) {
  const st = statSync(path);
  if (st.isDirectory()) return readdirSync(path).sort().flatMap((e) => { const p = join(path, e); return statSync(p).isDirectory() || ['.yml', '.yaml', '.json'].includes(extname(e)) ? loadRules(p) : []; });
  return parseRules(readFileSync(path, 'utf8'), path);
}

const baseApi = (n) => String(n).replace(/^.*[.!]/, '').replace(/(?<=[a-z0-9])(?:ExA|ExW|Ex|A|W)$/, '').toLowerCase();

/**
 * Build the feature set of an analysed file for matching.
 * @param {{ format: string, imports?: any, exports?: any, sections?: any[], segments?: any[], machine?: string }} info  parsed binary
 * @param {Uint8Array} [buf]  raw bytes (for string features)
 */
export function featuresOf(info, buf) {
  const imports = info.format === 'pe' ? info.imports.flatMap((i) => i.functions.map((f) => ({ dll: i.dll.toLowerCase().replace(/\.dll$/, ''), name: f.name || `#${f.ordinal}` }))) : (info.imports || []).map((n) => ({ dll: '', name: n }));
  const exports = info.format === 'pe' ? (info.exports?.names || []).map((e) => (typeof e === 'string' ? e : e.name)) : info.exports || [];
  const sections = [...(info.sections || []).map((s) => s.name), ...(info.segments || []).flatMap((s) => [s.name, ...(s.sections || []).map((x) => x.name)])];
  return {
    format: info.format, os: info.format === 'pe' ? 'windows' : info.format === 'macho' ? 'macos' : 'linux', arch: info.machine,
    apis: new Set(imports.map((i) => baseApi(i.name))), qualified: new Set(imports.map((i) => `${i.dll}.${baseApi(i.name)}`)), importNames: imports.map((i) => i.name),
    exports: new Set(exports.map(String)), sections: new Set(sections.filter(Boolean)), strings: buf ? extractStrings(buf) : [],
    embeddedPe: !!(buf && Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength).indexOf('MZ', 2) > 0 && /This program cannot be run in DOS mode/.test(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength).toString('latin1', 2))),
  };
}

/** ASCII and UTF-16LE strings of at least `min` printable characters. */
export function extractStrings(buf, min = 4, limit = 200000) {
  const b = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength); const out = [];
  const ascii = b.toString('latin1').match(new RegExp(`[\\x20-\\x7e]{${min},}`, 'g')) || [];
  out.push(...ascii.slice(0, limit));
  const wide = b.toString('latin1').match(new RegExp(`(?:[\\x20-\\x7e]\\x00){${min},}`, 'g')) || [];
  out.push(...wide.slice(0, limit).map((s) => s.replace(/\x00/g, '')));
  return out;
}

function evalNode(n, f, hits) {
  switch (n.op) {
    case 'and': return n.kids.every((k) => evalNode(k, f, hits));
    case 'or': { let any = false; for (const k of n.kids) if (evalNode(k, f, hits)) any = true; return any; }
    case 'not': return !n.kids.every((k) => evalNode(k, f, []));
    case 'optional': n.kids.forEach((k) => evalNode(k, f, hits)); return true;
    case 'count': return n.kids.filter((k) => evalNode(k, f, hits)).length >= n.n;
    case 'never': return false;
    case 'feature': {
      const v = n.v; let ok = false;
      if (n.k === 'api' || n.k === 'import') { const q = v.includes('.') ? `${v.toLowerCase().replace(/\.dll(?=\.)/, '').replace(/\.[^.]*$/, '')}.${baseApi(v)}` : null; ok = q ? f.qualified.has(q) || (!f.qualified.size && f.apis.has(baseApi(v))) : f.apis.has(baseApi(v)); if (ok) hits.push(`${n.k}: ${v}`); }
      else if (n.k === 'export') { ok = f.exports.has(v); if (ok) hits.push(`export: ${v}`); }
      else if (n.k === 'section') { ok = f.sections.has(v); if (ok) hits.push(`section: ${v}`); }
      else if (n.k === 'string') { ok = f.strings.includes(v); if (ok) hits.push(`string: "${v}"`); }
      else if (n.k === 'substring') { const s = f.strings.find((x) => x.includes(v)); ok = !!s; if (ok) hits.push(`substring: "${v}"`); }
      else if (n.k === 'regex') { const s = f.strings.find((x) => n.re.test(x)); ok = !!s; if (ok) hits.push(`string: "${s.slice(0, 80)}"`); }
      else if (n.k === 'format') ok = f.format === v.toLowerCase();
      else if (n.k === 'os') ok = f.os === v.toLowerCase() || v === 'any';
      else if (n.k === 'arch') ok = String(f.arch).toLowerCase() === v.toLowerCase().replace('i386', 'i386') || v === 'any';
      else if (n.k === 'match') { ok = f.matched?.has(v) || [...(f.matchedNs || [])].some((ns) => ns === v || ns.startsWith(`${v}/`)); if (ok) hits.push(`match: ${v}`); }
      else if (n.k === 'characteristic') ok = v === 'embedded pe' ? f.embeddedPe : false;
      return ok;
    }
    default: return false;
  }
}

/**
 * Match compiled rules against a feature set.
 * @returns {{ id: string, name: string, namespace: string|null, attack: string[], techniques: string[], evidence: string[], severity: string|null, source: string }[]}
 */
export function matchRules(rules, features) {
  const f = { ...features, matched: new Set(), matchedNs: new Set() }; const done = new Map();
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const r of rules) {
      if (done.has(r)) continue;
      const hits = [];
      if (evalNode(r.root, f, hits)) { done.set(r, hits); f.matched.add(r.name); if (r.namespace) f.matchedNs.add(r.namespace); changed = true; }
    }
    if (!changed) break;
  }
  return rules.filter((r) => done.has(r)).map((r) => ({ id: r.id, name: r.name, namespace: r.namespace, attack: r.attack, techniques: r.techniques, evidence: [...new Set(done.get(r))], severity: r.severity, source: r.source }));
}
