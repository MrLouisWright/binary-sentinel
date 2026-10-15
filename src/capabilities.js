// Built-in capabilities live in rules/builtin.yml (capa rule format); this module keeps the old API on top of them.
import { readFileSync } from 'node:fs';
import { parseRules, matchRules } from './capa.js';

/** Built-in compiled rules. */
export const BUILTIN_RULES = parseRules(readFileSync(new URL('../rules/builtin.yml', import.meta.url), 'utf8'), 'builtin');

const apisOf = (n) => (n.op === 'feature' && n.k === 'api' ? [n.v] : (n.kids || []).flatMap(apisOf));
/** Legacy view: [{ id, label, attack, apis }] */
export const CAPABILITIES = BUILTIN_RULES.map((r) => ({ id: r.id, label: r.name, attack: r.techniques[0], apis: apisOf(r.root) }));

const base = (n) => n.replace(/(?<=[a-z0-9])(?:ExA|ExW|Ex|A|W)$/, '').toLowerCase();
/** Map imported function names to built-in capabilities. @param {string[]} names */
export function capabilities(names) {
  const f = { apis: new Set(names.map(base)), qualified: new Set(), exports: new Set(), sections: new Set(), strings: [] };
  return matchRules(BUILTIN_RULES, f).map((m) => {
    const want = new Set(CAPABILITIES.find((c) => c.id === m.id).apis.map(base));
    return { id: m.id, label: m.name, attack: m.techniques[0], apis: [...new Set(names.filter((n) => want.has(base(n))))] };
  });
}
