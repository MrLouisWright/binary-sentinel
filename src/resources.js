// PE resource directory walker and VS_VERSIONINFO parser.
import { createHash } from 'node:crypto';
import { entropy, detectType } from './binfmt.js';

export const RESOURCE_TYPES = { 1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE', 19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST' };

/**
 * Walk the resource tree (type / name / language).
 * @param {Uint8Array} buf  whole file
 * @param {number} dirOffset  file offset of the root IMAGE_RESOURCE_DIRECTORY
 * @param {(rva: number) => number} rva2off
 * @returns {{ type: string, name: string, lang: number, offset: number, size: number, entropy: number, magic: string, sha256: string }[]}
 */
export function parseResources(buf, dirOffset, rva2off, { limit = 4096 } = {}) {
  buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  const out = []; const seen = new Set();
  const nameAt = (o) => { const p = dirOffset + o; if (p + 2 > buf.length) return '?'; const n = buf.readUInt16LE(p); return buf.subarray(p + 2, Math.min(buf.length, p + 2 + n * 2)).toString('utf16le'); };
  const walk = (off, depth, path) => {
    const p = dirOffset + off; if (seen.has(p) || depth > 3 || p + 16 > buf.length || out.length >= limit) return; seen.add(p);
    const count = buf.readUInt16LE(p + 12) + buf.readUInt16LE(p + 14);
    for (let i = 0; i < Math.min(count, 1024); i++) {
      const e = p + 16 + i * 8; if (e + 8 > buf.length) return;
      const nm = buf.readUInt32LE(e); const data = buf.readUInt32LE(e + 4);
      const id = nm & 0x80000000 ? nameAt(nm & 0x7fffffff) : nm;
      if (data & 0x80000000) { walk(data & 0x7fffffff, depth + 1, [...path, id]); continue; }
      const de = dirOffset + data; if (de + 16 > buf.length) continue;
      const rva = buf.readUInt32LE(de); const size = buf.readUInt32LE(de + 4); const fo = rva2off(rva);
      const [t, n] = path; const lang = typeof id === 'number' ? id : 0;
      const ok = fo >= 0 && fo + size <= buf.length; const body = ok ? buf.subarray(fo, fo + size) : Buffer.alloc(0);
      out.push({ type: typeof t === 'number' ? RESOURCE_TYPES[t] || String(t) : String(t ?? id), name: String(n ?? ''), lang, offset: fo, size, truncated: !ok, entropy: entropy(body), magic: detectType(body.subarray(0, 0x10000)), sha256: createHash('sha256').update(body).digest('hex') });
    }
  };
  walk(0, 0, []);
  return out;
}

/**
 * Parse a VS_VERSIONINFO resource.
 * @returns {{ fileVersion?: string, productVersion?: string, strings: Record<string,string> } | null}
 */
export function parseVersionInfo(b) {
  b = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  const align4 = (n) => (n + 3) & ~3;
  const node = (o, end) => {
    if (o + 6 > end) return null;
    const len = b.readUInt16LE(o); const vlen = b.readUInt16LE(o + 2); const type = b.readUInt16LE(o + 4);
    if (len < 6 || o + len > end + 3) return null;
    const stop = Math.min(end, o + len);
    let k = o + 6; let key = ''; while (k + 1 < stop) { const c = b.readUInt16LE(k); k += 2; if (!c) break; key += String.fromCharCode(c); }
    const vo = align4(k); const vbytes = type === 1 ? vlen * 2 : vlen;
    const kids = []; let c = align4(vo + vbytes);
    while (c < stop) { const ch = node(c, stop); if (!ch) break; kids.push(ch); c = align4(c + ch.len); }
    return { key, len, type, value: b.subarray(vo, Math.min(stop, vo + vbytes)), kids };
  };
  const root = node(0, b.length);
  if (!root || root.key !== 'VS_VERSION_INFO') return null;
  const out = { strings: {} };
  if (root.value.length >= 52 && root.value.readUInt32LE(0) === 0xfeef04bd) {
    const v = (ms, ls) => `${ms >>> 16}.${ms & 0xffff}.${ls >>> 16}.${ls & 0xffff}`;
    out.fileVersion = v(root.value.readUInt32LE(8), root.value.readUInt32LE(12));
    out.productVersion = v(root.value.readUInt32LE(16), root.value.readUInt32LE(20));
  }
  for (const k of root.kids) if (k.key === 'StringFileInfo') for (const table of k.kids) for (const s of table.kids) out.strings[s.key] = s.value.toString('utf16le').replace(/\0+$/, '');
  return out;
}
