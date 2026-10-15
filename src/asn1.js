// Minimal DER reader (enough for PKCS#7 / Authenticode). Never throws past parse(): callers catch.

/** @typedef {{ tag: number, cls: number, constructed: boolean, start: number, hdr: number, len: number, end: number, buf: Uint8Array }} Node */

/** Parse one DER element at offset. */
export function parse(buf, off = 0, limit = buf.length) {
  if (off + 2 > limit) throw new Error('ASN.1: truncated header');
  const t = buf[off]; let p = off + 1;
  let tag = t & 0x1f; if (tag === 0x1f) { tag = 0; let b; do { b = buf[p++]; tag = (tag << 7) | (b & 0x7f); } while (b & 0x80 && p < limit); }
  let len = buf[p++];
  if (len & 0x80) { const n = len & 0x7f; if (!n || n > 4) throw new Error('ASN.1: unsupported length'); len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[p++]; }
  const end = p + len; if (end > limit) throw new Error('ASN.1: element runs past its parent');
  return { tag, cls: t >> 6, constructed: !!(t & 0x20), start: off, hdr: p - off, len, end, buf };
}
/** Children of a constructed node. */
export function children(n) {
  const out = []; let o = n.start + n.hdr;
  while (o < n.end) { const c = parse(n.buf, o, n.end); out.push(c); o = c.end; }
  return out;
}
export const value = (n) => n.buf.subarray(n.start + n.hdr, n.end);
export const raw = (n) => n.buf.subarray(n.start, n.end);
/** Decode an OBJECT IDENTIFIER node. */
export function oid(n) {
  const b = value(n); const parts = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
  return parts.join('.');
}
/** INTEGER as uppercase hex without leading zero bytes. */
export function intHex(n) { let b = Buffer.from(value(n)); while (b.length > 1 && b[0] === 0) b = b.subarray(1); return b.toString('hex').toUpperCase(); }
/** Context-specific [k] child, if any. */
export const ctx = (nodes, k) => nodes.find((c) => c.cls === 2 && c.tag === k);
