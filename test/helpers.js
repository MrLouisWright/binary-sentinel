// Builds small synthetic PE files for tests (no third-party binaries are shipped).
const align = (n, a) => Math.ceil(n / a) * a;
const SC = { code: 0x60000020, rdata: 0x40000040, data: 0xc0000040, rwx: 0xe0000020 };

/**
 * @param {{ bits?: 32|64, sections?: {name:string, kind?:string, chars?:number, data?:Buffer, vsize?:number, raw?:boolean}[], imports?: Record<string,(string|number)[]>, entry?: string, timestamp?: number, dllChars?: number, overlay?: Buffer, dll?: boolean, tls?: number }} o
 */
export function buildPE(o = {}) {
  const bits = o.bits || 32; const p64 = bits === 64; const FA = 0x200, SA = 0x1000;
  const secs = (o.sections || [{ name: '.text', kind: 'code', data: Buffer.alloc(0x200, 0x90) }, { name: '.data', kind: 'data', data: Buffer.alloc(0x200, 1) }]).map((s) => ({ ...s, data: s.data ?? Buffer.alloc(0) }));
  if (o.imports || o.tls) secs.push({ name: '.idata', kind: 'data', data: Buffer.alloc(0), idata: true });
  const optSize = p64 ? 240 : 224; const lfanew = 0x80;
  const hdrEnd = lfanew + 24 + optSize + secs.length * 40; const sizeHeaders = align(hdrEnd, FA);
  let va = SA; let raw = sizeHeaders;
  // pre-assign VAs
  for (const s of secs) { s.va = va; va += align(Math.max(s.vsize || 0, s.data.length || 0x200, 0x2000), SA); }
  // build idata contents now that its VA is known
  const id = secs.find((s) => s.idata); let importDir = null; let tlsDir = null; const imageBase = p64 ? 0x140000000n : 0x400000n;
  if (id) {
    const b = Buffer.alloc(0x2000); let off = 0; const dlls = Object.entries(o.imports || {});
    const descOff = 0; off = (dlls.length + 1) * 20; const thunk = p64 ? 8 : 4;
    dlls.forEach(([dll, funcs], i) => {
      const iltOff = off; off += (funcs.length + 1) * thunk; const iatOff = off; off += (funcs.length + 1) * thunk;
      const nameOff = off; b.write(dll + '\0', off, 'latin1'); off = align(off + dll.length + 1, 2);
      funcs.forEach((f, k) => {
        let v;
        if (typeof f === 'number') v = p64 ? (1n << 63n) | BigInt(f) : (0x80000000 | f) >>> 0;
        else { const hn = off; b.writeUInt16LE(0, off); b.write(f + '\0', off + 2, 'latin1'); off = align(off + 3 + f.length, 2); v = p64 ? BigInt(id.va + hn) : id.va + hn; }
        for (const t of [iltOff, iatOff]) { if (p64) b.writeBigUInt64LE(BigInt(v), t + k * 8); else b.writeUInt32LE(v, t + k * 4); }
      });
      const d = descOff + i * 20; b.writeUInt32LE(id.va + iltOff, d); b.writeUInt32LE(id.va + nameOff, d + 12); b.writeUInt32LE(id.va + iatOff, d + 16);
    });
    if (dlls.length) importDir = { va: id.va, size: (dlls.length + 1) * 20 };
    if (o.tls) {
      off = align(off, 8); const tdir = off; const cbs = off + 0x40; const ts = p64 ? 8 : 4;
      const cbVa = imageBase + BigInt(id.va + cbs);
      if (p64) b.writeBigUInt64LE(cbVa, tdir + 24); else b.writeUInt32LE(Number(cbVa), tdir + 12);
      for (let i = 0; i < o.tls; i++) { const v = imageBase + BigInt(secs[0].va + 0x10 * (i + 1)); if (p64) b.writeBigUInt64LE(v, cbs + i * ts); else b.writeUInt32LE(Number(v), cbs + i * ts); }
      tlsDir = { va: id.va + tdir, size: p64 ? 40 : 24 }; off = cbs + (o.tls + 1) * ts;
    }
    id.data = b.subarray(0, align(off, 16));
  }
  for (const s of secs) { s.rawPtr = s.raw === false || !s.data.length ? 0 : raw; s.rawSize = s.raw === false || !s.data.length ? 0 : align(s.data.length, FA); raw += s.rawSize; }
  const sizeImage = va; const fileLen = raw;
  const buf = Buffer.alloc(fileLen);
  buf.write('MZ', 0, 'latin1'); buf.writeUInt32LE(lfanew, 0x3c);
  buf.write('PE\0\0', lfanew, 'latin1'); const c = lfanew + 4;
  buf.writeUInt16LE(p64 ? 0x8664 : 0x14c, c); buf.writeUInt16LE(secs.length, c + 2); buf.writeUInt32LE(o.timestamp ?? 1700000000, c + 4); buf.writeUInt16LE(optSize, c + 16); buf.writeUInt16LE(0x0102 | (p64 ? 0x20 : 0) | (o.dll ? 0x2000 : 0), c + 18);
  const op = c + 20; buf.writeUInt16LE(p64 ? 0x20b : 0x10b, op);
  const ep = secs.find((s) => s.name === (o.entry || secs[0].name)); buf.writeUInt32LE(o.entryRva ?? ep.va, op + 16);
  if (p64) buf.writeBigUInt64LE(imageBase, op + 24); else buf.writeUInt32LE(Number(imageBase), op + 28);
  buf.writeUInt32LE(SA, op + 32); buf.writeUInt32LE(FA, op + 36); buf.writeUInt16LE(6, op + 40); buf.writeUInt16LE(6, op + 48);
  buf.writeUInt32LE(sizeImage, op + 56); buf.writeUInt32LE(sizeHeaders, op + 60); buf.writeUInt32LE(o.checksum ?? 0, op + 64);
  buf.writeUInt16LE(o.subsystem ?? 3, op + 68); buf.writeUInt16LE(o.dllChars ?? 0x8160, op + 70);
  const nd = p64 ? op + 108 : op + 92; buf.writeUInt32LE(16, nd);
  if (importDir) { buf.writeUInt32LE(importDir.va, nd + 4 + 8); buf.writeUInt32LE(importDir.size, nd + 8 + 8); }
  if (tlsDir) { buf.writeUInt32LE(tlsDir.va, nd + 4 + 9 * 8); buf.writeUInt32LE(tlsDir.size, nd + 8 + 9 * 8); }
  if (o.clr) { buf.writeUInt32LE(secs[0].va, nd + 4 + 14 * 8); buf.writeUInt32LE(72, nd + 8 + 14 * 8); }
  secs.forEach((s, i) => {
    const so = op + optSize + i * 40; buf.write(s.name.slice(0, 8), so, 'latin1');
    buf.writeUInt32LE(s.vsize ?? Math.max(s.data.length, 1), so + 8); buf.writeUInt32LE(s.va, so + 12); buf.writeUInt32LE(s.rawSize, so + 16); buf.writeUInt32LE(s.rawPtr, so + 20);
    buf.writeUInt32LE(s.chars ?? SC[s.kind || 'data'], so + 36);
    if (s.rawSize) s.data.copy(buf, s.rawPtr);
  });
  return o.overlay ? Buffer.concat([buf, o.overlay]) : buf;
}
export function random(n, seed = 1) { const b = Buffer.alloc(n); let x = seed; for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; b[i] = x >> 16; } return b; }
