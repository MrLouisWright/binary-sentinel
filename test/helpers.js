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
  for (const s of secs) { s.va = va; if (s.build) s.data = s.build(s.va); va += align(Math.max(s.vsize || 0, s.data.length || 0x200, 0x2000), SA); }
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
  for (const [k, idx] of [['resource', 2]]) { const sec = o.dirs?.[k] && secs.find((x) => x.name === o.dirs[k]); if (sec) { buf.writeUInt32LE(sec.va, nd + 4 + idx * 8); buf.writeUInt32LE(sec.data.length, nd + 8 + idx * 8); } }
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

/** UTF-16LE VS_VERSIONINFO blob with a fixed file info and a StringFileInfo table. */
export function buildVersionInfo(strings, ver = [1, 2, 3, 4]) {
  const pad4 = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);
  const node = (key, value, type, kids = []) => {
    const k = Buffer.from(`${key}\0`, 'utf16le');
    let head = pad4(Buffer.concat([Buffer.alloc(6), k]));
    const body = Buffer.concat([pad4(value), ...kids.map(pad4)]);
    const b = Buffer.concat([head, body]);
    b.writeUInt16LE(b.length, 0); b.writeUInt16LE(type === 1 ? value.length / 2 : value.length, 2); b.writeUInt16LE(type, 4);
    return b;
  };
  const ffi = Buffer.alloc(52); ffi.writeUInt32LE(0xfeef04bd, 0); ffi.writeUInt32LE(0x10000, 4);
  ffi.writeUInt32LE((ver[0] << 16) | ver[1], 8); ffi.writeUInt32LE((ver[2] << 16) | ver[3], 12); ffi.writeUInt32LE((ver[0] << 16) | ver[1], 16); ffi.writeUInt32LE((ver[2] << 16) | ver[3], 20);
  const strs = Object.entries(strings).map(([k, v]) => node(k, Buffer.from(`${v}\0`, 'utf16le'), 1));
  return node('VS_VERSION_INFO', ffi, 0, [node('StringFileInfo', Buffer.alloc(0), 1, [node('040904b0', Buffer.alloc(0), 1, strs)])]);
}

/** Resource section data (type -> id -> lang=1033) given its RVA; returns Buffer. entries: [{ type: number, id: number, data: Buffer }] */
export function buildResourceSection(va, entries) {
  const types = [...new Set(entries.map((e) => e.type))];
  const dirs = []; const leafs = [];
  // layout: root dir, type dirs, name dirs, data entries, data
  const dirSize = (n) => 16 + n * 8;
  let off = dirSize(types.length);
  const typeDirOff = {}; for (const t of types) { typeDirOff[t] = off; off += dirSize(entries.filter((e) => e.type === t).length); }
  const nameDirOff = new Map(); for (const e of entries) { nameDirOff.set(e, off); off += dirSize(1); }
  const dataEntOff = new Map(); for (const e of entries) { dataEntOff.set(e, off); off += 16; }
  const dataOff = new Map(); for (const e of entries) { off = Math.ceil(off / 8) * 8; dataOff.set(e, off); off += e.data.length; }
  const b = Buffer.alloc(off);
  const dir = (o, ents) => { b.writeUInt16LE(ents.length, o + 14); ents.forEach(([id, target, sub], i) => { b.writeUInt32LE(id, o + 16 + i * 8); b.writeUInt32LE((target | (sub ? 0x80000000 : 0)) >>> 0, o + 20 + i * 8); }); };
  dir(0, types.map((t) => [t, typeDirOff[t], true]));
  for (const t of types) dir(typeDirOff[t], entries.filter((e) => e.type === t).map((e) => [e.id, nameDirOff.get(e), true]));
  for (const e of entries) { dir(nameDirOff.get(e), [[1033, dataEntOff.get(e), false]]); b.writeUInt32LE(va + dataOff.get(e), dataEntOff.get(e)); b.writeUInt32LE(e.data.length, dataEntOff.get(e) + 4); e.data.copy(b, dataOff.get(e)); }
  return b;
}

/** Minimal 64-bit little-endian Mach-O. */
export function buildMachO(o = {}) {
  const cmds = []; const strtab = ['\0']; const syms = [];
  const lc = (cmd, body) => { const size = Math.ceil((8 + body.length) / 8) * 8; const b = Buffer.alloc(size); b.writeUInt32LE(cmd >>> 0, 0); b.writeUInt32LE(size, 4); body.copy(b, 8); return b; };
  const strCmd = (cmd, s, extra = 16) => { const body = Buffer.alloc(extra - 8 + s.length + 1); body.writeUInt32LE(extra, 0); body.write(s, extra - 8, 'latin1'); return lc(cmd, body); };
  const code = o.code || Buffer.alloc(0x200, 0xc3);
  const textOff = 0x1000;
  const seg = (name, vmaddr, vmsize, fileoff, filesize, prot, sects = []) => {
    const body = Buffer.alloc(64 + sects.length * 80); body.write(name, 0, 'latin1');
    body.writeBigUInt64LE(BigInt(vmaddr), 16); body.writeBigUInt64LE(BigInt(vmsize), 24); body.writeBigUInt64LE(BigInt(fileoff), 32); body.writeBigUInt64LE(BigInt(filesize), 40);
    body.writeUInt32LE(prot, 48); body.writeUInt32LE(prot, 52); body.writeUInt32LE(sects.length, 56);
    sects.forEach((s, i) => { const so = 64 + i * 80; body.write(s.name, so, 'latin1'); body.write(name, so + 16, 'latin1'); body.writeBigUInt64LE(BigInt(vmaddr + s.offset - fileoff), so + 32); body.writeBigUInt64LE(BigInt(s.size), so + 40); body.writeUInt32LE(s.offset, so + 48); body.writeUInt32LE(s.flags ?? 0x80000400, so + 64); });
    return lc(0x19, body);
  };
  cmds.push(seg('__PAGEZERO', 0, 0x100000000, 0, 0, 0));
  cmds.push(seg('__TEXT', 0x100000000, 0x2000, 0, textOff + code.length, o.textProt ?? 5, [{ name: '__text', offset: textOff, size: code.length }]));
  if (o.rwx) cmds.push(seg('__EVIL', 0x100004000, 0x1000, 0, 0, 7));
  for (const d of o.dylibs || ['/usr/lib/libSystem.B.dylib']) cmds.push(strCmd(typeof d === 'string' ? 0xc : d.weak ? 0x80000018 : 0xc, typeof d === 'string' ? d : d.name, 24));
  for (const r of o.rpaths || []) cmds.push(strCmd(0x8000001c, r, 12));
  const main = Buffer.alloc(16); main.writeBigUInt64LE(BigInt(o.entryOff ?? textOff), 0); cmds.push(lc(0x80000028, main));
  for (const s of o.imports || []) { syms.push(strtab.join('').length); strtab.push(`_${s}\0`); }
  const symtabIdx = cmds.length; cmds.push(lc(0x2, Buffer.alloc(16)));
  let sigIdx = -1; if (o.signature) { sigIdx = cmds.length; cmds.push(lc(0x1d, Buffer.alloc(8))); }
  const header = Buffer.alloc(32); header.writeUInt32LE(0xfeedfacf, 0); header.writeUInt32LE(0x0100000c, 4); header.writeUInt32LE(2, 12);
  const cmdBuf = Buffer.concat(cmds); header.writeUInt32LE(cmds.length, 16); header.writeUInt32LE(cmdBuf.length, 20); header.writeUInt32LE((o.pie === false ? 0 : 0x200000) | 0x85, 24);
  const body = Buffer.alloc(textOff + code.length); header.copy(body, 0); cmdBuf.copy(body, 32); code.copy(body, textOff);
  const symOff = body.length; const symBuf = Buffer.alloc(syms.length * 16); syms.forEach((sx, i) => { symBuf.writeUInt32LE(sx, i * 16); symBuf[i * 16 + 4] = 0x01; });
  const strBuf = Buffer.from(strtab.join(''), 'latin1'); const strOff = symOff + symBuf.length;
  let off = 32; for (let i = 0; i < symtabIdx; i++) off += cmds[i].length;
  body.writeUInt32LE(symOff, off + 8); body.writeUInt32LE(syms.length, off + 12); body.writeUInt32LE(strOff, off + 16); body.writeUInt32LE(strBuf.length, off + 20);
  let sig = Buffer.alloc(0);
  if (o.signature) {
    const sigOff = strOff + strBuf.length; const ident = Buffer.from('com.example.tool\0', 'latin1');
    const cd = Buffer.alloc(88 + ident.length); cd.writeUInt32BE(0xfade0c02, 0); cd.writeUInt32BE(cd.length, 4); cd.writeUInt32BE(0x20400, 8); cd.writeUInt32BE(o.signature === 'adhoc' ? 0x2 : 0, 12); cd.writeUInt32BE(88, 20); ident.copy(cd, 88);
    const cms = o.signature === 'adhoc' ? Buffer.from([0xfa, 0xde, 0x0b, 0x01, 0, 0, 0, 8]) : Buffer.concat([Buffer.from([0xfa, 0xde, 0x0b, 0x01, 0, 0, 0, 16]), Buffer.alloc(8, 1)]);
    const sb = Buffer.alloc(12 + 16); sb.writeUInt32BE(0xfade0cc0, 0); sb.writeUInt32BE(2, 8); sb.writeUInt32BE(0, 12); sb.writeUInt32BE(28, 16); sb.writeUInt32BE(0x10000, 20); sb.writeUInt32BE(28 + cd.length, 24);
    sig = Buffer.concat([sb, cd, cms]); sig.writeUInt32BE(sig.length, 4);
    let so = 32; for (let i = 0; i < sigIdx; i++) so += cmds[i].length;
    body.writeUInt32LE(sigOff, so + 8); body.writeUInt32LE(sig.length, so + 12);
  }
  return Buffer.concat([body, symBuf, strBuf, sig]);
}

/** Universal binary from thin slices. */
export function buildFat(slices) {
  const head = Buffer.alloc(8 + slices.length * 20); head.writeUInt32BE(0xcafebabe, 0); head.writeUInt32BE(slices.length, 4);
  let off = 0x1000; const parts = [];
  slices.forEach((s, i) => { const o = 8 + i * 20; head.writeUInt32BE(s.readUInt32LE(4), o); head.writeUInt32BE(off, o + 8); head.writeUInt32BE(s.length, o + 12); head.writeUInt32BE(12, o + 16); parts.push({ off, s }); off = Math.ceil((off + s.length) / 0x1000) * 0x1000; });
  const b = Buffer.alloc(off); head.copy(b, 0); for (const p of parts) p.s.copy(b, p.off);
  return b;
}
