// Pure-JS static parsers for PE (Windows) and ELF (Linux/Unix) executables. Never executes anything.
import { createHash } from 'node:crypto';
import { parseResources, parseVersionInfo } from './resources.js';
import { parseMachO } from './macho.js';

export function entropy(buf, start = 0, end = buf.length) {
  const n = end - start; if (n <= 0) return 0;
  const f = new Uint32Array(256); for (let i = start; i < end; i++) f[buf[i]]++;
  let h = 0; for (const c of f) if (c) { const p = c / n; h -= p * Math.log2(p); }
  return Math.round(h * 1000) / 1000;
}
const hash = (alg, b) => createHash(alg).update(b).digest('hex');
export function hashes(buf) { return { md5: hash('md5', buf), sha1: hash('sha1', buf), sha256: hash('sha256', buf), sha512: hash('sha512', buf) }; }

/** Identify a file by magic bytes. */
export function detectType(b) {
  const s = (o, str) => b.length >= o + str.length && b.toString('latin1', o, o + str.length) === str;
  if (s(0, 'MZ')) { const lf = b.length >= 0x40 ? b.readUInt32LE(0x3c) : 0; return lf && b.length > lf + 4 && s(lf, 'PE\0\0') ? 'pe' : 'mz-dos'; }
  if (s(0, '\x7fELF')) return 'elf';
  if (b.length >= 4) { const m = b.readUInt32BE(0); if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m)) return 'macho'; if (m === 0xcafebabe && b.length > 8 && b.readUInt32BE(4) < 40) return 'macho-fat'; if (m === 0xcafebabe) return 'java-class'; }
  if (s(0, 'PK\x03\x04') || s(0, 'PK\x05\x06')) return 'zip';
  if (s(0, '%PDF-')) return 'pdf';
  if (s(0, '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')) return 'ole';
  if (s(0, 'L\0\0\0\x01\x14\x02\0')) return 'lnk';
  if (s(0, 'Rar!\x1a\x07')) return 'rar';
  if (s(0, '7z\xbc\xaf\x27\x1c')) return '7z';
  if (s(0, '\x1f\x8b')) return 'gzip';
  if (s(0, 'MSCF')) return 'cab';
  if (s(0, '{\\rtf')) return 'rtf';
  if (s(0x8001, 'CD001')) return 'iso';
  if (s(0, '#!')) return 'script';
  if (s(0, 'dex\n')) return 'dex';
  const head = b.toString('latin1', 0, Math.min(b.length, 4096));
  if (/^\s*<(!doctype html|html|script)/i.test(head)) return 'html';
  if (/^\s*<\?xml/i.test(head) && /<svg/i.test(head)) return 'svg';
  let bin = 0; for (let i = 0; i < Math.min(b.length, 4096); i++) { const c = b[i]; if (c === 0 || (c < 9) || (c > 13 && c < 32)) bin++; }
  return bin === 0 ? 'text' : 'data';
}

class R {
  constructor(buf, le = true) { this.b = buf; this.le = le; }
  ok(o, n) { return o >= 0 && o + n <= this.b.length; }
  u8(o) { if (!this.ok(o, 1)) throw new RangeError(`read past end at 0x${o.toString(16)}`); return this.b[o]; }
  u16(o) { if (!this.ok(o, 2)) throw new RangeError(`read past end at 0x${o.toString(16)}`); return this.le ? this.b.readUInt16LE(o) : this.b.readUInt16BE(o); }
  u32(o) { if (!this.ok(o, 4)) throw new RangeError(`read past end at 0x${o.toString(16)}`); return this.le ? this.b.readUInt32LE(o) : this.b.readUInt32BE(o); }
  u64(o) { if (!this.ok(o, 8)) throw new RangeError(`read past end at 0x${o.toString(16)}`); return this.le ? this.b.readBigUInt64LE(o) : this.b.readBigUInt64BE(o); }
  cstr(o, max = 512) { let e = o; while (e < this.b.length && e - o < max && this.b[e] !== 0) e++; return this.b.toString('latin1', o, e); }
}

// ------------------------------------------------------------------ PE
const MACHINES = { 0x14c: 'i386', 0x8664: 'amd64', 0x1c0: 'arm', 0x1c4: 'armnt', 0xaa64: 'arm64', 0x200: 'ia64', 0x0: 'unknown', 0xebc: 'efi-bytecode' };
const SUBSYSTEMS = { 1: 'native', 2: 'windows-gui', 3: 'windows-console', 5: 'os2-console', 7: 'posix-console', 9: 'windows-ce-gui', 10: 'efi-application', 11: 'efi-boot-driver', 12: 'efi-runtime-driver', 13: 'efi-rom', 14: 'xbox', 16: 'windows-boot-application' };
const DIRS = ['export', 'import', 'resource', 'exception', 'security', 'basereloc', 'debug', 'architecture', 'globalptr', 'tls', 'loadconfig', 'boundimport', 'iat', 'delayimport', 'clr', 'reserved'];
export const PACKER_SECTIONS = { upx0: 'UPX', upx1: 'UPX', upx2: 'UPX', 'upx!': 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack', aspack: 'ASPack', '.petite': 'Petite', 'pec1': 'PECompact', 'pec2': 'PECompact', pec: 'PECompact', '.mpress1': 'MPRESS', '.mpress2': 'MPRESS', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack', nsp0: 'NsPack', '.themida': 'Themida', '.winlice': 'WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect', '.enigma1': 'Enigma', '.enigma2': 'Enigma', '.perplex': 'Perplex', '.yp': 'Y0da', '.packed': 'generic packer', '.rlpack': 'RLPack', '.spack': 'Simple Pack', 'kkrunchy': 'kkrunchy', '.boom': 'Boomerang', '.ccg': 'CCG', 'bitarts': 'Crunch', '.taz': 'PESpin', 'fsg!': 'FSG', '.mew': 'MEW', 'mew': 'MEW', '.sforce3': 'StarForce', '.svkp': 'SVKP', '.epack': 'ePack', '.neolit': 'NeoLite', '.ndata': 'NSIS installer', '.pelock': 'PELock', '.obsidium': 'Obsidium' };
// imphash ordinal lookups used by pefile for the common cases
const ORD = { 'ws2_32': { 1: 'accept', 2: 'bind', 3: 'closesocket', 4: 'connect', 5: 'getpeername', 6: 'getsockname', 7: 'getsockopt', 8: 'htonl', 9: 'htons', 10: 'ioctlsocket', 11: 'inet_addr', 12: 'inet_ntoa', 13: 'listen', 14: 'ntohl', 15: 'ntohs', 16: 'recv', 17: 'recvfrom', 18: 'select', 19: 'send', 20: 'sendto', 21: 'setsockopt', 22: 'shutdown', 23: 'socket', 51: 'gethostbyaddr', 52: 'gethostbyname', 53: 'getprotobyname', 54: 'getprotobynumber', 55: 'getservbyname', 56: 'getservbyport', 57: 'gethostname', 111: 'wsagetlasterror', 115: 'wsastartup', 116: 'wsacleanup', 151: '__wsafdisset' } };
ORD.wsock32 = ORD.ws2_32;

export function parsePE(buf) {
  const r = new R(buf); const anomalies = [];
  const lfanew = r.u32(0x3c);
  if (r.cstr(lfanew, 4) !== 'PE') throw new Error('Not a PE file (no PE signature)');
  const coff = lfanew + 4;
  const machine = r.u16(coff); const nsec = r.u16(coff + 2); const ts = r.u32(coff + 4); const optSize = r.u16(coff + 16); const chars = r.u16(coff + 18);
  const opt = coff + 20; const magic = r.u16(opt); const pe32plus = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) anomalies.push(`unknown optional header magic 0x${magic.toString(16)}`);
  const ep = r.u32(opt + 16);
  const imageBase = pe32plus ? r.u64(opt + 24) : BigInt(r.u32(opt + 28));
  const sectionAlign = r.u32(opt + 32), fileAlign = r.u32(opt + 36);
  const sizeOfImage = r.u32(opt + 56), sizeOfHeaders = r.u32(opt + 60), checksum = r.u32(opt + 64);
  const subsystem = r.u16(opt + 68), dllChars = r.u16(opt + 70);
  const ndOff = pe32plus ? opt + 108 : opt + 92; const nDirs = Math.min(r.u32(ndOff), 16);
  const dirs = {};
  for (let i = 0; i < nDirs; i++) { const va = r.u32(ndOff + 4 + i * 8), size = r.u32(ndOff + 8 + i * 8); if (va || size) dirs[DIRS[i]] = { va, size }; }
  const secOff = opt + optSize; const sections = [];
  if (nsec > 96) anomalies.push(`unusual number of sections (${nsec})`);
  for (let i = 0; i < Math.min(nsec, 96); i++) {
    const o = secOff + i * 40; if (!r.ok(o, 40)) { anomalies.push('section table truncated'); break; }
    const name = buf.toString('latin1', o, o + 8).replace(/\0.*$/s, '');
    const vsize = r.u32(o + 8), va = r.u32(o + 12), rawSize = r.u32(o + 16), rawPtr = r.u32(o + 20), c = r.u32(o + 36);
    const end = Math.min(buf.length, rawPtr + rawSize);
    const s = { name, virtualAddress: va, virtualSize: vsize, rawPointer: rawPtr, rawSize, characteristics: c, read: !!(c & 0x40000000), write: !!(c & 0x80000000), execute: !!(c & 0x20000000) || !!(c & 0x20), entropy: rawPtr < buf.length ? entropy(buf, rawPtr, end) : 0, md5: rawPtr < buf.length && end > rawPtr ? hash('md5', buf.subarray(rawPtr, end)) : null };
    if (rawPtr + rawSize > buf.length) anomalies.push(`section ${name || '#' + i} extends past end of file`);
    sections.push(s);
  }
  const rva2off = (rva) => {
    for (const s of sections) { const sz = Math.max(s.virtualSize, s.rawSize); if (rva >= s.virtualAddress && rva < s.virtualAddress + sz) { const off = rva - s.virtualAddress + s.rawPointer; return off < buf.length ? off : -1; } }
    return rva < sizeOfHeaders && rva < buf.length ? rva : -1;
  };
  // imports
  const imports = []; let importError = null;
  const parseImportTable = (dir, delayed) => {
    let o = rva2off(dir.va); if (o < 0) { importError = `${delayed ? 'delay-' : ''}import directory outside the file`; return; }
    for (let n = 0; n < 512; n++, o += delayed ? 32 : 20) {
      if (!r.ok(o, 20)) break;
      const ilt = delayed ? r.u32(o + 16) : (r.u32(o) || r.u32(o + 16)); const nameRva = delayed ? r.u32(o + 4) : r.u32(o + 12);
      if (!ilt && !nameRva) break;
      const no = rva2off(nameRva); if (no < 0) { importError = 'import name outside the file'; break; }
      const dll = r.cstr(no, 256); const funcs = [];
      let t = rva2off(ilt); const step = pe32plus ? 8 : 4;
      for (let k = 0; t >= 0 && k < 4096 && r.ok(t, step); k++, t += step) {
        const v = pe32plus ? r.u64(t) : BigInt(r.u32(t)); if (v === 0n) break;
        const isOrd = pe32plus ? (v >> 63n) === 1n : (v >> 31n) === 1n;
        if (isOrd) funcs.push({ ordinal: Number(v & 0xffffn) });
        else { const ho = rva2off(Number(v & 0x7fffffffn)); if (ho < 0) { importError = 'import thunk outside the file'; break; } funcs.push({ name: r.cstr(ho + 2, 512) }); }
      }
      imports.push({ dll, delayed, functions: funcs });
    }
  };
  try { if (dirs.import) parseImportTable(dirs.import, false); } catch (e) { importError = e.message; }
  try { if (dirs.delayimport) parseImportTable(dirs.delayimport, true); } catch (e) { importError ??= e.message; }
  // imphash (pefile-compatible for named imports and ws2_32/wsock32 ordinals)
  const parts = [];
  for (const imp of imports.filter((i) => !i.delayed)) {
    let lib = imp.dll.toLowerCase(); const ext = lib.match(/\.(dll|ocx|sys)$/); if (ext) lib = lib.slice(0, -4);
    for (const f of imp.functions) parts.push(`${lib}.${(f.name ?? (ORD[lib]?.[f.ordinal] || `ord${f.ordinal}`)).toLowerCase()}`);
  }
  const imphash = parts.length ? hash('md5', parts.join(',')) : null;
  // exports
  let exports = null;
  try {
    if (dirs.export) {
      const o = rva2off(dirs.export.va);
      if (o >= 0) {
        const nNames = r.u32(o + 24); const namesO = rva2off(r.u32(o + 32)); const names = [];
        for (let i = 0; i < Math.min(nNames, 5000) && namesO >= 0; i++) { const no = rva2off(r.u32(namesO + i * 4)); if (no >= 0) names.push(r.cstr(no, 256)); }
        exports = { dll: r.cstr(Math.max(0, rva2off(r.u32(o + 12))), 256), count: r.u32(o + 20), names };
      }
    }
  } catch (e) { anomalies.push(`export directory: ${e.message}`); }
  // resources + version info
  let resources = []; let versionInfo = null;
  try {
    if (dirs.resource) {
      const ro = rva2off(dirs.resource.va);
      if (ro >= 0) {
        resources = parseResources(buf, ro, rva2off);
        const v = resources.find((x) => x.type === 'VERSION' && !x.truncated);
        if (v) versionInfo = parseVersionInfo(buf.subarray(v.offset, v.offset + v.size));
      }
    }
  } catch (e) { anomalies.push(`resource directory: ${e.message}`); }
  // TLS callbacks
  let tlsCallbacks = 0;
  try {
    if (dirs.tls) {
      const o = rva2off(dirs.tls.va);
      if (o >= 0) {
        const cbVa = pe32plus ? r.u64(o + 24) : BigInt(r.u32(o + 12));
        if (cbVa) { let co = rva2off(Number(cbVa - imageBase)); const step = pe32plus ? 8 : 4; while (co >= 0 && r.ok(co, step) && tlsCallbacks < 64 && (pe32plus ? r.u64(co) : r.u32(co))) { tlsCallbacks++; co += step; } }
      }
    }
  } catch { /* ignore */ }
  // Rich header
  let rich = null;
  const ri = buf.subarray(0, Math.min(lfanew, buf.length)).indexOf('Rich');
  if (ri > 0 && r.ok(ri + 4, 4)) {
    const key = r.u32(ri + 4); const entries = [];
    let o = ri - 4; let dans = -1;
    while (o >= 0x80 - 4 && o >= 0) { if ((r.u32(o) ^ key) === 0x536e6144) { dans = o; break; } o -= 4; }
    if (dans >= 0) { for (let p = dans + 16; p < ri; p += 8) { const id = r.u32(p) ^ key, cnt = r.u32(p + 4) ^ key; entries.push({ product: id >>> 16, build: id & 0xffff, count: cnt }); } rich = { key: key.toString(16).padStart(8, '0'), entries, hash: hash('md5', buf.subarray(dans, ri).map((x, i) => x ^ buf[ri + 4 + (i % 4)])) }; }
  }
  // overlay
  const lastRaw = sections.reduce((m, s) => Math.max(m, s.rawPointer + s.rawSize), sizeOfHeaders);
  let overlay = null;
  let overlayStart = lastRaw;
  if (dirs.security && dirs.security.va >= lastRaw) overlayStart = lastRaw; // certificate lives in overlay
  if (buf.length > overlayStart) {
    const certEnd = dirs.security && dirs.security.va === overlayStart ? dirs.security.va + dirs.security.size : overlayStart;
    const size = buf.length - certEnd;
    if (size > 0) overlay = { offset: certEnd, size, entropy: entropy(buf, certEnd), magic: detectType(buf.subarray(certEnd, certEnd + 0x10000)) };
  }
  const epSection = sections.find((s) => ep >= s.virtualAddress && ep < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
  const flags = {
    dll: !!(chars & 0x2000), executable: !!(chars & 0x2), largeAddressAware: !!(chars & 0x20), relocsStripped: !!(chars & 0x1),
    aslr: !!(dllChars & 0x40), highEntropyVA: !!(dllChars & 0x20), nx: !!(dllChars & 0x100), cfg: !!(dllChars & 0x4000), noSEH: !!(dllChars & 0x400), forceIntegrity: !!(dllChars & 0x80), appContainer: !!(dllChars & 0x1000), guardCF: !!(dllChars & 0x4000),
  };
  return {
    format: 'pe', bits: pe32plus ? 64 : 32, machine: MACHINES[machine] || `0x${machine.toString(16)}`, timestamp: ts, timestampIso: ts ? new Date(ts * 1000).toISOString() : null,
    subsystem: SUBSYSTEMS[subsystem] || `unknown(${subsystem})`, entryPoint: ep, entrySection: epSection?.name ?? null, imageBase: `0x${imageBase.toString(16)}`,
    sectionAlignment: sectionAlign, fileAlignment: fileAlign, sizeOfImage, sizeOfHeaders, checksum, flags, directories: dirs,
    dotnet: !!dirs.clr, signed: !!(dirs.security && dirs.security.size), sections, imports, importError, imphash, exports, tlsCallbacks, rich, overlay, resources, versionInfo, anomalies,
  };
}

// ------------------------------------------------------------------ ELF
const EM = { 0: 'none', 2: 'sparc', 3: 'i386', 8: 'mips', 20: 'ppc', 21: 'ppc64', 22: 's390', 40: 'arm', 42: 'superh', 43: 'sparcv9', 50: 'ia64', 62: 'x86-64', 183: 'aarch64', 243: 'riscv', 258: 'loongarch' };
const ET = { 0: 'none', 1: 'relocatable', 2: 'executable', 3: 'shared-object', 4: 'core' };
const OSABI = { 0: 'sysv', 3: 'linux', 6: 'solaris', 9: 'freebsd', 12: 'openbsd', 97: 'arm', 255: 'standalone' };
const PT = { 0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY' };

export function parseELF(buf) {
  const anomalies = [];
  if (buf.length < 52) throw new Error('ELF header truncated');
  const cls = buf[4]; const data = buf[5]; const is64 = cls === 2;
  if (cls !== 1 && cls !== 2) throw new Error(`invalid ELF class ${cls}`);
  const r = new R(buf, data !== 2);
  const type = r.u16(16), machine = r.u16(18);
  const entry = is64 ? r.u64(24) : BigInt(r.u32(24));
  const phoff = Number(is64 ? r.u64(32) : BigInt(r.u32(28))); const shoff = Number(is64 ? r.u64(40) : BigInt(r.u32(32)));
  const phentsize = r.u16(is64 ? 54 : 42), phnum = r.u16(is64 ? 56 : 44), shentsize = r.u16(is64 ? 58 : 46), shnum = r.u16(is64 ? 60 : 48), shstrndx = r.u16(is64 ? 62 : 50);
  const segments = [];
  for (let i = 0; i < Math.min(phnum, 256); i++) {
    const o = phoff + i * phentsize; if (!r.ok(o, is64 ? 56 : 32)) { anomalies.push('program header table truncated'); break; }
    const t = r.u32(o); const flags = is64 ? r.u32(o + 4) : r.u32(o + 24);
    const off = Number(is64 ? r.u64(o + 8) : BigInt(r.u32(o + 4))); const vaddr = is64 ? r.u64(o + 16) : BigInt(r.u32(o + 8));
    const filesz = Number(is64 ? r.u64(o + 32) : BigInt(r.u32(o + 16))); const memsz = Number(is64 ? r.u64(o + 40) : BigInt(r.u32(o + 20)));
    segments.push({ type: PT[t] || `0x${t.toString(16)}`, offset: off, vaddr: `0x${vaddr.toString(16)}`, vaddrN: vaddr, fileSize: filesz, memSize: memsz, read: !!(flags & 4), write: !!(flags & 2), execute: !!(flags & 1) });
  }
  const sections = [];
  if (shoff && shnum) {
    const raw = [];
    for (let i = 0; i < Math.min(shnum, 4096); i++) {
      const o = shoff + i * shentsize; if (!r.ok(o, is64 ? 64 : 40)) { anomalies.push('section header table truncated'); break; }
      raw.push({ nameOff: r.u32(o), type: r.u32(o + 4), flags: Number(is64 ? r.u64(o + 8) : BigInt(r.u32(o + 8))), addr: is64 ? r.u64(o + 16) : BigInt(r.u32(o + 12)), offset: Number(is64 ? r.u64(o + 24) : BigInt(r.u32(o + 16))), size: Number(is64 ? r.u64(o + 32) : BigInt(r.u32(o + 20))), link: r.u32(is64 ? o + 40 : o + 24), entsize: Number(is64 ? r.u64(o + 56) : BigInt(r.u32(o + 36))) });
    }
    const strtab = raw[shstrndx];
    for (const s of raw) {
      const name = strtab && strtab.offset + s.nameOff < buf.length ? r.cstr(strtab.offset + s.nameOff, 128) : '';
      const nobits = s.type === 8; const end = Math.min(buf.length, s.offset + s.size);
      sections.push({ name, type: s.type, offset: s.offset, size: s.size, addr: s.addr, link: s.link, entsize: s.entsize, write: !!(s.flags & 1), alloc: !!(s.flags & 2), execute: !!(s.flags & 4), entropy: nobits || s.offset >= buf.length ? 0 : entropy(buf, s.offset, end) });
    }
  } else anomalies.push('no section headers (stripped with sstrip or packed)');
  // dynamic symbols / needed libs
  const sec = (n) => sections.find((s) => s.name === n);
  const needed = []; let runpath = null, rpath = null, bindNow = false, soname = null;
  const dynSeg = segments.find((s) => s.type === 'DYNAMIC');
  const dyn = sec('.dynamic') || (dynSeg && { offset: dynSeg.offset, size: dynSeg.fileSize });
  const dynstr = sec('.dynstr');
  if (dyn) {
    const ent = is64 ? 16 : 8;
    for (let o = dyn.offset; o + ent <= Math.min(buf.length, dyn.offset + dyn.size); o += ent) {
      const tag = Number(is64 ? r.u64(o) : BigInt(r.u32(o))); const val = Number(is64 ? r.u64(o + 8) : BigInt(r.u32(o + 4)));
      if (tag === 0) break;
      const str = () => (dynstr ? r.cstr(dynstr.offset + val, 256) : `@${val}`);
      if (tag === 1) needed.push(str()); else if (tag === 14) soname = str(); else if (tag === 15) rpath = str(); else if (tag === 29) runpath = str();
      else if (tag === 24) bindNow = true; else if (tag === 30 && (val & 8)) bindNow = true; else if (tag === 0x6ffffffb && (val & 1)) bindNow = true;
    }
  }
  const symbols = (tabName, strName) => {
    const t = sec(tabName), s = sec(strName); if (!t || !s) return [];
    const ent = is64 ? 24 : 16; const out = [];
    for (let o = t.offset + ent; o + ent <= Math.min(buf.length, t.offset + t.size) && out.length < 20000; o += ent) {
      const nameOff = r.u32(o); const info = is64 ? r.u8(o + 4) : r.u8(o + 12); const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      const name = r.cstr(s.offset + nameOff, 256); if (!name) continue;
      out.push({ name, type: ['notype', 'object', 'func', 'section', 'file', 'common', 'tls'][info & 0xf] || 'other', bind: ['local', 'global', 'weak'][info >> 4] || 'other', undefined: shndx === 0 });
    }
    return out;
  };
  const dynsym = symbols('.dynsym', '.dynstr');
  const imports = dynsym.filter((s) => s.undefined && s.name).map((s) => s.name.replace(/@.*$/, ''));
  const exportsList = dynsym.filter((s) => !s.undefined && s.bind !== 'local' && (s.type === 'func' || s.type === 'object')).map((s) => s.name);
  const hasSymtab = !!sec('.symtab');
  const interpSeg = segments.find((s) => s.type === 'INTERP');
  const interp = interpSeg ? r.cstr(interpSeg.offset, 256) : null;
  const stack = segments.find((s) => s.type === 'GNU_STACK');
  const relro = segments.some((s) => s.type === 'GNU_RELRO') ? (bindNow ? 'full' : 'partial') : 'none';
  const entrySeg = segments.find((s) => s.type === 'LOAD' && entry >= s.vaddrN && entry < s.vaddrN + BigInt(s.memSize));
  const entrySec = sections.find((s) => s.alloc && entry >= s.addr && entry < s.addr + BigInt(s.size));
  // telfhash-like import hash: md5 of sorted, lower-cased imported function names
  const importHash = imports.length ? hash('md5', [...new Set(imports.map((x) => x.toLowerCase()))].sort().join(',')) : null;
  for (const s of segments) delete s.vaddrN;
  for (const s of sections) s.addr = `0x${s.addr.toString(16)}`;
  return {
    format: 'elf', bits: is64 ? 64 : 32, endian: data === 2 ? 'big' : 'little', osabi: OSABI[buf[7]] || `unknown(${buf[7]})`, type: ET[type] || `0x${type.toString(16)}`, machine: EM[machine] || `0x${machine.toString(16)}`,
    entryPoint: `0x${entry.toString(16)}`, entrySection: entrySec?.name ?? null, entryInLoad: !!entrySeg, interpreter: interp, segments, sections, needed, soname, rpath, runpath,
    imports, exports: exportsList, importHash, stripped: !hasSymtab,
    hardening: { pie: type === 3 && !!interp, nx: stack ? !stack.execute : false, execStack: stack ? stack.execute : true, relro, bindNow, canary: imports.includes('__stack_chk_fail') || imports.includes('__stack_chk_guard'), fortify: imports.some((i) => /^__\w+_chk$/.test(i) && i !== '__stack_chk_fail') },
    anomalies,
  };
}

export function parseBinary(buf) {
  const t = detectType(buf);
  if (t === 'pe') return parsePE(buf);
  if (t === 'elf') return parseELF(buf);
  if (t === 'macho' || t === 'macho-fat') return parseMachO(buf);
  return null;
}
