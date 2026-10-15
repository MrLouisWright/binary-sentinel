// Mach-O (macOS / iOS) parser: thin and universal (fat) binaries. Static only.
import { entropy } from './binfmt.js';

const CPU = { 7: 'i386', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32', 18: 'ppc', 0x01000012: 'ppc64' };
const FILETYPE = { 1: 'object', 2: 'executable', 3: 'fvmlib', 4: 'core', 5: 'preload', 6: 'dylib', 7: 'dylinker', 8: 'bundle', 9: 'dylib-stub', 10: 'dsym', 11: 'kext' };
const LC = { SEGMENT: 0x1, SYMTAB: 0x2, UNIXTHREAD: 0x5, LOAD_DYLIB: 0xc, ID_DYLIB: 0xd, LOAD_DYLINKER: 0xe, SEGMENT_64: 0x19, CODE_SIGNATURE: 0x1d, ENCRYPTION_INFO: 0x21, LAZY_LOAD_DYLIB: 0x20, ENCRYPTION_INFO_64: 0x2c, LOAD_WEAK_DYLIB: 0x80000018, RPATH: 0x8000001c, REEXPORT_DYLIB: 0x8000001f, LOAD_UPWARD_DYLIB: 0x80000023, MAIN: 0x80000028 };
const DYLIB_KIND = { [LC.LOAD_DYLIB]: 'load', [LC.LOAD_WEAK_DYLIB]: 'weak', [LC.REEXPORT_DYLIB]: 'reexport', [LC.LAZY_LOAD_DYLIB]: 'lazy', [LC.LOAD_UPWARD_DYLIB]: 'upward' };
export const MACHO_FLAGS = { noUndefs: 0x1, twoLevel: 0x80, pie: 0x200000, allowStackExecution: 0x20000, noHeapExecution: 0x1000000, hasTlv: 0x800000 };
const prot = (p) => `${p & 1 ? 'r' : '-'}${p & 2 ? 'w' : '-'}${p & 4 ? 'x' : '-'}`;

/** Is this buffer a Mach-O (thin or fat)? */
export function isMachO(b) {
  if (b.length < 8) return false;
  const m = b.readUInt32BE(0);
  return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m) || ((m === 0xcafebabe || m === 0xcafebabf) && b.readUInt32BE(4) > 0 && b.readUInt32BE(4) < 40);
}

/**
 * Parse a Mach-O. Universal binaries return { format: 'macho-fat', slices: [...] } with each slice parsed.
 * @param {Uint8Array} buf
 */
export function parseMachO(buf) {
  buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  const m = buf.readUInt32BE(0);
  if (m === 0xcafebabe || m === 0xcafebabf) {
    const n = buf.readUInt32BE(4); const is64 = m === 0xcafebabf; const slices = []; const anomalies = [];
    for (let i = 0; i < Math.min(n, 32); i++) {
      const o = 8 + i * (is64 ? 32 : 20); if (o + 20 > buf.length) { anomalies.push('fat header truncated'); break; }
      const cpu = buf.readInt32BE(o) >>> 0; const off = is64 ? Number(buf.readBigUInt64BE(o + 8)) : buf.readUInt32BE(o + 8); const size = is64 ? Number(buf.readBigUInt64BE(o + 16)) : buf.readUInt32BE(o + 12);
      if (off + size > buf.length) { anomalies.push(`slice ${CPU[cpu] || cpu} extends past end of file`); continue; }
      try { slices.push({ offset: off, size, ...parseThin(buf.subarray(off, off + size)) }); } catch (e) { anomalies.push(`slice ${CPU[cpu] || cpu}: ${e.message}`); }
    }
    return { format: 'macho-fat', slices, anomalies };
  }
  return parseThin(buf);
}

function parseThin(b) {
  const m = b.readUInt32BE(0); const le = m === 0xcefaedfe || m === 0xcffaedfe; const is64 = m === 0xfeedfacf || m === 0xcffaedfe;
  if (![0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m)) throw new Error('Not a Mach-O file');
  const u32 = (o) => { if (o < 0 || o + 4 > b.length) throw new RangeError(`read past end at 0x${o.toString(16)}`); return le ? b.readUInt32LE(o) : b.readUInt32BE(o); };
  const u64 = (o) => { if (o < 0 || o + 8 > b.length) throw new RangeError(`read past end at 0x${o.toString(16)}`); return Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)); };
  const str = (o, max) => { let e = o; const lim = Math.min(b.length, o + max); while (e < lim && b[e]) e++; return b.toString('latin1', o, e); };
  const cputype = u32(4) >>> 0; const filetype = u32(12); const ncmds = u32(16); const sizeofcmds = u32(20); const flags = u32(24);
  const anomalies = []; const segments = []; const dylibs = []; const rpaths = []; let entryOff = null; let symtab = null; let codeSig = null; let encrypted = false; let dylinker = null; let id = null;
  let o = is64 ? 32 : 28; const cmdsEnd = o + sizeofcmds;
  if (cmdsEnd > b.length) anomalies.push('load commands extend past end of file');
  for (let i = 0; i < Math.min(ncmds, 4096); i++) {
    if (o + 8 > b.length) { anomalies.push('load command table truncated'); break; }
    const cmd = u32(o) >>> 0; const size = u32(o + 4);
    if (size < 8 || o + size > b.length) { anomalies.push(`load command #${i} has bad size ${size}`); break; }
    if (cmd === LC.SEGMENT || cmd === LC.SEGMENT_64) {
      const w = cmd === LC.SEGMENT_64; const name = str(o + 8, 16);
      const vmaddr = w ? u64(o + 24) : u32(o + 24), vmsize = w ? u64(o + 32) : u32(o + 28), fileoff = w ? u64(o + 40) : u32(o + 32), filesize = w ? u64(o + 48) : u32(o + 36);
      const maxprot = u32(w ? o + 56 : o + 40), initprot = u32(w ? o + 60 : o + 44), nsects = u32(w ? o + 64 : o + 48);
      const sections = [];
      for (let s = 0; s < Math.min(nsects, 255); s++) {
        const so = o + (w ? 72 : 56) + s * (w ? 80 : 68); if (so + (w ? 80 : 68) > o + size) break;
        const sz = w ? u64(so + 40) : u32(so + 36); const off = u32(w ? so + 48 : so + 40); const sflags = u32(w ? so + 64 : so + 56);
        const end = Math.min(b.length, off + sz);
        sections.push({ name: str(so, 16), segment: str(so + 16, 16), size: sz, offset: off, entropy: off && off < b.length && (sflags & 0xff) !== 1 ? entropy(b, off, end) : 0, execute: !!(sflags & 0x80000400) });
      }
      segments.push({ name, vmaddr: `0x${vmaddr.toString(16)}`, vmaddrNum: vmaddr, vmsize, fileoff, filesize, maxprot: prot(maxprot), initprot: prot(initprot), read: !!(initprot & 1), write: !!(initprot & 2), execute: !!(initprot & 4), entropy: filesize && fileoff < b.length ? entropy(b, fileoff, Math.min(b.length, fileoff + filesize)) : 0, sections });
      if (fileoff + filesize > b.length) anomalies.push(`segment ${name} extends past end of file`);
    } else if (DYLIB_KIND[cmd]) dylibs.push({ name: str(o + u32(o + 8), size), kind: DYLIB_KIND[cmd] });
    else if (cmd === LC.ID_DYLIB) id = str(o + u32(o + 8), size);
    else if (cmd === LC.LOAD_DYLINKER) dylinker = str(o + u32(o + 8), size);
    else if (cmd === LC.RPATH) rpaths.push(str(o + u32(o + 8), size));
    else if (cmd === LC.MAIN) entryOff = u64(o + 8);
    else if (cmd === LC.SYMTAB) symtab = { symoff: u32(o + 8), nsyms: u32(o + 12), stroff: u32(o + 16), strsize: u32(o + 20) };
    else if (cmd === LC.CODE_SIGNATURE) codeSig = { offset: u32(o + 8), size: u32(o + 12) };
    else if (cmd === LC.ENCRYPTION_INFO || cmd === LC.ENCRYPTION_INFO_64) encrypted = encrypted || u32(o + 16) !== 0;
    o += size;
  }
  // imports = undefined external symbols
  const imports = []; const exports = [];
  if (symtab) {
    const ent = is64 ? 16 : 12;
    for (let i = 0; i < Math.min(symtab.nsyms, 200000); i++) {
      const so = symtab.symoff + i * ent; if (so + ent > b.length) { anomalies.push('symbol table truncated'); break; }
      const strx = u32(so); const type = b[so + 4];
      if (type & 0xe0) continue; // stabs
      const nm = symtab.stroff + strx < b.length ? str(symtab.stroff + strx, 1024) : '';
      if (!nm) continue;
      const clean = nm.replace(/^_/, '');
      if ((type & 0x0e) === 0 && type & 1) imports.push(clean);
      else if ((type & 0x0e) === 0x0e && type & 1) exports.push(clean);
    }
  }
  // code signature
  let signature = null;
  if (codeSig) {
    signature = { present: true, adhoc: false, identifier: null, teamId: null, cms: false };
    try {
      const so = codeSig.offset;
      if (b.readUInt32BE(so) === 0xfade0cc0) {
        const count = b.readUInt32BE(so + 8);
        for (let i = 0; i < Math.min(count, 64); i++) {
          const type = b.readUInt32BE(so + 12 + i * 8); const off = so + b.readUInt32BE(so + 16 + i * 8); const magic = b.readUInt32BE(off); const len = b.readUInt32BE(off + 4);
          if (magic === 0xfade0c02) { const version = b.readUInt32BE(off + 8); const f = b.readUInt32BE(off + 12); signature.adhoc = !!(f & 0x2); signature.identifier = b.toString('latin1', off + b.readUInt32BE(off + 20), off + len).split('\0')[0]; if (version >= 0x20200) { const t = b.readUInt32BE(off + 48); if (t) signature.teamId = b.toString('latin1', off + t, off + len).split('\0')[0]; } }
          if (type === 0x10000 && magic === 0xfade0b01) signature.cms = len > 8;
        }
      } else anomalies.push('LC_CODE_SIGNATURE does not point at a code signature SuperBlob');
    } catch { anomalies.push('code signature truncated'); }
    if (signature.cms) signature.adhoc = false;
  }
  const text = segments.find((s) => s.name === '__TEXT');
  const entryVm = entryOff != null && text ? text.vmaddrNum + entryOff : null;
  const entrySeg = entryVm != null ? segments.find((s) => entryVm >= s.vmaddrNum && entryVm < s.vmaddrNum + s.vmsize) : null;
  const entrySection = entrySeg?.sections.find((s) => entryOff >= s.offset && entryOff < s.offset + s.size)?.name ?? null;
  return {
    format: 'macho', bits: is64 ? 64 : 32, machine: CPU[cputype] || `0x${cputype.toString(16)}`, type: FILETYPE[filetype] || `unknown(${filetype})`, flags: Object.fromEntries(Object.entries(MACHO_FLAGS).map(([k, v]) => [k, !!(flags & v)])),
    entryPoint: entryOff, entrySegment: entrySeg?.name ?? null, entrySection, segments: segments.map(({ vmaddrNum, ...s }) => s), dylibs, rpaths, dylinker, id, imports: [...new Set(imports)], exports, signature, encrypted, anomalies,
  };
}
