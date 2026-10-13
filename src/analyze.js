import { parsePE, parseELF, detectType, entropy, hashes, PACKER_SECTIONS } from './binfmt.js';
import { capabilities } from './capabilities.js';

const SIGS = [['UPX!', 'UPX'], ['$Info: This file is packed with the UPX', 'UPX'], ['MPRESS', 'MPRESS'], ['PECompact2', 'PECompact'], ['aPLib', 'aPLib (ASPack and others)'], ['Themida', 'Themida'], ['.vmp0', 'VMProtect'], ['ConfuserEx', 'ConfuserEx'], ['Enigma protector', 'Enigma'], ['NullsoftInst', 'NSIS installer'], ['Inno Setup', 'Inno Setup installer']];
const INJECTION_SETS = [['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], ['VirtualAllocEx', 'WriteProcessMemory', 'QueueUserAPC'], ['WriteProcessMemory', 'SetThreadContext', 'ResumeThread'], ['NtUnmapViewOfSection', 'WriteProcessMemory'], ['NtMapViewOfSection', 'NtCreateThreadEx']];

/** PE checksum (same algorithm as imagehlp CheckSumMappedFile). */
export function peChecksum(buf, checksumOffset) {
  let sum = 0n; const len = buf.length;
  for (let i = 0; i < len; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    const w = i + 1 < len ? buf.readUInt16LE(i) : buf[i];
    sum += BigInt(w); sum = (sum & 0xffffn) + (sum >> 16n);
  }
  sum = (sum & 0xffffn) + (sum >> 16n);
  return Number(sum + BigInt(len)) >>> 0;
}

/**
 * Statically analyse one file buffer. Never executes anything.
 * @returns {{ info: object|null, raw: object[], summary: object }}
 */
export function analyzeBuffer(buf, name, opts = {}) {
  const raw = []; const add = (rule, message, extra = {}) => raw.push({ rule, message, file: name, ...extra });
  const type = detectType(buf);
  const h = hashes(buf);
  const summary = { type, size: buf.length, sha256: h.sha256, entropy: entropy(buf) };
  if (type !== 'pe' && type !== 'elf') {
    if (['macho', 'macho-fat', 'mz-dos'].includes(type)) add('unsupported-format', `${type} file not analysed`);
    return { info: { format: type, hashes: h }, raw, summary, skipped: !['macho', 'macho-fat', 'mz-dos'].includes(type) };
  }
  let info;
  try { info = type === 'pe' ? parsePE(buf) : parseELF(buf); } catch (e) {
    add('header-anomaly', `Header could not be parsed: ${e.message}`, { fix: 'Likely corrupted or deliberately malformed; analyse in a disassembler.' });
    return { info: { format: type, hashes: h }, raw, summary };
  }
  info.hashes = h;
  const now = opts.now ? new Date(opts.now) : new Date();
  const text = buf.toString('latin1');
  const sigs = [...new Set(SIGS.filter(([s]) => text.includes(s)).map(([, n]) => n))];
  for (const a of info.anomalies) add('header-anomaly', a);

  if (info.format === 'pe') {
    Object.assign(summary, { format: `PE${info.bits === 64 ? '32+' : '32'} ${info.machine} ${info.flags.dll ? 'DLL' : 'EXE'}`, subsystem: info.subsystem, compiled: info.timestampIso, imphash: info.imphash, entry: `${info.entrySection ?? '?'} 0x${info.entryPoint.toString(16)}`, sections: info.sections.map((s) => `${s.name || '?'}(${s.entropy})`), imports: info.imports.reduce((n, i) => n + i.functions.length, 0) });
    const packers = [...new Set(info.sections.map((s) => PACKER_SECTIONS[s.name.toLowerCase()]).filter(Boolean))];
    for (const p of packers) add('packer-section', `Section names indicate ${p}`, { evidence: info.sections.map((s) => s.name).join(', '), fix: p === 'UPX' ? 'Unpack with "upx -d" in an isolated lab before further analysis.' : 'Unpack in an isolated lab (dynamic unpacking) before further analysis.' });
    for (const p of sigs.filter((s) => !packers.includes(s))) add('packer-signature', `Signature string for ${p}`);
    for (const s of info.sections) {
      const loc = `section ${s.name || '?'}`;
      if (s.rawSize > 512 && (s.entropy >= 7.2 && s.execute || s.entropy >= 7.6 && !/^\.rsrc$/i.test(s.name))) add('high-entropy-section', `${loc} entropy ${s.entropy}${s.execute ? ' (executable)' : ''}`, { location: loc });
      if (s.write && s.execute) add('rwx-section', `${loc} is writable and executable`, { location: loc, fix: 'Legitimate compilers rarely emit W+X sections; typical of packers and self-modifying code.' });
      if (s.execute && s.rawSize === 0 && s.virtualSize > 4096) add('virtual-only-section', `${loc} has no raw data but ${s.virtualSize} bytes of virtual size`, { location: loc });
    }
    const epSec = info.sections.find((s) => s.name === info.entrySection);
    if (!info.flags.dll || info.entryPoint) {
      if (!epSec) add('entrypoint-anomaly', `Entry point 0x${info.entryPoint.toString(16)} is outside every section`);
      else if (!epSec.execute) add('entrypoint-anomaly', `Entry point is in non-executable section ${epSec.name}`, { location: `section ${epSec.name}` });
      else if (info.sections.length > 2 && epSec === info.sections[info.sections.length - 1]) add('entrypoint-anomaly', `Entry point is in the last section (${epSec.name}), typical of packers and file infectors`, { location: `section ${epSec.name}` });
    }
    if (info.tlsCallbacks) add('tls-callbacks', `${info.tlsCallbacks} TLS callback(s)`);
    if (info.overlay) {
      const emb = ['pe', 'mz-dos', 'zip', '7z', 'rar', 'cab', 'elf'].includes(info.overlay.magic);
      add(emb ? 'embedded-executable' : 'overlay', `${info.overlay.size} bytes of overlay at 0x${info.overlay.offset.toString(16)} (entropy ${info.overlay.entropy}${emb ? `, looks like ${info.overlay.magic}` : ''})`, { severity: emb ? undefined : info.overlay.entropy > 7.5 && info.overlay.size > 4096 ? 'medium' : undefined });
    }
    const ts = info.timestamp;
    if (!ts) add('timestamp-anomaly', 'Compile timestamp is zero');
    else if (ts * 1000 > now.getTime() + 86400000) add('timestamp-anomaly', `Compile timestamp ${info.timestampIso} is in the future`);
    else if (ts < 788918400) add('timestamp-anomaly', `Compile timestamp ${info.timestampIso} is before 1995 (forged, or a reproducible-build hash)`);
    if (info.checksum) { const lf = buf.readUInt32LE(0x3c); const actual = peChecksum(buf, lf + 24 + 64); if (actual !== info.checksum) add('checksum-mismatch', `Header checksum 0x${info.checksum.toString(16)} != computed 0x${actual.toString(16)} (file modified after linking)`); }
    if (!info.flags.aslr) add('no-aslr', 'DYNAMIC_BASE (ASLR) not set', { fix: 'Link with /DYNAMICBASE.' });
    if (!info.flags.nx) add('no-nx', 'NX_COMPAT (DEP) not set', { fix: 'Link with /NXCOMPAT.' });
    if (!info.flags.cfg && !info.dotnet) add('no-cfg', 'Control Flow Guard not enabled', { fix: 'Compile and link with /guard:cf.' });
    if (!info.signed) add('unsigned', 'No Authenticode signature');
    if (info.dotnet) add('dotnet', '.NET assembly: native imports say little, use a .NET decompiler (ILSpy, dnSpy)');
    if (info.importError) add('header-anomaly', `Import table: ${info.importError}`);
  } else {
    const hd = info.hardening;
    Object.assign(summary, { format: `ELF${info.bits} ${info.machine} ${info.type}`, interpreter: info.interpreter, needed: info.needed, importHash: info.importHash, hardening: Object.entries(hd).map(([k, v]) => `${k}=${v}`).join(' '), sections: info.sections.length });
    const upx = sigs.includes('UPX');
    for (const p of sigs) add('packer-signature', `Signature string for ${p}`, { fix: p === 'UPX' ? 'Unpack with "upx -d" in an isolated lab.' : undefined });
    for (const s of info.sections) if (s.size > 512 && s.entropy >= 7.2 && (s.execute || s.entropy >= 7.6)) add('high-entropy-section', `section ${s.name} entropy ${s.entropy}`, { location: `section ${s.name}` });
    const loads = info.segments.filter((s) => s.type === 'LOAD');
    for (const s of loads) if (s.write && s.execute) add('rwx-section', `LOAD segment at ${s.vaddr} is RWX`, { location: `segment ${s.vaddr}` });
    if (!info.sections.length && loads.length) {
      const e = Math.max(...loads.filter((s) => s.fileSize).map((s) => entropy(buf, s.offset, Math.min(buf.length, s.offset + s.fileSize))));
      if (e >= 7.2 && !upx) add('high-entropy-section', `LOAD segment entropy ${e} with no section headers`);
    }
    if (info.type === 'executable' || info.type === 'shared-object') {
      if (!info.entryInLoad && info.entryPoint !== '0x0') add('entrypoint-anomaly', `Entry point ${info.entryPoint} is outside every LOAD segment`);
      else if (info.sections.length && info.entrySection && !/^\.(text|init|plt)/.test(info.entrySection)) add('entrypoint-anomaly', `Entry point is in section ${info.entrySection}`);
      if (info.type === 'executable' && info.interpreter) add('no-aslr', 'Not a position-independent executable (PIE)', { fix: 'Build with -fPIE -pie.' });
      if (hd.execStack) add('no-nx', 'Executable stack (PT_GNU_STACK RWX or missing)', { fix: 'Link with -z noexecstack.' });
      if (info.interpreter || info.needed.length) {
        if (hd.relro !== 'full') add('no-relro', `RELRO is ${hd.relro}`, { fix: 'Link with -Wl,-z,relro,-z,now.' });
        if (!hd.canary) add('no-canary', 'No __stack_chk_fail import', { fix: 'Compile with -fstack-protector-strong.' });
      }
    }
    for (const [k, v] of [['RPATH', info.rpath], ['RUNPATH', info.runpath]]) if (v) for (const p of v.split(':')) if (!p.startsWith('/') && !p.startsWith('$ORIGIN') || /^\/(tmp|var\/tmp|dev\/shm)(\/|$)/.test(p) || p === '') add('unsafe-rpath', `${k} contains "${p}"`, { fix: 'Use absolute, root-owned paths or $ORIGIN.' });
  }
  // capabilities
  const names = info.format === 'pe' ? info.imports.flatMap((i) => i.functions.map((f) => f.name).filter(Boolean)) : info.imports;
  const caps = capabilities(names); info.capabilities = caps;
  const set = new Set(names.map((n) => n.replace(/(?<=[a-z])(A|W)$/, '')));
  const inj = INJECTION_SETS.find((g) => g.every((a) => set.has(a)));
  if (inj) add('injection-imports', `Imports ${inj.join(' + ')} (classic remote process injection)`, { evidence: 'ATT&CK T1055' });
  const crtOnly = (c) => c.id === 'anti-debug' && c.apis.every((a) => /^(IsDebuggerPresent|OutputDebugString[AW]?)$/.test(a)); // MSVC CRT imports these
  const flagged = caps.filter((c) => !crtOnly(c)).filter((c) => !['network', 'execution', 'discovery', 'memory-exec', 'dynamic-loading', 'crypto'].includes(c.id) && !(inj && c.id === 'injection'));
  for (const c of flagged) add('suspicious-imports', `${c.label}: ${c.apis.slice(0, 6).join(', ')}`, { evidence: `ATT&CK ${c.attack}`, location: `capability ${c.id}` });
  const dyn = caps.find((c) => c.id === 'dynamic-loading');
  if (dyn && names.length < 15 && (info.format === 'pe' ? dyn.apis.some((a) => /GetProcAddress/i.test(a)) : dyn.apis.includes('dlsym'))) add('dynamic-api-resolution', `Only ${names.length} imports, including ${dyn.apis.join(', ')}`, { fix: 'The real imports are resolved at run time; unpack or emulate to recover them.' });
  summary.capabilities = caps.map((c) => `${c.label} (${c.attack})`);
  return { info, raw, summary };
}
