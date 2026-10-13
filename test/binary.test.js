import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildPE, random } from './helpers.js';
import { parsePE, parseELF, detectType, entropy, capabilities, triage, analyzeBuffer, peChecksum, exitCode } from '../src/index.js';

const FX = new URL('./fixtures/', import.meta.url).pathname;
const BIN = new URL('../bin/binary-sentinel.js', import.meta.url).pathname;
const run = (args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
const rulesOf = (buf, opts) => analyzeBuffer(buf, 'x', { now: '2026-10-14', ...opts }).raw.map((f) => f.rule);

test('entropy and type detection', () => {
  assert.equal(entropy(Buffer.alloc(100)), 0);
  assert.ok(entropy(random(65536)) > 7.9);
  assert.equal(detectType(buildPE()), 'pe');
  assert.equal(detectType(Buffer.from('MZ\0\0')), 'mz-dos');
  assert.equal(detectType(readFileSync(FX + 'elf-hardened')), 'elf');
  assert.equal(detectType(Buffer.from('PK\x03\x04aaaa')), 'zip');
  assert.equal(detectType(Buffer.from('%PDF-1.7')), 'pdf');
  assert.equal(detectType(Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])), 'macho');
  assert.equal(detectType(Buffer.from('#!/bin/sh\n')), 'script');
});

test('PE32 headers, imports, imphash (pefile-compatible), TLS', () => {
  const pe = parsePE(buildPE({ imports: { 'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryA'], 'WS2_32.dll': [23, 4, 'send'], 'foo.ocx': [7] }, tls: 2 }));
  assert.equal(pe.bits, 32); assert.equal(pe.machine, 'i386'); assert.equal(pe.subsystem, 'windows-console');
  assert.deepEqual(pe.sections.map((s) => s.name), ['.text', '.data', '.idata']);
  assert.equal(pe.imports[1].functions[0].ordinal, 23);
  assert.equal(pe.imphash, 'c3230d226d64ef26217a5eb989c5a143'); // verified with pefile 2024.8.26
  assert.equal(pe.tlsCallbacks, 2);
  assert.equal(pe.flags.aslr, true); assert.equal(pe.flags.nx, true);
  assert.equal(pe.timestampIso, '2023-11-14T22:13:20.000Z');
});

test('PE32+ imphash matches pefile', () => {
  const pe = parsePE(buildPE({ bits: 64, imports: { 'user32.dll': ['MessageBoxW'], 'advapi32.DLL': ['RegSetValueExW'] } }));
  assert.equal(pe.bits, 64); assert.equal(pe.machine, 'amd64');
  assert.equal(pe.imphash, '7f6ac87788373d21830704db0a7fca2e');
});

test('clean PE has only informational findings', () => {
  const r = rulesOf(buildPE({ dllChars: 0xc160, imports: { 'KERNEL32.dll': ['GetStdHandle', 'WriteFile', 'ExitProcess', 'HeapAlloc', 'HeapFree', 'GetLastError', 'CloseHandle', 'ReadFile', 'CreateFileW', 'GetCommandLineW', 'SetLastError', 'GetModuleHandleW', 'FlushFileBuffers', 'GetFileType', 'LCMapStringW', 'IsDebuggerPresent'] } }));
  assert.deepEqual(r, ['unsigned']);
});

test('packed PE: UPX sections, entropy, RWX, EP in last section, dynamic resolution', () => {
  const buf = buildPE({ sections: [{ name: 'UPX0', chars: 0xe0000080, vsize: 0x20000, raw: false }, { name: 'UPX1', kind: 'rwx', data: random(0x8000) }, { name: '.rsrc', kind: 'rdata', data: Buffer.alloc(0x200, 2) }], entry: 'UPX1', imports: { 'KERNEL32.DLL': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'ExitProcess'] } });
  const r = rulesOf(buf);
  for (const x of ['packer-section', 'high-entropy-section', 'rwx-section', 'virtual-only-section', 'dynamic-api-resolution']) assert.ok(r.includes(x), `${x} in ${r}`);
  const r2 = rulesOf(buildPE({ sections: [{ name: '.text', kind: 'code', data: Buffer.alloc(0x200, 0x90) }, { name: '.data', kind: 'data', data: Buffer.alloc(0x200) }, { name: '.evil', kind: 'code', data: Buffer.alloc(0x200, 0xcc) }], entry: '.evil' }));
  assert.ok(r2.includes('entrypoint-anomaly'));
  assert.ok(rulesOf(buildPE({ entryRva: 0x900000 })).includes('entrypoint-anomaly'));
  assert.ok(rulesOf(buildPE({ entry: '.data' })).includes('entrypoint-anomaly'));
});

test('capabilities and injection', () => {
  const r = analyzeBuffer(buildPE({ imports: { 'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'OpenProcess'], 'USER32.dll': ['SetWindowsHookExW', 'GetAsyncKeyState'], 'ADVAPI32.dll': ['RegSetValueExW', 'CreateServiceW'], 'urlmon.dll': ['URLDownloadToFileW'] } }), 'x');
  const rules = r.raw.map((f) => f.rule);
  assert.ok(rules.includes('injection-imports'));
  const caps = r.info.capabilities.map((c) => c.id);
  for (const c of ['injection', 'keylogging', 'persistence-registry', 'persistence-service', 'download']) assert.ok(caps.includes(c), c);
  assert.ok(r.raw.some((f) => f.rule === 'suspicious-imports' && /T1056\.001/.test(f.evidence)));
  assert.deepEqual(capabilities(['printf', 'malloc']), []);
  assert.deepEqual(capabilities(['CreateProcessA']).map((c) => c.id), ['execution']);
});

test('hardening, timestamps, overlay, checksum, .NET', () => {
  let r = rulesOf(buildPE({ dllChars: 0 }));
  assert.ok(r.includes('no-aslr') && r.includes('no-nx') && r.includes('no-cfg'));
  assert.ok(rulesOf(buildPE({ timestamp: 0 })).includes('timestamp-anomaly'));
  assert.ok(rulesOf(buildPE({ timestamp: 2000000000 })).includes('timestamp-anomaly'));
  assert.ok(rulesOf(buildPE({ timestamp: 708992537 })).includes('timestamp-anomaly'));
  r = analyzeBuffer(buildPE({ overlay: buildPE() }), 'x').raw;
  assert.ok(r.some((f) => f.rule === 'embedded-executable'));
  r = analyzeBuffer(buildPE({ overlay: random(8192) }), 'x').raw.find((f) => f.rule === 'overlay');
  assert.equal(r.severity, 'medium');
  const b = buildPE({ checksum: 0x1234 });
  assert.ok(rulesOf(b).includes('checksum-mismatch'));
  const good = buildPE(); const lf = good.readUInt32LE(0x3c); good.writeUInt32LE(peChecksum(good, lf + 88), lf + 88);
  assert.ok(!rulesOf(good).includes('checksum-mismatch'));
  assert.ok(rulesOf(buildPE({ clr: true })).includes('dotnet'));
});

test('malformed PE is reported, not thrown', () => {
  const b = buildPE(); const t = b.subarray(0, 0x180);
  const r = analyzeBuffer(t, 'trunc');
  assert.ok(r.raw.some((f) => f.rule === 'header-anomaly'));
  const bad = buildPE({ imports: { 'a.dll': ['x'] } }); const lf = bad.readUInt32LE(0x3c); bad.writeUInt32LE(0x7ffffff0, lf + 24 + 96 + 8);
  assert.ok(analyzeBuffer(bad, 'b').raw.some((f) => f.rule === 'header-anomaly'));
});

test('ELF parsing and hardening (gcc-built fixtures)', () => {
  const h = parseELF(readFileSync(FX + 'elf-hardened'));
  assert.equal(h.bits, 64); assert.equal(h.machine, 'x86-64'); assert.equal(h.type, 'shared-object');
  assert.deepEqual(h.hardening, { pie: true, nx: true, execStack: false, relro: 'full', bindNow: true, canary: true, fortify: true });
  assert.ok(h.needed.includes('libc.so.6')); assert.equal(h.stripped, true);
  assert.ok(h.importHash);
  assert.deepEqual(rulesOf(readFileSync(FX + 'elf-hardened')), []);
  const w = parseELF(readFileSync(FX + 'elf-weak'));
  assert.equal(w.type, 'executable'); assert.equal(w.hardening.execStack, true); assert.equal(w.hardening.relro, 'none'); assert.equal(w.runpath ?? w.rpath, '.');
  assert.ok(w.imports.includes('ptrace') && w.imports.includes('execve'));
  const r = rulesOf(readFileSync(FX + 'elf-weak'));
  for (const x of ['no-aslr', 'no-nx', 'no-relro', 'no-canary', 'unsafe-rpath', 'suspicious-imports']) assert.ok(r.includes(x), x);
});

test('ELF packer signature and missing sections', () => {
  const b = Buffer.from(readFileSync(FX + 'elf-hardened'));
  b.write('UPX!', 0x200, 'latin1');
  assert.ok(rulesOf(b).includes('packer-signature'));
  // zero the section header table pointer
  b.writeBigUInt64LE(0n, 40); b.writeUInt16LE(0, 60);
  const r = analyzeBuffer(b, 'x').raw;
  assert.ok(r.some((f) => f.rule === 'header-anomaly' && /no section headers/.test(f.message)));
});

test('triage: directories, profiles, allowlist, exit codes', () => {
  const d = mkdtempSync(join(tmpdir(), 'bs-'));
  writeFileSync(join(d, 'a.exe'), buildPE({ dllChars: 0 })); writeFileSync(join(d, 'notes.txt'), 'hello');
  writeFileSync(join(d, 'p.dll'), buildPE({ sections: [{ name: 'UPX0', kind: 'rwx', data: random(4096) }] }));
  let rep = triage([d], { now: '2026-10-14' });
  assert.equal(rep.targets.length, 2);
  assert.equal(exitCode(rep, 'high'), 1);
  rep = triage([join(d, 'a.exe')], { profile: 'hardening' });
  assert.equal(rep.findings.find((f) => f.rule === 'no-aslr').severity, 'high');
  rep = triage([join(d, 'p.dll')], { allow: [{ rule: '*', target: '*p.dll', reason: 'known packed vendor DLL', expires: '2099-01-01' }], now: '2026-10-14' });
  assert.equal(rep.findings.length, 0);
  assert.equal(exitCode(triage([join(d, 'missing')]), 'none'), 2);
  assert.throws(() => triage([d], { profile: 'x' }), /Unknown profile/);
  const one = triage([join(d, 'notes.txt')]); assert.equal(one.findings.length, 0);
  assert.equal(triage([{ name: 'mem', buffer: buildPE() }], { details: true }).targets[0].data.format, 'pe');
});

test('CLI', () => {
  let r = run([FX, '--no-color', '--fail-on', 'none']); assert.equal(r.status, 0); assert.match(r.stdout, /elf-weak/);
  r = run([FX + 'elf-weak', '--profile', 'hardening']); assert.equal(r.status, 1);
  r = run([FX + 'elf-hardened', '-f', 'json']); assert.equal(r.status, 0); assert.equal(JSON.parse(r.stdout).targets[0].data.format, 'elf');
  r = run([FX + 'elf-weak', '-f', 'sarif', '--fail-on', 'none']); assert.ok(JSON.parse(r.stdout).runs[0].results.length >= 5);
  assert.equal(run([]).status, 2); assert.equal(run(['--profile', 'zzz', FX]).status, 2);
  assert.match(run(['--list-rules']).stdout, /packer-section/);
});
