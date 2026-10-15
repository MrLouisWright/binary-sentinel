import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildPE, buildMachO, buildFat, buildResourceSection, buildVersionInfo, random } from './helpers.js';
import { parseMachO, isMachO, verifyAuthenticode, parseResources, parseVersionInfo, parseRules, loadRules, matchRules, featuresOf, parseYaml, analyzeBuffer, triage, parsePE, BUILTIN_RULES, CAPABILITIES, capabilities, detectType } from '../src/index.js';

const FX = new URL('./fixtures/', import.meta.url).pathname;
const BIN = new URL('../bin/binary-sentinel.js', import.meta.url).pathname;
const tmp = () => mkdtempSync(join(tmpdir(), 'bs-f-'));
const rules = (a) => a.raw.map((r) => r.rule);

test('Mach-O: parse thin binaries', () => {
  const b = buildMachO({ imports: ['printf', 'ptrace', '__stack_chk_fail'], dylibs: ['/usr/lib/libSystem.B.dylib', { name: '@rpath/Foo.dylib', weak: true }], rpaths: ['@executable_path/../Frameworks', '/tmp/lib'], signature: 'adhoc' });
  assert.equal(detectType(b), 'macho'); assert.ok(isMachO(b));
  const m = parseMachO(b);
  assert.equal(m.machine, 'arm64'); assert.equal(m.type, 'executable'); assert.equal(m.flags.pie, true);
  assert.deepEqual(m.imports.sort(), ['__stack_chk_fail', 'printf', 'ptrace']);
  assert.deepEqual(m.dylibs.map((d) => d.kind), ['load', 'weak']);
  assert.deepEqual(m.rpaths, ['@executable_path/../Frameworks', '/tmp/lib']);
  assert.equal(m.entrySegment, '__TEXT'); assert.equal(m.entrySection, '__text');
  assert.equal(m.signature.adhoc, true); assert.equal(m.signature.identifier, 'com.example.tool');
  assert.deepEqual(m.anomalies, []);
});

test('Mach-O: analysis rules and universal binaries', () => {
  const a = analyzeBuffer(buildMachO({ imports: ['printf', 'ptrace'], pie: false, rwx: true, rpaths: ['lib', '/tmp/x'], dylibs: [{ name: '@rpath/A.dylib', weak: true }] }), 'tool');
  const r = rules(a);
  for (const x of ['no-aslr', 'rwx-section', 'unsafe-rpath', 'unsigned', 'no-canary', 'dylib-hijack-risk', 'suspicious-imports']) assert.ok(r.includes(x), `${x} in ${r}`);
  assert.equal(r.filter((x) => x === 'unsafe-rpath').length, 2);
  assert.match(a.summary.format, /Mach-O 64 arm64 executable/);
  const good = analyzeBuffer(buildMachO({ imports: ['printf', '__stack_chk_fail'], signature: 'developer' }), 'ok');
  assert.deepEqual(rules(good), []); assert.equal(good.summary.signature, 'signed');
  assert.ok(rules(analyzeBuffer(buildMachO({ imports: ['__stack_chk_fail'], signature: 'adhoc' }), 'x')).includes('adhoc-signed'));
  const fat = buildFat([buildMachO({ imports: ['__stack_chk_fail'], signature: 'developer' }), buildMachO({ imports: ['task_for_pid', 'mach_vm_write', 'thread_create_running', '__stack_chk_fail'], signature: 'developer' })]);
  assert.equal(detectType(fat), 'macho-fat');
  const fa = analyzeBuffer(fat, 'uni');
  assert.equal(fa.info.slices.length, 2); assert.ok(rules(fa).includes('injection-imports'));
  assert.match(fa.summary.format, /universal/);
  const d = tmp(); writeFileSync(join(d, 'uni'), fat); writeFileSync(join(d, 'readme.txt'), 'hi');
  assert.equal(triage([d]).targets.length, 1);
});

test('Authenticode: valid, nested, chain, tampered, truncated', () => {
  const s = verifyAuthenticode(readFileSync(join(FX, 'signed-selfsigned.exe')));
  assert.equal(s.signed, true); assert.equal(s.valid, true); assert.equal(s.signatures[0].digestAlgorithm, 'sha256');
  assert.equal(s.signatures[0].selfSigned, true); assert.match(s.signatures[0].signer.subject, /binary-sentinel test signer/);
  const n = verifyAuthenticode(readFileSync(join(FX, 'signed-chain-nested.exe')));
  assert.equal(n.valid, true); assert.deepEqual(n.signatures.map((x) => x.digestAlgorithm), ['sha1', 'sha256']);
  assert.deepEqual(n.signatures[0].chain, ['Test Code Signer', 'Test Root CA']); assert.equal(n.signatures[0].selfSigned, false);
  const t = Buffer.from(readFileSync(join(FX, 'signed-selfsigned.exe'))); t[0x44c] ^= 1;
  const tv = verifyAuthenticode(t); assert.equal(tv.valid, false); assert.match(tv.errors[0], /modified after signing/);
  assert.ok(rules(analyzeBuffer(t, 'x.exe')).includes('signature-invalid'));
  const sig = Buffer.from(readFileSync(join(FX, 'signed-selfsigned.exe'))); sig[sig.length - 40] ^= 0xff;
  assert.equal(verifyAuthenticode(sig).valid, false);
  assert.equal(verifyAuthenticode(buildPE()).signed, false);
  const sa = analyzeBuffer(readFileSync(join(FX, 'signed-selfsigned.exe')), 'x.exe');
  assert.ok(rules(sa).includes('signature-untrusted')); assert.ok(!rules(sa).includes('unsigned'));
  assert.ok(rules(analyzeBuffer(readFileSync(join(FX, 'signed-selfsigned.exe')), 'x.exe', { now: '2200-01-01' })).includes('signature-expired'));
  assert.ok(!rules(analyzeBuffer(t, 'x.exe', { verifySignatures: false })).includes('signature-invalid'));
});

test('PE resources and version info', () => {
  const vi = buildVersionInfo({ CompanyName: 'Microsoft Corporation', OriginalFilename: 'notepad.exe', FileVersion: '10.0.1' }, [10, 0, 19041, 1]);
  const v = parseVersionInfo(vi); assert.equal(v.fileVersion, '10.0.19041.1'); assert.equal(v.strings.CompanyName, 'Microsoft Corporation');
  const payload = buildPE();
  const pe = buildPE({ sections: [{ name: '.text', kind: 'code', data: Buffer.alloc(0x200, 0x90) }, { name: '.rsrc', kind: 'rdata', build: (va) => buildResourceSection(va, [{ type: 16, id: 1, data: vi }, { type: 10, id: 101, data: payload }, { type: 10, id: 102, data: random(8192, 3) }]) }], dirs: { resource: '.rsrc' } });
  const info = parsePE(pe);
  assert.deepEqual(info.resources.map((r) => `${r.type}/${r.name}`).sort(), ['RCDATA/101', 'RCDATA/102', 'VERSION/1']);
  assert.equal(info.resources.find((r) => r.name === '101').magic, 'pe'); assert.equal(info.versionInfo.strings.OriginalFilename, 'notepad.exe');
  const a = analyzeBuffer(pe, 'svchost.exe'); const r = rules(a);
  for (const x of ['embedded-executable', 'high-entropy-resource', 'version-info-mismatch', 'masquerading']) assert.ok(r.includes(x), `${x} in ${r}`);
  assert.match(a.summary.version, /Microsoft Corporation/);
  assert.ok(!rules(analyzeBuffer(pe, 'notepad.exe')).includes('version-info-mismatch'));
  assert.deepEqual(parseResources(Buffer.alloc(8), 0, () => -1), []);
});

test('capa-style rules: YAML, combinators, match, unsupported features', () => {
  const y = parseYaml('a:\n  b: 1 # c\n  l:\n    - x: "q # not comment"\n    - y\n---\nz: [1, two]\n');
  assert.deepEqual(y, [{ a: { b: 1, l: [{ x: 'q # not comment' }, 'y'] } }, { z: [1, 'two'] }]);
  const rs = parseRules(`
rule:
  meta:
    name: create thread
    namespace: host-interaction/thread/create
  features:
    - or:
      - api: CreateThread
      - api: kernel32.CreateRemoteThread
---
rule:
  meta:
    name: inject with mapping
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    severity: high
  features:
    - and:
      - match: host-interaction/thread
      - 2 or more:
        - api: MapViewOfFile
        - api: CreateFileMapping
        - string: /evil\\.example/i
      - not:
        - section: .goodsec
      - optional:
        - bytes: 00 11
---
rule:
  meta:
    name: needs bytes
  features:
    - bytes: 00 11 22
`, 't.yml');
  assert.deepEqual(rs[2].unsupported, ['bytes']);
  const pe = buildPE({ imports: { 'kernel32.dll': ['CreateRemoteThread', 'MapViewOfFileEx', 'CreateFileMappingA'] }, sections: [{ name: '.text', kind: 'code', data: Buffer.from('xx EVIL.example.com yy') }] });
  const info = parsePE(pe);
  const m = matchRules(rs, featuresOf(info, pe));
  assert.deepEqual(m.map((x) => x.name), ['create thread', 'inject with mapping']);
  assert.deepEqual(m[1].techniques, ['T1055']);
  assert.ok(m[1].evidence.includes('string: "xx EVIL.example.com yy"'));
  const wrongDll = parseRules('rule:\n  meta:\n    name: x\n  features:\n    - api: user32.CreateRemoteThread\n')[0];
  assert.equal(matchRules([wrongDll], featuresOf(info, pe)).length, 0);
  const d = tmp(); mkdirSync(join(d, 'sub')); writeFileSync(join(d, 'sub', 'r.yml'), 'rule:\n  meta:\n    name: maps file\n    severity: low\n  features:\n    - api: MapViewOfFile\n'); writeFileSync(join(d, 'ignore.txt'), 'x');
  assert.equal(loadRules(d).length, 1);
  const rep = triage([{ name: 'a.exe', buffer: pe }], { rules: [d] });
  const f = rep.findings.find((x) => x.rule === 'capability-rule'); assert.equal(f.severity, 'low'); assert.match(f.message, /maps file/);
  assert.throws(() => triage([], { rules: [join(d, 'missing')] }), /Cannot load rules/);
});

test('built-in capabilities come from rules/builtin.yml', () => {
  assert.equal(BUILTIN_RULES.length, CAPABILITIES.length); assert.ok(CAPABILITIES.length >= 17);
  assert.deepEqual(capabilities(['VirtualAllocEx', 'WriteProcessMemoryW', 'GetAsyncKeyState']).map((c) => c.id), ['injection', 'keylogging', 'memory-exec']);
  assert.equal(CAPABILITIES.find((c) => c.id === 'injection').attack, 'T1055');
});

test('CLI --rules and --no-verify-signatures', () => {
  const d = tmp(); writeFileSync(join(d, 'r.yml'), 'rule:\n  meta:\n    name: exits\n    severity: high\n  features:\n    - api: kernel32.ExitProcess\n');
  const run = (args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
  let r = run([join(FX, 'signed-selfsigned.exe'), '--rules', join(d, 'r.yml')]); assert.equal(r.status, 1); assert.match(r.stdout, /exits.*capability-rule/);
  const t = Buffer.from(readFileSync(join(FX, 'signed-selfsigned.exe'))); t[0x44c] ^= 1; writeFileSync(join(d, 't.exe'), t);
  assert.equal(run([join(d, 't.exe')]).status, 1);
  r = run([join(d, 't.exe'), '--no-verify-signatures']); assert.doesNotMatch(r.stdout, /signature-invalid/);
  assert.match(run(['--help']).stdout, /--rules/);
});
