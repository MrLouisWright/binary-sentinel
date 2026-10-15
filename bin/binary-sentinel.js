#!/usr/bin/env node
import { runCli, UsageError } from '../src/cli-core.js';
import { triage, TOOL, PROFILES } from '../src/index.js';

const HELP = `binary-sentinel {VERSION} — static PE/ELF triage (headers, sections, entropy, imports, imphash, packers, hardening)

Usage: binary-sentinel <file|dir...> [options]

Samples are only read, never executed. Directories are searched for PE/ELF/Mach-O files by magic bytes.

      --profile <p>          triage (default: packers, capabilities, anomalies) | hardening (ASLR/NX/RELRO/PIE/canary as high)
      --rules <path>         capa-style rule file or directory (repeatable); matches report as capability-rule
      --no-verify-signatures Skip Authenticode verification
      --details              Include full parsed headers, sections and imports in JSON output
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { profile: { type: 'string' }, details: { type: 'boolean' }, rules: { type: 'string', multiple: true }, 'no-verify-signatures': { type: 'boolean' } },
  run(o, pos, cfg) {
    const paths = pos.length ? pos : cfg.paths || [];
    if (!paths.length) throw new UsageError('No file or directory given');
    const profile = o.profile || cfg.profile || 'triage';
    if (!PROFILES[profile]) throw new UsageError(`Invalid --profile ${profile}`);
    return triage(paths, { profile, details: o.details ?? (o.format === 'json' || !!o.json), rules: [...(cfg.rules || []), ...(o.rules || [])], verifySignatures: o['no-verify-signatures'] ? false : cfg.verifySignatures, allow: cfg.allow, severity: cfg.severity });
  },
});
