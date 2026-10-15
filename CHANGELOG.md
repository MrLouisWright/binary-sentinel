# Changelog

## 1.1.0 (2026-10-15)

- Mach-O support: thin and universal binaries, segments/sections, dylibs, rpaths, code signature (ad-hoc / Developer ID / team), PIE, stack execution, canary, dylib-hijack risk, Mach task injection imports.
- Capabilities now come from capa-style rule files (`rules/builtin.yml`). Load your own with `--rules <file|dir>` (api, import, export, string, substring, section, format, os, arch, match, and/or/not/optional/N-or-more); matches are reported as `capability-rule`.
- Authenticode verification: image hash, message digest and signer signature, nested signatures, chain, timestamp and validity (`signature-invalid`, `signature-untrusted`, `signature-expired`). `--no-verify-signatures` to skip.
- PE resources and version info: embedded executables in resources, high-entropy resources, `version-info-mismatch` and `masquerading`.
- New reusable API: `parseMachO`, `verifyAuthenticode`, `parseResources`, `parseVersionInfo`, `loadRules`, `parseRules`, `matchRules`, `featuresOf`, `extractStrings`, `resolveRules`.
- Dual ESM + CommonJS build with generated type declarations.

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Pure-JS PE parser: headers, DLL characteristics, data directories, sections with entropy, imports (normal, delay-load, ordinals), pefile-compatible imphash, exports, TLS callbacks, Rich header, overlay, checksum, .NET and signature detection.
- Pure-JS ELF parser: program/section headers, dynamic section, imports/exports, import hash, interpreter, RPATH/RUNPATH and checksec-style hardening.
- Packer hints (section names, signatures, entropy, virtual-only sections, entry point placement, dynamic API resolution), capability mapping to MITRE ATT&CK and injection detection.
- `triage` and `hardening` profiles, allowlist with expiry, per-rule severity, text/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
