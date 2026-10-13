# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Pure-JS PE parser: headers, DLL characteristics, data directories, sections with entropy, imports (normal, delay-load, ordinals), pefile-compatible imphash, exports, TLS callbacks, Rich header, overlay, checksum, .NET and signature detection.
- Pure-JS ELF parser: program/section headers, dynamic section, imports/exports, import hash, interpreter, RPATH/RUNPATH and checksec-style hardening.
- Packer hints (section names, signatures, entropy, virtual-only sections, entry point placement, dynamic API resolution), capability mapping to MITRE ATT&CK and injection detection.
- `triage` and `hardening` profiles, allowlist with expiry, per-rule severity, text/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
