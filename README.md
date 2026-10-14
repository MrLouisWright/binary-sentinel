# binary-sentinel

> Static PE and ELF triage in pure JavaScript: headers, sections, entropy, imports, imphash, packer hints, capabilities and hardening checks.

`binary-sentinel` gives an analyst a quick first look at a Windows PE (EXE/DLL/SYS, 32- and 64-bit) or Linux/Unix ELF file without leaving the terminal or CI. The same parser can also check your own release binaries for missing hardening (ASLR, DEP/NX, CFG, PIE, RELRO, stack canaries). **Samples are only ever read as bytes and are never executed or loaded.**

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**, no native code.

## What it extracts

**PE**: machine, bitness, subsystem, compile timestamp, entry point and its section, image base, DLL characteristics (ASLR, high-entropy VA, DEP, CFG, NO_SEH, AppContainer), data directories, sections (name, sizes, RWX flags, **Shannon entropy**, MD5), **imports** (including delay-load imports and ordinals), **imphash** (same algorithm as `pefile`, verified against it), exports, **TLS callbacks**, **Rich header** (entries + hash), **overlay** (offset, size, entropy, embedded file type), Authenticode presence, .NET (CLR) detection and the header **checksum** (recomputed).

**ELF**: class, endianness, OS ABI, type, machine, entry point, program headers (with RWX), sections and their entropy, interpreter, `DT_NEEDED` libraries, SONAME, RPATH/RUNPATH, dynamic imports/exports, an import hash (MD5 of sorted imported symbols), stripped state, and checksec-style hardening: PIE, NX, RELRO (none/partial/full), BIND_NOW, stack canary and FORTIFY_SOURCE.

Every file also gets its MD5/SHA1/SHA256/SHA512, overall entropy and a magic-byte type (also recognises Mach-O, ZIP, PDF, OLE, LNK, RAR, 7z, CAB, ISO, scripts…).

## Rules

| Rule | Default | What it means |
|---|---|---|
| `packer-section` | high | Section names of UPX, ASPack, PECompact, MPRESS, NsPack, Themida/WinLicense, VMProtect, Enigma, Petite, FSG, MEW, Obsidium and more |
| `packer-signature` | high | Packer/protector strings (`UPX!`, `PECompact2`, `ConfuserEx`…) |
| `rwx-section` | high | Writable + executable section or LOAD segment |
| `entrypoint-anomaly` | high | Entry point outside every section, in a non-executable section or in the last section |
| `embedded-executable` | high | Overlay contains another PE/ELF or archive (droppers, installers) |
| `injection-imports` | high | Classic injection API combinations (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread, process hollowing…) |
| `high-entropy-section` | medium | Executable section ≥ 7.2 bits/byte, or any section ≥ 7.6 |
| `dynamic-api-resolution` | medium | Fewer than 15 imports including GetProcAddress/dlsym |
| `virtual-only-section` | medium | Executable section with no raw data but a large virtual size |
| `tls-callbacks` | medium | Code that runs before the entry point |
| `suspicious-imports` | medium | Capability groups mapped to ATT&CK: injection (T1055), keylogging (T1056.001), screen capture (T1113), credential access (T1003), downloads (T1105), registry/service persistence (T1547.001/T1543.003), token manipulation (T1134), anti-debugging (T1622), clipboard (T1115), log clearing (T1070.001) |
| `header-anomaly` | medium | Truncated or malformed headers, imports outside the file, no ELF section table |
| `unsafe-rpath` | medium | RPATH/RUNPATH that is relative or in /tmp, /var/tmp, /dev/shm |
| `overlay` | low (medium if high-entropy) | Data after the last section |
| `timestamp-anomaly`, `checksum-mismatch` | low | Forged/zero/future timestamps; file modified after linking |
| `no-aslr`, `no-nx`, `no-relro` | low | Missing hardening (high in `--profile hardening`) |
| `no-cfg`, `no-canary`, `unsigned`, `dotnet`, `unsupported-format` | info | Context |

Network, process, discovery, crypto and memory APIs are listed as capabilities in the summary but do not raise findings on their own, because almost every program uses them. `IsDebuggerPresent` on its own is ignored because the MSVC CRT imports it.

### Profiles

- `--profile triage` (default): for malware triage and incoming-file screening.
- `--profile hardening`: for your own build artefacts. Missing ASLR/NX/RPATH safety becomes high, RELRO/canary medium, and capability findings drop to info.

## Install and run

```bash
npx binary-sentinel suspicious.exe
npx binary-sentinel ./samples --format json --json triage.json   # JSON includes full headers/sections/imports
npx binary-sentinel dist/ --profile hardening --fail-on high      # CI gate for your own binaries
```

## Library

```js
import { parsePE, parseELF, triage, capabilities, entropy } from 'binary-sentinel';
import { readFileSync } from 'node:fs';

const pe = parsePE(readFileSync('sample.exe'));
pe.imphash; pe.sections.map((s) => [s.name, s.entropy]); pe.tlsCallbacks; pe.overlay;

const report = triage(['samples/'], { profile: 'triage' });
```

## Configuration

Put a `.binary-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "packer-section": "high" },
  "allow": [
    { "rule": "packer-section", "match": "*vendor-installer.exe", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `packer-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/binary-sentinel@v1
    with:
      targets: 'dist/'
      fail-on: high
      sarif: binary-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: binary-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `profile`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
