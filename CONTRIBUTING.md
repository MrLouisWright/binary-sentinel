# Contributing to `binary-sentinel`

Thanks for helping improve this package. Small, focused changes are welcome.

## Development

```bash
git clone https://github.com/MrLouisWright/binary-sentinel.git
cd binary-sentinel
npm ci
npm test
```

Requires Node.js 18 or newer (see `engines` in `package.json`).

## Pull requests

1. Create a branch from `main` with a clear name (`fix/…`, `docs/…`, `ci/…`).
2. Keep the change scoped to one concern.
3. Run `npm test` (and `npm pack --dry-run` if you touch packaging) before opening the PR.
4. Prefer Conventional Commit style subject lines (`fix: …`, `docs: …`, `ci: …`).
5. Do not bump the package version or publish to npm in the PR — releases are handled separately.

## Reporting issues

Use GitHub Issues. Include the package version, Node version, a minimal reproduction, and the CLI/library output when relevant.

## License

By contributing you agree your work is released under the MIT license already used by this repository.
