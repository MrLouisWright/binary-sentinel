// Dual ESM + CJS build with esbuild; .d.ts generated from source by tsc (JSDoc-aware).
import * as esbuild from 'esbuild';
import { rmSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
const ENTRIES = ["index"];
rmSync('dist', { recursive: true, force: true }); mkdirSync('dist');
const shared = { bundle: true, platform: 'node', target: 'node18', packages: 'external', legalComments: 'none', logLevel: 'warning' };
for (const e of ENTRIES) {
  await esbuild.build({ ...shared, entryPoints: [`src/${e}.js`], outfile: `dist/${e}.js`, format: 'esm' });
  await esbuild.build({ ...shared, entryPoints: [`src/${e}.js`], outfile: `dist/${e}.cjs`, format: 'cjs',
    banner: { js: "const __importMetaUrl = require('node:url').pathToFileURL(__filename).href;" },
    define: { 'import.meta.url': '__importMetaUrl' } });
}
const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
execFileSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], { stdio: 'inherit' });
for (const e of ENTRIES) if (existsSync(`dist/${e}.d.ts`)) copyFileSync(`dist/${e}.d.ts`, `dist/${e}.d.cts`);
console.log('built', ENTRIES.join(', '));
