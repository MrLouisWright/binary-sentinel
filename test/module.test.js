import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
const req = createRequire(import.meta.url);
test('index: ESM import and CJS require expose the same API', async () => {
  const esm = await import('../dist/index.js');
  const cjs = req('../dist/index.cjs');
  assert.ok(Object.keys(esm).length > 0);
  assert.deepEqual(Object.keys(cjs).filter((k) => k !== 'default').sort(), Object.keys(esm).filter((k) => k !== 'default').sort());
  assert.ok(existsSync(new URL('../dist/index.d.ts', import.meta.url)));
});
