import test from 'node:test';
import assert from 'node:assert/strict';
import { ordinaryClickDelay } from '../src/provider.mjs';
test('ordinary button timing stays in the requested random 1–2 second interval', () => {
  assert.equal(ordinaryClickDelay(() => 0), 1000);
  assert.equal(ordinaryClickDelay(() => 0.5), 1500);
  assert.equal(ordinaryClickDelay(() => 1), 2000);
  for (let i = 0; i < 100; i++) { const wait = ordinaryClickDelay(); assert.ok(wait >= 1000 && wait <= 2000); }
});
