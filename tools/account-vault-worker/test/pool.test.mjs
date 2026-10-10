import test from 'node:test';
import assert from 'node:assert/strict';
import { runPool } from '../src/pool.mjs';

const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};

test('two accounts really overlap, with independent completion and bounded capacity', async () => {
  const first = deferred(), second = deferred(), started = deferred();
  let active = 0, peak = 0;
  const queue = [1, 2, 3];
  const events = [];
  const controller = new AbortController();
  const pool = runPool({ concurrency: 2, signal: controller.signal, idleMs: 1,
    claim: async () => queue.shift(),
    run: async id => {
      active++; peak = Math.max(peak, active); events.push(`start${id}`);
      if (id === 1) await first.promise;
      if (id === 2) { started.resolve(); await second.promise; }
      events.push(`close${id}`); active--;
      if (id === 3) controller.abort();
      return true;
    },
  });
  await started.promise;
  assert.equal(active, 2);
  first.resolve();
  // The third task can start while the second waits for its human challenge.
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(events.includes('start3'));
  assert.ok(!events.includes('close2'));
  second.resolve();
  await pool;
  assert.equal(peak, 2);
  assert.equal(active, 0);
  assert.equal(events.filter(event => event.startsWith('close')).length, 3);
});

test('uncertain result stops new claims while another active account finishes', async () => {
  const started = deferred(), uncertain = deferred(), pending = deferred();
  const queue = [1, 2, 3];
  const finished = [];
  const pool = runPool({ concurrency: 2, signal: new AbortController().signal,
    claim: async () => queue.shift(),
    run: async id => {
      if (id === 1) { await started.promise; uncertain.resolve(); return false; }
      started.resolve(); await pending.promise; finished.push(id); return true;
    },
  });
  await uncertain.promise;
  await new Promise(resolve => setImmediate(resolve));
  pending.resolve();
  await pool;
  assert.deepEqual(queue, [3]);
  assert.deepEqual(finished, [2]);
});

test('invalid concurrency is rejected before claiming anything', async () => {
  for (const concurrency of [0, 5, 1.5]) {
    await assert.rejects(runPool({ concurrency, claim: () => assert.fail(), signal: new AbortController().signal }), RangeError);
  }
});
