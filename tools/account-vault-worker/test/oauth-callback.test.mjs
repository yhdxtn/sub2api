import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { registerOAuthCallback } from '../src/oauth-callback.mjs';

async function reservePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function status(origin, state) {
  const url = new URL('/auth/callback?code=synthetic&state=' + encodeURIComponent(state), origin);
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: url.port,
      path: url.pathname + url.search, headers: { Host: url.host }, agent: false }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
}

test('concurrent callbacks stay isolated and the port is released and reopened after the last job', async t => {
  const origin = 'http://localhost:' + await reservePort();
  const [releaseA, releaseB] = await Promise.all([
    registerOAuthCallback('state-a', origin), registerOAuthCallback('state-b', origin),
  ]);
  t.after(async () => { await releaseA(); await releaseB(); });
  assert.equal(await status(origin, 'state-a'), 200);
  assert.equal(await status(origin, 'state-b'), 200);
  assert.equal(await status(origin, 'unknown'), 400);
  await releaseA();
  assert.equal(await status(origin, 'state-a'), 400);
  assert.equal(await status(origin, 'state-b'), 200);
  const closing = releaseB();
  // A subsequent job may register while the previous listener is closing.
  const releaseC = await registerOAuthCallback('state-c', origin);
  t.after(releaseC);
  await closing;
  assert.equal(await status(origin, 'state-c'), 200);
  assert.equal(await status(origin, 'state-b'), 400);
  await releaseC();
  const replacement = createServer();
  await new Promise((resolve, reject) => {
    replacement.once('error', reject);
    replacement.listen(Number(new URL(origin).port), '127.0.0.1', resolve);
  });
  await new Promise(resolve => replacement.close(resolve));
});
