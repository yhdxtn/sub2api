import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { BackendClient, JobSession } from '../src/backend.mjs';

const TICKET = 'avw1_' + 'x'.repeat(43);
const claim = () => ({ job: { id: 'fixture-job', phase: 'login', status: 'running', revision: 1 }, lease_token: 'fixture-lease', lease_expires_at: new Date(Date.now() + 120_000).toISOString(), account: { email: 'account@example.test', password: 'public-password' } });
const response = data => new Response(JSON.stringify({ code: 0, message: '', data }), { status: 200 });

test('backend credentials stay in headers, redirects are refused, and writes are not retried', async () => {
  let calls = 0;
  const backend = new BackendClient({ origin: 'https://panel.example.test', ticket: TICKET, fetchImpl: async (url, options) => {
    calls++;
    assert.equal(url, 'https://panel.example.test/api/v1/account-vault-worker/claim');
    assert.equal(url.includes(TICKET), false);
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, `Bearer ${TICKET}`);
    throw new Error('PUBLIC-ERROR-CANARY');
  } });
  await assert.rejects(backend.claim('fixture-worker'), error => error.code === 'BACKEND_RESPONSE_UNKNOWN' && !error.message.includes('CANARY'));
  assert.equal(calls, 1);
});

test('401, 403 and 409 immediately invalidate the owned lease and abort waits', async () => {
  for (const status of [401, 403, 409]) {
    const backend = new BackendClient({ origin: 'http://localhost:8080', ticket: TICKET, fetchImpl: async () => new Response('{}', { status }) });
    const session = new JobSession(backend, claim());
    await assert.rejects(session.heartbeat());
    assert.equal(session.signal.aborted, true);
    assert.throws(() => session.checkLease());
    session.close();
  }
});

test('heartbeat can recover a newer revision without granting a write permit', async () => {
  const received = [];
  const backend = new BackendClient({ origin: 'http://localhost:8080', ticket: TICKET, fetchImpl: async (_url, options) => {
    received.push(JSON.parse(options.body));
    return response({ job: { ...claim().job, phase: 'enrolled', revision: 7 }, lease_expires_at: claim().lease_expires_at });
  } });
  const session = new JobSession(backend, claim());
  const result = await session.heartbeat('awaiting_user');
  assert.equal(session.job.revision, 7);
  assert.equal(session.job.phase, 'enrolled');
  assert.equal(result.permit, undefined);
  assert.equal(received[0].progress, 'awaiting_user');
  session.close();
});

test('navigation wait sends the supported progress without pausing the task', async () => {
  const received = [];
  const backend = new BackendClient({ origin: 'http://localhost:8080', ticket: TICKET, fetchImpl: async (_url, options) => {
    received.push(JSON.parse(options.body));
    return response({ job: claim().job, lease_expires_at: claim().lease_expires_at });
  } });
  const session = new JobSession(backend, claim());
  await session.heartbeat('awaiting_navigation');
  assert.equal(received[0].progress, 'awaiting_navigation');
  assert.equal(session.signal.aborted, false);
  session.close();
});

test('heartbeat and checkpoint use the latest revision in serialized order', async () => {
  const received = [];
  const backend = new BackendClient({ origin: 'http://localhost:8080', ticket: TICKET, fetchImpl: async (url, options) => {
    const body = JSON.parse(options.body); received.push(body.revision);
    if (url.endsWith('/checkpoint')) { await new Promise(resolve => setTimeout(resolve, 10)); return response({ job: { ...claim().job, phase: 'prepared', revision: 2 } }); }
    return response({ job: { ...claim().job, phase: 'prepared', revision: 2 }, lease_expires_at: claim().lease_expires_at });
  } });
  const session = new JobSession(backend, claim());
  await Promise.all([session.checkpoint('prepared'), session.heartbeat()]);
  assert.deepEqual(received, [1, 2]);
  session.close();
});

test('expired local lease prevents even a backend request', async () => {
  let calls = 0;
  const backend = new BackendClient({ origin: 'http://localhost:8080', ticket: TICKET, fetchImpl: async () => { calls++; return response({}); } });
  const session = new JobSession(backend, { ...claim(), lease_expires_at: new Date(0).toISOString() });
  await assert.rejects(session.checkpoint('disable'));
  assert.equal(calls, 0);
  session.close();
});

test('native Node HTTP fetch does not follow a backend redirect or forward its bearer', async t => {
  let targetRequests = 0;
  const target = createServer((_request, response) => { targetRequests++; response.end('{}'); });
  target.listen(0, '127.0.0.1'); await once(target, 'listening');
  let observedAuthorization = '';
  const source = createServer((request, reply) => {
    observedAuthorization = request.headers.authorization;
    reply.writeHead(307, { Location: `http://127.0.0.1:${target.address().port}/unexpected` }); reply.end();
  });
  source.listen(0, '127.0.0.1'); await once(source, 'listening');
  t.after(async () => { source.closeAllConnections(); target.closeAllConnections(); await Promise.all([new Promise(resolve => source.close(resolve)), new Promise(resolve => target.close(resolve))]); });
  const client = new BackendClient({ origin: `http://127.0.0.1:${source.address().port}`, ticket: TICKET });
  await assert.rejects(client.claim('fixture-worker'), error => error.code === 'BACKEND_RESPONSE_UNKNOWN');
  assert.equal(observedAuthorization, `Bearer ${TICKET}`);
  assert.equal(targetRequests, 0);
});
