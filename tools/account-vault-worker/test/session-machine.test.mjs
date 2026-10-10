import test from 'node:test';
import assert from 'node:assert/strict';
import { runSessionJob } from '../src/session-machine.mjs';

function fixture({ badImport = false, phase = 'login' } = {}) {
  const events = [];
  const raw = { accessToken: 'PUBLIC-SYNTHETIC-TOKEN', sessionToken: 'PUBLIC-SYNTHETIC-SESSION', user: { id: 'user', email: 'test@example.test' } };
  const session = { job: { kind: 'session', phase, status: 'running' }, account: { email: 'test@example.test', password: 'PUBLIC-SYNTHETIC-PASSWORD' }, signal: new AbortController().signal,
    checkLease() {}, async heartbeat() {}, async loginCode() { throw new Error('fixture does not require OTP'); },
    async authorizeSession() { events.push('authorization_started'); return { auth_url: 'synthetic-auth-url' }; },
    async saveSession(oauth) { assert.equal(oauth.code, 'synthetic-code'); assert.deepEqual(Object.keys(oauth).sort(), ['code', 'state']); events.push('saved'); this.job.phase = 'prepared'; },
    async completeSession() { events.push('imported'); if (badImport) throw new Error('synthetic import failure'); this.job = { ...this.job, phase: 'completed', status: 'completed', gateway_account_id: 42 }; },
    async pause() { events.push('paused'); },
  };
  const provider = { async login(options) { assert.equal(options.authorizationOnly, true); events.push('login'); }, async session() { assert.fail('OAuth flow must not read a web Session'); }, async close() { events.push('closed'); },
    async authorizeSession(url) { assert.equal(url, 'synthetic-auth-url'); events.push('authorized'); return { code: 'synthetic-code', state: 'synthetic-state' }; },
    async mfa() { assert.fail('must not read MFA state'); }, async disable() { assert.fail('must not disable MFA'); }, async enroll() { assert.fail('must not enroll MFA'); }, async activate() { assert.fail('must not activate MFA'); },
  };
  return { session, provider, events, raw };
}
test('OAuth-only workflow saves and imports before success, without web Session or MFA calls', async () => {
  const f = fixture(); const result = await runSessionJob(f);
  assert.deepEqual(result, { status: 'completed' });
  assert.deepEqual(f.events, ['login', 'authorization_started', 'authorized', 'saved', 'imported', 'closed']);
  assert.equal(f.raw.accessToken, 'PUBLIC-SYNTHETIC-TOKEN');
});
test('import failure pauses without claiming completion and still closes the owned page', async () => {
  const f = fixture({ badImport: true }); const result = await runSessionJob(f);
  assert.equal(result.status, 'paused');
  assert.deepEqual(f.events, ['login', 'authorization_started', 'authorized', 'saved', 'imported', 'paused', 'closed']);
});
test('blank login recovery still requires OAuth exchange and confirmed import', async () => {
  const f = fixture({ badImport: true });
  f.provider.login = async () => {
    f.events.push('login');
    return { authorizationLoginRequired: true };
  };
  const result = await runSessionJob(f);
  assert.equal(result.status, 'paused');
  assert.deepEqual(f.events, ['login', 'authorization_started', 'authorized', 'saved', 'imported', 'paused', 'closed']);
});
test('durably saved Session can finish import without repeating sign-in or capture', async () => {
  const f = fixture({ phase: 'prepared' }); const result = await runSessionJob(f);
  assert.equal(result.status, 'completed'); assert.deepEqual(f.events, ['imported', 'closed']);
});
