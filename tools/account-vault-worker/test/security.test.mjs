import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { validateOrigin, validateTicket, assertIdentity, normalizeMfa, isNewFactorConfirmed, parseEnrollment } from '../src/security.mjs';
import { readHiddenLine } from '../src/terminal.mjs';

test('backend origin permits HTTPS and loopback HTTP but rejects credential or path-bearing URLs', () => {
  for (const origin of ['https://panel.example.test', 'http://localhost:8080', 'http://127.0.0.1:8080', 'http://[::1]:8080']) assert.equal(validateOrigin(origin), origin);
  for (const origin of ['http://panel.example.test', 'https://user:password@panel.example.test', 'https://panel.example.test/api/v1', 'https://panel.example.test/?token=test', 'https://panel.example.test/#fragment', 'file:///tmp/test', '//panel.example.test']) assert.throws(() => validateOrigin(origin));
  assert.equal(validateTicket('avw1_' + 'x'.repeat(43)).length, 48);
  for (const ticket of ['', 'short', 'public token with spaces but long enough', 'x'.repeat(8193), 'eyJhbGciOiJIUzI1NiJ9.public.admin-token']) assert.throws(() => validateTicket(ticket));
});

test('activation proof requires both flags, a single matching new factor and default', () => {
  const valid = { enabled: true, enabledV2: true, defaultId: 'new', ids: ['new'] };
  assert.equal(isNewFactorConfirmed(valid, 'old', 'new'), true);
  for (const changed of [{ ...valid, enabled: false }, { ...valid, enabledV2: false }, { ...valid, defaultId: 'old' }, { ...valid, ids: ['old', 'new'] }, { ...valid, ids: ['other'] }]) assert.equal(isNewFactorConfirmed(changed, 'old', 'new'), false);
  assert.equal(isNewFactorConfirmed(valid, 'new', 'new'), false);
  assert.throws(() => normalizeMfa({ mfa_enabled: true, factors: { totp: [] } }));
  assert.throws(() => normalizeMfa({ mfa_enabled: true, mfa_enabled_v2: true, factors: { totp: [{ id: 'old', factor_type: 'sms', is_recovery: false }] } }));
});

test('identity response shape errors are distinct from a verified email mismatch', () => {
  assert.equal(assertIdentity({ id: 'fixture-id', email: 'ACCOUNT@example.test' }, 'account@example.test').id, 'fixture-id');
  assert.throws(() => assertIdentity({ email: 'account@example.test' }, 'account@example.test'), error => error.code === 'ACCOUNT_IDENTITY_RESPONSE_MISSING_ID');
  assert.throws(() => assertIdentity({ id: 'fixture-id', email: 'other@example.test' }, 'account@example.test'), error => error.code === 'ACCOUNT_IDENTITY_MISMATCH');
});

test('enrollment accepts null email and only a distinct, complete TOTP candidate', () => {
  const payload = { email: null, secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', session_id: 'fixture-session', factor: { id: 'new', factor_type: 'totp' } };
  assert.equal(parseEnrollment(payload, 'account@example.test', 'old').factorId, 'new');
  for (const changed of [{ ...payload, email: 'other@example.test' }, { ...payload, session_id: '' }, { ...payload, secret: 'not a seed' }, { ...payload, factor: { id: 'old', factor_type: 'totp' } }]) assert.throws(() => parseEnrollment(changed, 'account@example.test', 'old'));
});

test('ticket stdin is not echoed and remains out of terminal output', async () => {
  const input = new PassThrough(); const output = new PassThrough(); let shown = '';
  output.on('data', chunk => { shown += chunk; });
  const hidden = readHiddenLine({ input, output });
  input.end('PUBLIC-CONNECTION-TICKET-CANARY-123456\n');
  assert.equal(await hidden, 'PUBLIC-CONNECTION-TICKET-CANARY-123456');
  assert.equal(shown.includes('CANARY'), false);
});

test('Ctrl+C aborts a hidden prompt without echoing its partially entered ticket', async () => {
  const input = new PassThrough(); const output = new PassThrough(); let shown = '';
  output.on('data', chunk => { shown += chunk; });
  const hidden = readHiddenLine({ input, output });
  input.end('PUBLIC-CANARY\u0003');
  await assert.rejects(hidden, error => error.code === 'WORKER_STOPPED');
  assert.equal(shown.includes('CANARY'), false);
});
