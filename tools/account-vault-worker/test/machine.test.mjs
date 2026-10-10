import test from 'node:test';
import assert from 'node:assert/strict';
import { runJob, freshCode } from '../src/machine.mjs';
import { WorkerError } from '../src/errors.mjs';

const EMAIL = 'account@example.test';
const OLD = { enabled: true, enabledV2: true, defaultId: 'old', ids: ['old'] };
const OFF = { enabled: false, enabledV2: false, defaultId: '', ids: [] };
const NEW = { enabled: true, enabledV2: true, defaultId: 'new', ids: ['new'] };

function harness(options = {}) {
  const controller = new AbortController();
  let remote = options.remote ?? 'old';
  let finalCommitLost = false;
  const events = []; const pauses = [];
  const session = {
    job: { id: 'fixture-job', phase: options.phase ?? 'login', status: 'running', revision: 1 },
    account: { email: EMAIL, password: 'public-password-fixture' },
    checkpointData: options.phase ? { upstream_id: 'subject', old_factor_id: 'old', new_factor_id: 'new', session_id: 'fixture-session' } : {},
    signal: controller.signal, stopReason: '',
    stop(reason) { this.stopReason ||= reason; controller.abort(); },
    checkLease() { if (controller.signal.aborted) throw new WorkerError('LEASE_LOST', { terminal: true }); },
    remember(fields) { this.checkpointData = { ...this.checkpointData, ...fields }; },
    async heartbeat(progress) { events.push(progress ? `heartbeat:${progress}` : 'heartbeat'); if (options.saveCommittedButLost) this.job.phase = 'enrolled'; if (finalCommitLost) { controller.abort(); this.stopReason = 'LEASE_LOST'; throw new WorkerError('LEASE_LOST', { terminal: true }); } return { job: this.job }; },
    async pause(code) { if (this.stopReason !== 'LEASE_LOST') pauses.push(code); },
    async loginCode() { events.push('login-code'); return { code: '123456', period: 30, server_time: 1000, expires_at: 30_000 }; },
    async activationCode() {
      events.push('activation-code');
      if (options.loseLeaseAtCode) { controller.abort(); this.stopReason = 'LEASE_LOST'; }
      return { code: '234567', period: 30, server_time: 1000, expires_at: 30_000, session_id: 'fixture-session', factor_id: 'new' };
    },
    async checkpoint(action, data) {
      events.push(`checkpoint:${action}`);
      if (action === 'enrolled' && (options.saveFailure || options.saveCommittedButLost)) throw new WorkerError('BACKEND_RESPONSE_UNKNOWN', { unknown: true });
      if (action === 'verify' && options.finalCommitLost) { finalCommitLost = true; throw new WorkerError('BACKEND_RESPONSE_UNKNOWN', { unknown: true }); }
      const phases = { prepared: 'prepared', disable: 'disable_intent', disabled: 'disabled', enroll: 'enroll_intent', enrolled: 'enrolled', activate: 'activate_intent', verify: 'completed' };
      if (action === 'enrolled') assert.equal(data.enrollment.secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      this.job = { ...this.job, phase: phases[action], revision: this.job.revision + 1, ...(action === 'verify' ? { status: 'completed' } : {}) };
      if (options.loseLeaseAtPermit === action) { controller.abort(); this.stopReason = 'LEASE_LOST'; }
      return { job: this.job, permit: options.missingPermit ? undefined : action, factor_id: 'old' };
    },
  };
  const provider = {
    async login() { events.push('login'); return { id: 'subject', email: options.wrongEmail ? 'other@example.test' : EMAIL }; },
    async identity() { events.push('identity'); return { id: options.wrongSubject || (options.switchAfterPermit && events.includes(`checkpoint:${options.switchAfterPermit}`)) ? 'other-subject' : 'subject', email: EMAIL }; },
    async mfa() { events.push('mfa'); return remote === 'old' ? OLD : remote === 'new' ? NEW : OFF; },
    async disable(id) { assert.equal(id, 'old'); events.push('disable'); remote = 'off'; if (options.disableLost) throw new WorkerError('UPSTREAM_RESPONSE_UNKNOWN', { unknown: true }); },
    async enroll() { events.push('enroll'); return { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', sessionId: 'fixture-session', factorId: 'new' }; },
    async activate() { events.push('activate'); remote = 'new'; if (options.activateLost) throw new WorkerError('UPSTREAM_RESPONSE_UNKNOWN', { unknown: true }); },
    async dismissKnownOnboarding() { events.push('dismiss-onboarding'); },
    async close() { events.push('close'); },
  };
  return { session, provider, events, pauses };
}

test('normal task persists enrollment before obtaining an activation permit and completes once', async () => {
  const fixture = harness();
  assert.equal((await runJob(fixture)).status, 'completed');
  const writes = fixture.events.filter(event => ['disable', 'enroll', 'activate'].includes(event));
  assert.deepEqual(writes, ['disable', 'enroll', 'activate']);
  assert.ok(fixture.events.indexOf('checkpoint:enrolled') < fixture.events.indexOf('checkpoint:activate'));
  assert.ok(fixture.events.indexOf('checkpoint:activate') < fixture.events.indexOf('activate'));
  assert.ok(fixture.events.indexOf('checkpoint:verify') < fixture.events.indexOf('dismiss-onboarding'));
  assert.equal(fixture.events.at(-1), 'close');
});

test('enrollment storage failure or lost acknowledgement never activates', async () => {
  for (const scenario of [{ saveFailure: true }, { saveCommittedButLost: true }]) {
    const fixture = harness(scenario);
    assert.equal((await runJob(fixture)).status, 'paused');
    assert.equal(fixture.events.includes('activate'), false);
    assert.equal(fixture.events.filter(event => event === 'enroll').length, 1);
    assert.equal(fixture.pauses.at(-1), 'storage_failed');
    if (scenario.saveCommittedButLost) assert.equal(fixture.session.job.phase, 'enrolled');
  }
});

test('wrong email or bound upstream subject causes no MFA modifications', async () => {
  for (const scenario of [{ wrongEmail: true }, { wrongSubject: true, phase: 'prepared' }]) {
    const fixture = harness(scenario);
    assert.equal((await runJob(fixture)).status, 'paused');
    assert.equal(fixture.events.some(event => ['disable', 'enroll', 'activate'].includes(event)), false);
    assert.deepEqual(fixture.pauses, ['identity_mismatch']);
  }
});

test('lost disable response resumes by observation without sending disable again', async () => {
  const first = harness({ disableLost: true });
  assert.equal((await runJob(first)).status, 'paused');
  assert.equal(first.session.job.phase, 'disable_intent');
  const recovered = harness({ phase: 'disable_intent', remote: 'off' });
  assert.equal((await runJob(recovered)).status, 'completed');
  assert.equal(recovered.events.includes('disable'), false);
  const unresolved = harness({ phase: 'disable_intent', remote: 'old' });
  assert.equal((await runJob(unresolved)).status, 'paused');
  assert.equal(unresolved.events.some(event => ['disable', 'enroll', 'activate'].includes(event)), false);
});

test('lost activation response resumes only when the exact new factor is confirmed', async () => {
  const first = harness({ activateLost: true });
  assert.equal((await runJob(first)).status, 'paused');
  assert.equal(first.session.job.phase, 'activate_intent');
  const recovered = harness({ phase: 'activate_intent', remote: 'new' });
  assert.equal((await runJob(recovered)).status, 'completed');
  assert.equal(recovered.events.some(event => ['disable', 'enroll', 'activate'].includes(event)), false);
  const unresolved = harness({ phase: 'activate_intent', remote: 'off' });
  assert.equal((await runJob(unresolved)).status, 'paused');
  assert.equal(unresolved.events.includes('activate'), false);
});

test('unknown enrollment cannot be blindly reissued on resume', async () => {
  const fixture = harness({ phase: 'enroll_intent', remote: 'off' });
  assert.equal((await runJob(fixture)).status, 'paused');
  assert.deepEqual(fixture.events, ['close']);
  assert.deepEqual(fixture.pauses, ['enrollment_uncertain']);
});

test('a missing permit or a lost lease prevents the next provider write', async () => {
  for (const scenario of [{ missingPermit: true }, { loseLeaseAtPermit: 'disable' }, { loseLeaseAtPermit: 'enroll' }, { loseLeaseAtCode: true }]) {
    const fixture = harness(scenario);
    assert.equal((await runJob(fixture)).status, 'paused');
    if (scenario.loseLeaseAtPermit === 'enroll') assert.equal(fixture.events.includes('enroll'), false);
    else if (scenario.loseLeaseAtCode) assert.equal(fixture.events.includes('activate'), false);
    else assert.equal(fixture.events.includes('disable'), false);
  }
});

test('identity is checked again after a disable or enroll permit arrives', async () => {
  for (const action of ['disable', 'enroll']) {
    const fixture = harness({ switchAfterPermit: action });
    assert.equal((await runJob(fixture)).status, 'paused');
    assert.equal(fixture.events.includes(action), false);
    assert.equal(fixture.pauses.at(-1), 'identity_mismatch');
  }
});

test('manual login retains the lease and uses only backend-supported progress values', async () => {
  const fixture = harness(); let manual = 0;
  fixture.provider.login = async options => { await options.onManual('LOGIN_MANUAL_REQUIRED'); return { id: 'subject', email: EMAIL }; };
  assert.equal((await runJob({ ...fixture, onManual: async () => { manual++; } })).status, 'completed');
  assert.equal(manual, 1);
  assert.deepEqual(fixture.events.filter(value => value.startsWith('heartbeat:')), ['heartbeat:awaiting_user', 'heartbeat:working']);
});

test('Cloudflare login challenge stays visible as a distinct waiting state', async () => {
  const fixture = harness();
  fixture.provider.login = async options => { await options.onManual('LOGIN_CLOUDFLARE_CHALLENGE'); return { id: 'subject', email: EMAIL }; };
  assert.equal((await runJob({ ...fixture, onManual: async () => false })).status, 'completed');
  assert.deepEqual(fixture.events.filter(value => value.startsWith('heartbeat:')), ['heartbeat:awaiting_cloudflare']);
});

test('an official login redirect reports loading without requesting user action', async () => {
  const fixture = harness();
  fixture.provider.login = async options => { await options.onManual('LOGIN_PROVIDER_REDIRECT'); return { id: 'subject', email: EMAIL }; };
  assert.equal((await runJob({ ...fixture, onManual: async () => false })).status, 'completed');
  assert.deepEqual(fixture.events.filter(value => value.startsWith('heartbeat:')), ['heartbeat:awaiting_provider']);
});

test('failed initial navigation asks the operator to open ChatGPT and retains the lease', async () => {
  const fixture = harness();
  fixture.provider.login = async options => { await options.onManual('LOGIN_NAVIGATION_REQUIRED'); return { id: 'subject', email: EMAIL }; };
  assert.equal((await runJob({ ...fixture, onManual: async () => false })).status, 'completed');
  assert.deepEqual(fixture.events.filter(value => value.startsWith('heartbeat:')), ['heartbeat:awaiting_navigation']);
});

test('resuming activation intent obtains login OTP through login-code, without an activation write', async () => {
  const fixture = harness({ phase: 'activate_intent', remote: 'new' });
  fixture.provider.login = async options => { await options.getOldCode(); return { id: 'subject', email: EMAIL }; };
  assert.equal((await runJob(fixture)).status, 'completed');
  assert.equal(fixture.events.includes('login-code'), true);
  assert.equal(fixture.events.includes('activation-code'), false);
  assert.equal(fixture.events.includes('activate'), false);
});

test('lost final acknowledgement with a cleared lease stops without claiming backend completion or repeating writes', async () => {
  const fixture = harness({ finalCommitLost: true });
  const result = await runJob(fixture);
  assert.equal(result.status, 'paused');
  assert.equal(result.code, 'BACKEND_RESPONSE_UNKNOWN');
  assert.equal(fixture.session.job.phase, 'activate_intent');
  assert.deepEqual(fixture.events.filter(event => ['disable', 'enroll', 'activate'].includes(event)), ['disable', 'enroll', 'activate']);
  assert.equal(fixture.pauses.length, 0);
});

test('activation code is obtained after identity verification, with no intervening network identity check', async () => {
  const fixture = harness();
  assert.equal((await runJob(fixture)).status, 'completed');
  const codeIndex = fixture.events.indexOf('activation-code');
  assert.equal(fixture.events[codeIndex - 1], 'identity');
  assert.equal(fixture.events[codeIndex + 1], 'activate');
});

test('OTP freshness subtracts request RTT using a monotonic clock and rereads before sending', async () => {
  let monotonic = 0; let reads = 0;
  const waits = [];
  const result = await freshCode(async () => {
    reads++;
    monotonic += reads === 1 ? 4000 : 200;
    return { code: reads === 1 ? '111111' : '222222', period: 30, server_time: 1000, expires_at: reads === 1 ? 6000 : 30_000 };
  }, undefined, { now: () => monotonic, wait: async ms => { waits.push(ms); monotonic += ms; } });
  assert.equal(result.code, '222222');
  assert.equal(reads, 2);
  assert.deepEqual(waits, [1150]);
  assert.equal(result.validUntilMono - monotonic, 28_800);
});

test('Ctrl+C from a raw manual prompt aborts the owned session before reporting pause', async () => {
  const fixture = harness();
  fixture.provider.login = async options => { await options.onManual('LOGIN_MANUAL_REQUIRED'); };
  fixture.session.pause = async code => {
    assert.equal(fixture.session.signal.aborted, true);
    assert.equal(code, 'worker_stopped');
  };
  const result = await runJob({ ...fixture, onManual: async () => { throw new WorkerError('WORKER_STOPPED'); } });
  assert.equal(result.status, 'paused');
  assert.equal(fixture.events.some(event => ['disable', 'enroll', 'activate'].includes(event)), false);
});
