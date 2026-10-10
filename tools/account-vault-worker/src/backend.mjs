import { randomUUID } from 'node:crypto';
import { WorkerError, assertAlive } from './errors.mjs';
import { validateOrigin, validateTicket } from './security.mjs';

const BASE = '/api/v1/account-vault-worker';

function checkedJob(job) {
  if (!job || typeof job.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(job.id) ||
      !Number.isSafeInteger(job.revision) || job.revision < 0 || typeof job.phase !== 'string' || typeof job.status !== 'string') {
    throw new WorkerError('BACKEND_PROTOCOL_INVALID', { terminal: true });
  }
  return job;
}

export class BackendClient {
  #origin; #ticket; #fetch; #timeout;
  constructor({ origin, ticket, fetchImpl = globalThis.fetch, timeoutMs = 20_000 }) {
    this.#origin = validateOrigin(origin);
    this.#ticket = validateTicket(ticket);
    this.#fetch = fetchImpl;
    this.#timeout = timeoutMs;
  }

  async request(path, body, signal) {
    assertAlive(signal);
    const timeout = path.endsWith('/session/save') ? Math.max(this.#timeout, 70_000) : this.#timeout;
    let response;
    try {
      response = await this.#fetch(this.#origin + BASE + path, {
        method: 'POST', redirect: 'error', cache: 'no-store',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', Authorization: `Bearer ${this.#ticket}` },
        body: JSON.stringify(body), signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout),
      });
    } catch { throw new WorkerError('BACKEND_RESPONSE_UNKNOWN', { unknown: true }); }
    if ([401, 403, 409].includes(response.status)) {
      await response.body?.cancel().catch(() => {});
      throw new WorkerError(response.status === 409 ? 'LEASE_LOST' : 'WORKER_UNAUTHORIZED', { terminal: true });
    }
    if (!response.ok || response.redirected) {
      await response.body?.cancel().catch(() => {});
      throw new WorkerError('BACKEND_REQUEST_FAILED', { unknown: true });
    }
    const chunks = []; let total = 0;
    try {
      for await (const value of response.body ?? []) {
        total += value.length;
        if (total > 256 * 1024) throw new Error('limit');
        chunks.push(value);
      }
      const bytes = Buffer.concat(chunks);
      try {
        const value = JSON.parse(bytes.toString('utf8'));
        if (value?.code !== 0 || !Object.hasOwn(value, 'data')) throw new Error('shape');
        return value.data;
      } finally { bytes.fill(0); }
    } catch { throw new WorkerError('BACKEND_PROTOCOL_INVALID', { unknown: true }); }
    finally { for (const chunk of chunks) chunk.fill(0); }
  }

  async claim(workerId = randomUUID(), signal) {
    const result = await this.request('/claim', { worker_id: workerId }, signal);
    if (result?.job === null) return null;
    checkedJob(result?.job);
    if (typeof result.lease_token !== 'string' || !result.lease_token ||
        typeof result.account?.email !== 'string' || typeof result.account?.password !== 'string' ||
        !Number.isFinite(Date.parse(result.lease_expires_at))) {
      throw new WorkerError('BACKEND_PROTOCOL_INVALID', { terminal: true });
    }
    return result;
  }

  close() { this.#ticket = ''; }
}

// All backend calls for an owned job are serialized. A heartbeat cannot replace
// a newer checkpoint with an older snapshot, and no mutation is retried here.
export class JobSession {
  #client; #lease; #job; #account; #checkpoint; #expires; #chain = Promise.resolve();
  #controller = new AbortController(); #timer; #heartbeatMs; #reason = '';
  #progress = 'working';

  constructor(client, claim, { heartbeatMs = 30_000 } = {}) {
    this.#client = client;
    this.#job = checkedJob(claim.job);
    this.#lease = claim.lease_token;
    this.#account = claim.account;
    this.#checkpoint = claim.checkpoint ?? {};
    this.#expires = Date.parse(claim.lease_expires_at);
    this.#heartbeatMs = heartbeatMs;
  }

  get job() { return this.#job; }
  get account() { return this.#account; }
  get checkpointData() { return this.#checkpoint; }
  get signal() { return this.#controller.signal; }
  get stopReason() { return this.#reason; }

  remember(fields) { this.#checkpoint = { ...this.#checkpoint, ...fields }; }

  checkLease() {
    assertAlive(this.signal);
    if (!this.#lease || Date.now() >= this.#expires) {
      this.stop('LEASE_LOST');
      throw new WorkerError('LEASE_LOST', { terminal: true });
    }
  }

  stop(reason = 'WORKER_STOPPED') {
    this.#reason ||= reason;
    clearInterval(this.#timer);
    this.#controller.abort();
  }

  #accept(value) {
    const job = checkedJob(value.job);
    if (job.id !== this.#job.id || job.revision < this.#job.revision) throw new WorkerError('BACKEND_PROTOCOL_INVALID', { terminal: true });
    this.#job = job;
    if (value.lease_expires_at !== undefined) {
      const expires = Date.parse(value.lease_expires_at);
      if (!Number.isFinite(expires)) throw new WorkerError('BACKEND_PROTOCOL_INVALID', { terminal: true });
      this.#expires = expires;
    }
    return value;
  }

  #call(endpoint, fields = {}, { acceptsJob = false } = {}) {
    const operation = async () => {
      this.checkLease();
      try {
        const result = await this.#client.request(`/${this.#job.id}/${endpoint}`, {
          lease_token: this.#lease, revision: this.#job.revision, ...fields,
        }, this.signal);
        return acceptsJob ? this.#accept(result) : result;
      } catch (error) {
        if (error instanceof WorkerError && error.terminal) this.stop(error.code);
        throw error;
      }
    };
    const result = this.#chain.then(operation, operation);
    this.#chain = result.catch(() => {});
    return result;
  }

  startHeartbeat() {
    this.#timer = setInterval(() => {
      this.heartbeat().catch(error => this.stop(error instanceof WorkerError ? error.code : 'LEASE_LOST'));
    }, this.#heartbeatMs);
    this.#timer.unref?.();
  }

  heartbeat(progress) {
    if (progress !== undefined) {
      if (!['working', 'authorizing', 'exchanging', 'awaiting_user', 'awaiting_navigation', 'awaiting_cloudflare', 'awaiting_provider', 'awaiting_authorization'].includes(progress)) throw new WorkerError('BACKEND_PROGRESS_INVALID');
      this.#progress = progress;
    }
    return this.#call('heartbeat', { progress: this.#progress }, { acceptsJob: true });
  }
  checkpoint(action, data = {}) { return this.#call('checkpoint', { action, ...data }, { acceptsJob: true }); }
  loginCode() { return this.#call('login-code'); }
  activationCode() { return this.#call('activation-code'); }
  authorizeSession() { return this.#call('session/authorize', {}, { acceptsJob: true }); }
  saveSession(oauth) { return this.#call('session/save', { oauth }, { acceptsJob: true }); }
  completeSession() { return this.#call('session/complete', {}, { acceptsJob: true }); }

  async pause(errorCode) {
    clearInterval(this.#timer);
    if (this.#job.status === 'completed' || !this.#lease || ['LEASE_LOST', 'WORKER_UNAUTHORIZED'].includes(this.#reason)) return;
    // Cancellation aborts browser work immediately. A separate, bounded request
    // makes the best-effort pause even after the local AbortController fired.
    try {
      await this.#chain;
      if (this.#job.status === 'completed') return;
      const result = await this.#client.request(`/${this.#job.id}/pause`, {
        lease_token: this.#lease, revision: this.#job.revision, error_code: errorCode,
      });
      this.#job = checkedJob(result);
    } catch { /* Durable intent and server lease expiry remain the recovery source. */ }
  }

  close() {
    this.stop();
    this.#account.password = '';
    this.#checkpoint = {};
    this.#lease = '';
  }
}
