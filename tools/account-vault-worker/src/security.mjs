import { WorkerError } from './errors.mjs';

export function validateOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new WorkerError('BACKEND_ORIGIN_INVALID'); }
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username || parsed.password ||
      parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new WorkerError('BACKEND_ORIGIN_INVALID');
  }
  return parsed.origin;
}

export function validateTicket(value) {
  if (typeof value !== 'string' || !/^avw1_[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new WorkerError('WORKER_TICKET_INVALID');
  }
  return value;
}

export function canonicalEmail(value) {
  if (typeof value !== 'string') throw new WorkerError('ACCOUNT_IDENTITY_INVALID');
  return value.trim().toLowerCase();
}

export function assertIdentity(value, expectedEmail) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_EMPTY');
  if (!Object.hasOwn(value, 'id')) {
    if (value.user && typeof value.user === 'object') throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_NESTED_USER');
    if (value.data && typeof value.data === 'object') throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_NESTED_DATA');
    if (value.error || value.detail) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_API_ERROR');
    throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_MISSING_ID');
  }
  if (typeof value.id !== 'string' || !value.id || value.id.length > 256) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_INVALID_ID');
  if (!Object.hasOwn(value, 'email')) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_MISSING_EMAIL');
  if (Array.isArray(value.email)) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_EMAIL_ARRAY');
  if (value.email !== null && typeof value.email === 'object') throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_EMAIL_OBJECT');
  if (typeof value.email === 'number') throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_EMAIL_NUMBER');
  if (typeof value.email === 'boolean') throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_EMAIL_BOOLEAN');
  if (typeof value.email !== 'string' || !value.email) throw new WorkerError('ACCOUNT_IDENTITY_RESPONSE_INVALID_EMAIL');
  if (canonicalEmail(value.email) !== canonicalEmail(expectedEmail)) throw new WorkerError('ACCOUNT_IDENTITY_MISMATCH');
  return { id: value.id, email: canonicalEmail(value.email) };
}

export function normalizeMfa(value) {
  if (!value || typeof value.mfa_enabled !== 'boolean' || typeof value.mfa_enabled_v2 !== 'boolean' ||
      !value.factors || !Array.isArray(value.factors.totp) || value.factors.totp.length > 10 ||
      !(value.native_default_factor_id === null || value.native_default_factor_id === undefined || typeof value.native_default_factor_id === 'string')) {
    throw new WorkerError('MFA_RESPONSE_UNSUPPORTED');
  }
  const ids = value.factors.totp.map(factor => {
    if (!factor || factor.factor_type !== 'totp' || factor.is_recovery !== false ||
        typeof factor.id !== 'string' || !factor.id || factor.id.length > 256) {
      throw new WorkerError('MFA_RESPONSE_UNSUPPORTED');
    }
    return factor.id;
  });
  if (new Set(ids).size !== ids.length) throw new WorkerError('MFA_RESPONSE_UNSUPPORTED');
  return { enabled: value.mfa_enabled, enabledV2: value.mfa_enabled_v2, defaultId: value.native_default_factor_id ?? '', ids };
}

export function isNewFactorConfirmed(mfa, oldId, newId) {
  return !!oldId && !!newId && oldId !== newId && mfa.enabled && mfa.enabledV2 &&
    mfa.ids.length === 1 && mfa.ids[0] === newId && mfa.defaultId === newId && !mfa.ids.includes(oldId);
}

export function parseEnrollment(value, expectedEmail, oldFactorId) {
  if (!value || typeof value.secret !== 'string' || value.secret.length < 2 || value.secret.length > 1024 ||
      !/^[A-Za-z2-7]+={0,6}$/.test(value.secret) || typeof value.session_id !== 'string' || !value.session_id ||
      value.session_id.length > 512 || /[\s\x00-\x1f\x7f]/u.test(value.session_id) || value.factor?.factor_type !== 'totp' ||
      typeof value.factor.id !== 'string' || !value.factor.id || value.factor.id.length > 256 || value.factor.id === oldFactorId ||
      !(value.email === null || value.email === undefined || canonicalEmail(value.email) === canonicalEmail(expectedEmail))) {
    throw new WorkerError('ENROLLMENT_RESPONSE_UNSUPPORTED', { unknown: true });
  }
  return { secret: value.secret, sessionId: value.session_id, factorId: value.factor.id };
}
