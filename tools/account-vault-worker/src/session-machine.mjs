import { freshCode, pauseCode } from './machine.mjs';
import { WorkerError, safeCode, assertAlive } from './errors.mjs';

// No MFA read, disable, enroll, or activation method is called by this workflow.
export async function runSessionJob({ session, provider, onManual = async () => { throw new WorkerError('LOGIN_MANUAL_REQUIRED'); }, onProgress = () => {} }) {
  const check = () => { assertAlive(session.signal); session.checkLease(); };
  const manual = async reason => {
    const progress = reason === 'LOGIN_CLOUDFLARE_CHALLENGE' ? 'awaiting_cloudflare'
      : reason === 'LOGIN_NAVIGATION_REQUIRED' ? 'awaiting_navigation'
      : reason === 'LOGIN_PROVIDER_REDIRECT' ? 'awaiting_provider'
      : reason === 'LOGIN_OAUTH_CONSENT_REQUIRED' ? 'awaiting_authorization' : 'awaiting_user';
    await session.heartbeat(progress);
    await onManual(reason, session.signal);
    check();
  };
  try {
    check();
    if (session.job.kind !== 'session') throw new WorkerError('JOB_PHASE_UNSUPPORTED');
    if (session.job.phase === 'login') {
      onProgress('login');
      // A stalled web-login redirect can hand off to the system-generated
      // OAuth login in this browser. Only exchanged, identity-checked tokens
      // followed by a confirmed import establish success.
      await provider.login({ email: session.account.email, password: session.account.password, authorizationOnly: true,
        getOldCode: () => freshCode(() => session.loginCode(), session.signal), checkLease: check,
        onManual: manual,
      });
      check();
      onProgress('authorization');
      const authorization = await session.authorizeSession();
      await session.heartbeat('authorizing');
      check();
      const oauth = await provider.authorizeSession(authorization.auth_url, {
        email: session.account.email, password: session.account.password,
        getOldCode: () => freshCode(() => session.loginCode(), session.signal), checkLease: check, onManual: manual,
      });
      check();
      await session.heartbeat('exchanging');
      onProgress('exchange');
      try { await session.saveSession(oauth); }
      finally { oauth.code = ''; oauth.state = ''; }
      if (session.job.phase !== 'prepared') throw new WorkerError('SESSION_NOT_SAVED');
    }
    if (session.job.phase !== 'prepared') throw new WorkerError('JOB_PHASE_UNSUPPORTED');
    onProgress('import');
    await session.completeSession();
    if (session.job.status !== 'completed' || session.job.phase !== 'completed' || !session.job.gateway_account_id) throw new WorkerError('COMPLETION_NOT_CONFIRMED');
    return { status: 'completed' };
  } catch (error) {
    const code = session.stopReason || safeCode(error);
    await session.pause(code.startsWith('SESSION_') ? 'network_error' : pauseCode(code, session.job.phase));
    return { status: 'paused', code };
  } finally {
    await provider?.close();
  }
}
