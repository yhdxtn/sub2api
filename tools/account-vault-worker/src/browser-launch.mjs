import { WorkerError } from './errors.mjs';

export function browserLaunchOptions(platform = process.platform, configured = process.env.ACCOUNT_VAULT_BROWSER_CHANNEL) {
  const channel = configured || (platform === 'win32' ? 'msedge' : 'chromium');
  if (channel !== 'msedge' && channel !== 'chromium') throw new WorkerError('BROWSER_CHANNEL_INVALID');
  return { headless: false, chromiumSandbox: true, ...(channel === 'msedge' ? { channel: 'msedge' } : {}) };
}

export function browserLaunchFailure(error, options) {
  const message = typeof error?.message === 'string' ? error.message : '';
  if (options.channel !== 'msedge') return 'BROWSER_START_FAILED_RUN_INSTALL_BROWSER';
  if (/executable (?:does not|doesn.t) exist|not found|could not find/i.test(message)) return 'BROWSER_EDGE_NOT_FOUND';
  if (/timeout|timed out/i.test(message)) return 'BROWSER_EDGE_START_TIMEOUT';
  if (/target page, context or browser has been closed|browser has been closed|process exited/i.test(message)) return 'BROWSER_EDGE_CLOSED_ON_START';
  if (/spawn|eacces|access is denied/i.test(message)) return 'BROWSER_EDGE_SPAWN_FAILED';
  return 'BROWSER_EDGE_START_FAILED';
}
