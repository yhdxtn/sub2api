// Never propagate provider responses, Playwright errors, URLs containing query
// strings, or credential values into terminal output or backend progress.
export class WorkerError extends Error {
  constructor(code, { unknown = false, terminal = false } = {}) {
    super(code);
    this.name = 'WorkerError';
    this.code = code;
    this.unknown = unknown;
    this.terminal = terminal;
  }
}

export function safeCode(error, fallback = 'WORKER_FAILED') {
  return error instanceof WorkerError ? error.code : fallback;
}

export function assertAlive(signal) {
  if (signal?.aborted) throw new WorkerError('WORKER_STOPPED', { terminal: true });
}

export function delay(ms, signal) {
  assertAlive(signal);
  return new Promise((resolve, reject) => {
    const cleanup = () => signal?.removeEventListener('abort', abort);
    const timer = setTimeout(() => { cleanup(); resolve(); }, ms);
    function abort() {
      clearTimeout(timer);
      cleanup();
      reject(new WorkerError('WORKER_STOPPED', { terminal: true }));
    }
    signal?.addEventListener('abort', abort, { once: true });
  });
}
