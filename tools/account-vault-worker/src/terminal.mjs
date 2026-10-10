import { createInterface } from 'node:readline/promises';
import { WorkerError, assertAlive, delay } from './errors.mjs';

export async function askOrigin({ input = process.stdin, output = process.stdout, signal } = {}) {
  if (!input.isTTY) throw new WorkerError('ORIGIN_REQUIRED_USE_FLAG');
  const reader = createInterface({ input, output, terminal: true });
  try { return (await reader.question('后台地址（例如 https://panel.example.com，不含 /api/v1）：', { signal })).trim(); }
  catch { throw new WorkerError('WORKER_STOPPED', { terminal: true }); }
  finally { reader.close(); }
}

// Raw terminal input is not echoed and never goes into a command argument,
// URL, environment variable, file or readline history. A parent process may
// also provide one line through stdin without creating a credential file.
export function readHiddenLine({ input = process.stdin, output = process.stdout, prompt = '连接码（输入隐藏）：', signal, allowEmpty = false } = {}) {
  assertAlive(signal);
  output.write(prompt);
  const raw = !!input.isTTY && typeof input.setRawMode === 'function';
  const previousRaw = input.isRaw;
  const wasPaused = input.isPaused();
  if (raw) input.setRawMode(true);
  input.setEncoding('utf8');
  input.resume();
  return new Promise((resolve, reject) => {
    let text = '';
    let done = false;
    const cleanup = () => {
      input.removeListener('data', onData);
      input.removeListener('end', onEnd);
      input.removeListener('error', onError);
      signal?.removeEventListener('abort', onAbort);
      if (raw) input.setRawMode(previousRaw ?? false);
      if (wasPaused) input.pause();
      output.write('\n');
    };
    const finish = error => {
      if (done) return;
      done = true;
      cleanup();
      const value = text; text = '';
      if (error) reject(error);
      else if (!allowEmpty && !value) reject(new WorkerError('WORKER_TICKET_INVALID'));
      else resolve(value);
    };
    function onData(chunk) {
      for (const character of chunk) {
        if (character === '\u0003') { finish(new WorkerError('WORKER_STOPPED', { terminal: true })); return; }
        if (character === '\r' || character === '\n') { finish(); return; }
        if (character === '\u007f' || character === '\b') { text = text.slice(0, -1); continue; }
        if (character < ' ' || character > '~') { finish(new WorkerError('WORKER_TICKET_INVALID')); return; }
        text += character;
        if (text.length > 8192) { finish(new WorkerError('WORKER_TICKET_INVALID')); return; }
      }
    }
    function onEnd() { finish(); }
    function onError() { finish(new WorkerError('STDIN_UNAVAILABLE')); }
    function onAbort() { finish(new WorkerError('WORKER_STOPPED', { terminal: true })); }
    input.on('data', onData);
    input.on('end', onEnd);
    input.on('error', onError);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export async function waitForManual(signal) {
  // The automatically launched helper has no console. Keep its browser open
  // and recheck the login page until the user finishes any external challenge.
  if (!process.stdin.isTTY) { await delay(1500, signal); return false; }
  await readHiddenLine({
    prompt: '请在当前可见浏览器完成额外验证，然后回到这里按回车继续；Ctrl+C 暂停：',
    signal, allowEmpty: true,
  });
}
