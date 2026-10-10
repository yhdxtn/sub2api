import { spawn } from 'node:child_process';
import { access, lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { WorkerError, delay } from './errors.mjs';

const PREFIX = 'sub2api-vault-edge-';
const EDGE_SUFFIX = join('Microsoft', 'Edge', 'Application', 'msedge.exe');

export async function findEdgeExecutable(env = process.env) {
  for (const prefix of [env['PROGRAMFILES(X86)'], env.PROGRAMFILES, env.LOCALAPPDATA]) {
    if (!prefix) continue;
    const candidate = join(prefix, EDGE_SUFFIX);
    try { await access(candidate, constants.X_OK); return candidate; } catch { /* Try the next standard install path. */ }
  }
  throw new WorkerError('BROWSER_EDGE_NOT_FOUND');
}

function browserEnvironment(source) {
  const keys = ['SystemRoot', 'WINDIR', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP', 'HOMEDRIVE', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PATH'];
  return Object.fromEntries(keys.filter(key => source[key]).map(key => [key, source[key]]));
}

async function removeOwnedProfile(profile) {
  const root = resolve(tmpdir());
  const target = resolve(profile);
  if (!target.startsWith(root + sep) || !basename(target).startsWith(PREFIX)) return;
  try {
    const info = await lstat(target);
    if (!info.isDirectory() || info.isSymbolicLink()) return;
    const actual = await realpath(target);
    if (actual !== target || !actual.startsWith(root + sep)) return;
    await rm(target, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
  } catch { /* A stopped browser may still be releasing Windows file handles. */ }
}

async function availableLoopbackPort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose, rejectClose) => server.close(error => error ? rejectClose(error) : resolveClose()));
  return port;
}

export async function launchPrivateEdge(chromium, signal) {
  const executable = await findEdgeExecutable();
  const profile = await mkdtemp(join(tmpdir(), PREFIX));
  const port = await availableLoopbackPort();
  const child = spawn(executable, [
    `--user-data-dir=${profile}`,
    '--remote-debugging-address=127.0.0.1', `--remote-debugging-port=${port}`,
    '--inprivate', '--no-first-run', '--no-default-browser-check',
    'https://chatgpt.com/',
  ], { env: browserEnvironment(process.env), stdio: 'ignore', windowsHide: false });
  let browser;
  let closed = false;
  let spawnFailed = false;
  child.on('error', () => { spawnFailed = true; });
  const close = async () => {
    if (closed) return;
    closed = true;
    await browser?.close().catch(() => {});
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([
        new Promise(resolveExit => child.once('exit', resolveExit)),
        new Promise(resolveTimeout => setTimeout(resolveTimeout, 5000)),
      ]);
    }
    await removeOwnedProfile(profile);
  };
  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (signal?.aborted || child.exitCode !== null || spawnFailed) throw new WorkerError('BROWSER_EDGE_CLOSED_ON_START');
      try {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1000) });
        const version = await response.json();
        if (response.ok && typeof version.webSocketDebuggerUrl === 'string' && /^Edg\//.test(version.Browser)) {
          ready = true;
          break;
        }
      } catch { /* Edge has not opened its local debugging endpoint yet. */ }
      await delay(150, signal);
    }
    if (!ready) throw new WorkerError('BROWSER_EDGE_START_TIMEOUT');
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 15_000 });
    const context = browser.contexts()[0];
    if (!context) throw new WorkerError('BROWSER_EDGE_CONTEXT_UNAVAILABLE');
    const page = context.pages()[0] ?? await context.waitForEvent('page', { timeout: 10_000 });
    if (!page) throw new WorkerError('BROWSER_EDGE_PAGE_UNAVAILABLE');
    return { browser, context, page, close };
  } catch (error) {
    await close();
    if (error instanceof WorkerError) throw error;
    throw new WorkerError('BROWSER_EDGE_CDP_START_FAILED');
  }
}
