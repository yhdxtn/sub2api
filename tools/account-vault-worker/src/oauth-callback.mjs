import { createServer } from 'node:http';
import { WorkerError } from './errors.mjs';

const listeners = new Map();

// One loopback listener serves this helper's concurrent windows. Each page
// captures its own callback and state; no authorization codes are retained here.
export async function registerOAuthCallback(state, origin = 'http://localhost:1455') {
  const redirect = new URL(origin);
  if (redirect.protocol !== 'http:' || redirect.hostname !== 'localhost' || !redirect.port || redirect.origin !== origin) throw new WorkerError('SESSION_AUTHORIZATION_INVALID');
  for (;;) {
    let entry = listeners.get(origin);
    if (entry?.closing) { await entry.closing; continue; }
    if (!entry) {
      entry = { states: new Set(), server: null, ready: null, closing: null };
      listeners.set(origin, entry);
      entry.ready = new Promise((resolve, reject) => {
        const server = entry.server = createServer((request, response) => {
          let valid = false;
          try {
            const url = new URL(request.url, origin);
            valid = request.method === 'GET' && request.headers.host === redirect.host &&
              url.origin === origin && url.pathname === '/auth/callback' &&
              url.href.length <= 16384 && url.searchParams.getAll('state').length === 1 && entry.states.has(url.searchParams.get('state'));
          } catch { /* Reject an invalid local callback. */ }
          response.writeHead(valid ? 200 : 400, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
            'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer' });
          response.end('<!doctype html><meta charset="utf-8"><title>授权结果处理中</title><p>' +
            (valid ? '正在核对授权结果并导入。请保留窗口。' : '此授权回调无效，请回到账号库恢复任务。') + '</p>');
        });
        server.once('error', () => { if (listeners.get(origin) === entry) listeners.delete(origin); reject(new WorkerError('SESSION_CALLBACK_UNAVAILABLE')); });
        server.listen(Number(redirect.port), '127.0.0.1', () => { server.unref(); resolve(); });
      });
    }
    await entry.ready;
    if (entry.closing) { await entry.closing; continue; }
    if (entry.states.has(state)) throw new WorkerError('SESSION_AUTHORIZATION_INVALID');
    entry.states.add(state);
    let released = false;
    return () => {
      if (released) return entry.closing;
      released = true;
      entry.states.delete(state);
      if (entry.states.size) return;
      // Release the fixed callback port once all concurrent jobs finish. Wait
      // for closing before a later job tries to listen on the same port.
      entry.closing = new Promise(resolve => {
        entry.server.close(() => {
          if (listeners.get(origin) === entry) listeners.delete(origin);
          resolve();
        });
        entry.server.closeIdleConnections();
      });
      return entry.closing;
    };
  }
}
