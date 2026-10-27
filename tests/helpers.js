import { once } from 'node:events';
import { Writable } from 'node:stream';
import { createApp } from '../src/app.js';
import { openDb } from '../src/db.js';
import { createLogger } from '../src/logger.js';
import { createVulnerableApp } from '../vulnerable/app.js';

export const PASSWORD = 'correct horse battery staple'; // test data only

// Starts the app on a free port. APP=vulnerable runs the same tests against
// the "before" version, to show which ones it fails.
export async function startApp(options = {}) {
  const logs = [];
  const sink = new Writable({
    write(chunk, encoding, done) {
      for (const line of chunk.toString().split('\n').filter(Boolean)) logs.push(JSON.parse(line));
      done();
    },
  });
  const log = createLogger(sink);
  const db = await openDb({ demoPassword: PASSWORD });
  const make = process.env.APP === 'vulnerable' ? createVulnerableApp : createApp;
  const server = make({ db, log, ...options }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(method, path, { token, body, headers = {} } = {}) {
    const res = await fetch(base + path, {
      method,
      redirect: 'manual',
      headers: {
        ...(body !== undefined && { 'content-type': 'application/json' }),
        ...(token && { authorization: `Bearer ${token}` }),
        ...headers,
      },
      body: body === undefined || typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, headers: res.headers, text, json };
  }

  async function loginAs(name) {
    const res = await call('POST', '/api/login', { body: { name, password: PASSWORD } });
    if (res.status !== 200) throw new Error(`login as ${name} failed: ${res.status}`);
    return res.json.token;
  }

  const close = () => new Promise((resolve) => server.close(resolve));
  return { base, db, logs, call, loginAs, close };
}
