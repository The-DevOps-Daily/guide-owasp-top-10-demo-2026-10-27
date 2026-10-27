import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { PASSWORD, startApp } from './helpers.js';

describe('A07 authentication failures', () => {
  let app;
  before(async () => {
    app = await startApp();
  });
  after(() => app.close());

  const login = (name, password) => app.call('POST', '/api/login', { body: { name, password } });

  it('gives the same answer for a wrong password and an unknown user', async () => {
    const wrong = await login('alice', 'not the password');
    const unknown = await login('mallory', 'not the password');
    assert.equal(wrong.status, 401);
    assert.deepEqual(wrong.json, unknown.json);
  });

  it('issues a new random session ID at each login', async () => {
    const a = await app.loginAs('bob');
    const b = await app.loginAs('bob');
    assert.match(a, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(a, b);
  });

  it('ends the session on the server at logout', async () => {
    const token = await app.loginAs('bob');
    assert.equal((await app.call('POST', '/api/logout', { token })).status, 204);
    assert.equal((await app.call('GET', '/api/invoices/1002', { token })).status, 401);
  });

  it('blocks a client after 5 failed logins in 15 minutes', async () => {
    // Two failures already happened in the first test.
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await login('alice', `guess-${i}`)).status);
    assert.deepEqual(statuses, [401, 401, 401, 429]);
    // The limit applies to the client, so even the right password waits.
    assert.equal((await login('alice', PASSWORD)).status, 429);
  });
});
