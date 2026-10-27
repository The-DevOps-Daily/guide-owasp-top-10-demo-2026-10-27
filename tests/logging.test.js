import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A09 security logging', () => {
  let app;
  before(async () => {
    app = await startApp();
  });
  after(() => app.close());

  it('logs a failed login as one event, without the password', async () => {
    await app.call('POST', '/api/login', { body: { name: 'alice', password: 'hunter2-guess' } });
    const events = app.logs.filter((l) => l.event?.startsWith('authn_login_fail'));
    assert.equal(events.length, 1);
    assert.equal(events[0].event, 'authn_login_fail:alice');
    assert.doesNotMatch(JSON.stringify(app.logs), /hunter2-guess/);
  });

  it('keeps a name with a line break inside one JSON log line', async () => {
    const name = 'bob\n{"event":"authn_login_success:admin"}';
    await app.call('POST', '/api/login', { body: { name, password: 'x' } });
    assert.ok(app.logs.some((l) => l.event === `authn_login_fail:${name}`));
    assert.ok(!app.logs.some((l) => l.event === 'authn_login_success:admin'));
  });
});
