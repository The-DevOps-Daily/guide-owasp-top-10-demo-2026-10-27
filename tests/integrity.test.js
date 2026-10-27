import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A08 data integrity: profile updates', () => {
  let app, alice;
  before(async () => {
    app = await startApp();
    alice = await app.loginAs('alice');
  });
  after(() => app.close());

  it('changes an editable field', async () => {
    const res = await app.call('PATCH', '/api/profile', {
      token: alice,
      body: { displayName: 'Alice A.' },
    });
    assert.equal(res.json.displayName, 'Alice A.');
  });

  it('refuses a field the user must not set', async () => {
    const res = await app.call('PATCH', '/api/profile', {
      token: alice,
      body: { displayName: 'Alice', role: 'admin' },
    });
    assert.equal(res.status, 400);
    const { role } = app.db.prepare("SELECT role FROM users WHERE name = 'alice'").get();
    assert.equal(role, 'user');
  });
});
