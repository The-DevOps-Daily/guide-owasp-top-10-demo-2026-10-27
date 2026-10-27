import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A01 broken access control', () => {
  let app, alice, admin;
  before(async () => {
    app = await startApp();
    alice = await app.loginAs('alice');
    admin = await app.loginAs('admin');
  });
  after(() => app.close());

  it('rejects requests without a session', async () => {
    assert.equal((await app.call('GET', '/api/invoices/1001')).status, 401);
  });

  it('lets alice read her own invoice', async () => {
    const res = await app.call('GET', '/api/invoices/1001', { token: alice });
    assert.equal(res.status, 200);
    assert.equal(res.json.id, 1001);
  });

  it("does not let alice read bob's invoice", async () => {
    const res = await app.call('GET', '/api/invoices/1002', { token: alice });
    assert.equal(res.status, 404);
  });

  it('keeps the admin user list from regular users', async () => {
    assert.equal((await app.call('GET', '/api/admin/users', { token: alice })).status, 403);
    assert.equal((await app.call('GET', '/api/admin/users', { token: admin })).status, 200);
  });
});
