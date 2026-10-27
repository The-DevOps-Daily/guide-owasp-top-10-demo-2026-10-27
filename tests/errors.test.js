import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A02 and A10: errors and exceptional conditions', () => {
  let app, alice;
  const balances = () =>
    app.db
      .prepare('SELECT id, balance_cents FROM accounts ORDER BY id')
      .all()
      .map((a) => ({ ...a }));
  before(async () => {
    app = await startApp();
    alice = await app.loginAs('alice');
  });
  after(() => app.close());

  it('sends security headers and no X-Powered-By', async () => {
    const res = await app.call('GET', '/');
    assert.ok(res.headers.get('content-security-policy'));
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-powered-by'), null);
  });

  it('rolls back the debit when the credit fails', async () => {
    const before = balances();
    const res = await app.call('POST', '/api/transfers', {
      token: alice,
      body: { from: 1, to: 999, amountCents: 2500 },
    });
    assert.equal(res.status, 404);
    assert.deepEqual(balances(), before);
  });

  it('refuses an overdraft and keeps both balances', async () => {
    const before = balances();
    const res = await app.call('POST', '/api/transfers', {
      token: alice,
      body: { from: 1, to: 2, amountCents: 1_000_000 },
    });
    assert.equal(res.status, 409);
    assert.deepEqual(balances(), before);
  });

  it('answers malformed JSON with 400 and no stack trace', async () => {
    const res = await app.call('POST', '/api/transfers', { token: alice, body: '{"from": 1,' });
    assert.equal(res.status, 400);
    assert.doesNotMatch(res.text, /at .*\.js:\d+/);
    assert.ok(res.json.requestId);
  });

  it('refuses a request body over 10 kB', async () => {
    const res = await app.call('PATCH', '/api/profile', {
      token: alice,
      body: { displayName: 'x'.repeat(20_000) },
    });
    assert.equal(res.status, 413);
  });
});
