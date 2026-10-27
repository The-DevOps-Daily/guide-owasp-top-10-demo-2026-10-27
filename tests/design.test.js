import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A06 insecure design: orders', () => {
  let app, alice;
  before(async () => {
    app = await startApp();
    alice = await app.loginAs('alice');
  });
  after(() => app.close());

  const order = (body) => app.call('POST', '/api/orders', { token: alice, body });

  it('ignores a total sent by the client', async () => {
    const res = await order({ productId: 1, quantity: 2, totalCents: 1 });
    assert.equal(res.status, 201);
    assert.equal(res.json.totalCents, 2 * 49900);
  });

  it('enforces the quantity limit from the business rules', async () => {
    assert.equal((await order({ productId: 2, quantity: 600 })).status, 422);
  });
});
