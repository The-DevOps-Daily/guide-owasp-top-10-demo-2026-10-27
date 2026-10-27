import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers.js';

describe('A05 injection', () => {
  let app, alice;
  before(async () => {
    app = await startApp();
    alice = await app.loginAs('alice');
  });
  after(() => app.close());

  it('treats SQL syntax in a filter as data', async () => {
    // The input from the OWASP Top 10:2025 A05 example.
    const memo = encodeURIComponent("' OR '1'='1");
    const res = await app.call('GET', `/api/invoices?memo=${memo}`, { token: alice });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, []);
  });

  it('still finds a real memo', async () => {
    const memo = encodeURIComponent('Alice: hosting, October');
    const res = await app.call('GET', `/api/invoices?memo=${memo}`, { token: alice });
    assert.deepEqual(
      res.json.map((i) => i.id),
      [1001]
    );
  });

  it('rejects a host name with shell syntax', async () => {
    // The input from the OWASP Top 10:2025 A05 command injection example.
    const host = encodeURIComponent('example.com; cat /etc/passwd');
    const res = await app.call('GET', `/api/lookup?host=${host}`, { token: alice });
    assert.equal(res.status, 400);
  });

  it('HTML-encodes user input in pages', async () => {
    const res = await app.call('GET', `/hello?name=${encodeURIComponent('<b>Ann</b>')}`);
    assert.match(res.text, /Hello, &lt;b&gt;Ann&lt;\/b&gt;!/);
  });
});
