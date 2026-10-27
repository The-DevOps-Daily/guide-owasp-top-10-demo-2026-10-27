import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createSafeFetch, isPublicAddress } from '../src/safe-fetch.js';
import { startApp } from './helpers.js';

// An "internal" service on 127.0.0.1, and a stand-in for a public site on 127.0.0.2
// that redirects to it. (Linux routes all of 127.0.0.0/8 to the loopback interface.)
async function listen(host, handler) {
  const server = http.createServer(handler).listen(0, host);
  await once(server, 'listening');
  return { server, url: `http://${host}:${server.address().port}` };
}

// Never point the vulnerable variant at these URLs: it would really fetch them.
const skip = process.env.APP === 'vulnerable' && 'runs against the fixed app only';

describe('SSRF: the preview endpoint', { skip }, () => {
  let app, alice, internal, outside;
  before(async () => {
    internal = await listen('127.0.0.1', (req, res) => res.end('<title>internal admin</title>'));
    outside = await listen('127.0.0.2', (req, res) => {
      if (req.url === '/redirect') {
        res.writeHead(302, { location: `${internal.url}/` }).end();
      } else {
        res.end('<title>Public page</title>');
      }
    });
    // In this test only, 127.0.0.2 counts as a public address.
    app = await startApp({ safeFetch: createSafeFetch({ isAllowed: (a) => a === '127.0.0.2' }) });
    alice = await app.loginAs('alice');
  });
  after(() => Promise.all([app.close(), internal.server.close(), outside.server.close()]));

  const preview = (url) => app.call('POST', '/api/preview', { token: alice, body: { url } });

  it('fetches an allowed address', async () => {
    const res = await preview(`${outside.url}/`);
    assert.deepEqual(res.json, { status: 200, title: 'Public page' });
  });

  for (const target of [
    'http://127.0.0.1:PORT/',
    'http://localhost:PORT/',
    'http://[::1]:PORT/',
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
  ]) {
    it(`blocks ${target}`, async () => {
      const res = await preview(target.replace('PORT', internal.server.address().port));
      assert.equal(res.status, 400);
    });
  }

  it('does not follow a redirect to an internal address', async () => {
    const res = await preview(`${outside.url}/redirect`);
    assert.equal(res.status, 400);
  });
});

describe('SSRF: isPublicAddress', () => {
  const cases = {
    '1.1.1.1': true,
    '2606:4700:4700::1111': true,
    '10.0.0.5': false,
    '100.64.0.1': false,
    '127.0.0.1': false,
    '169.254.169.254': false,
    '172.16.3.4': false,
    '192.168.1.1': false,
    '::1': false,
    '::ffff:127.0.0.1': false,
    'fd00::1': false,
    'fe80::1': false,
  };
  for (const [address, expected] of Object.entries(cases)) {
    it(`${address} is ${expected ? 'public' : 'not public'}`, () => {
      assert.equal(isPublicAddress(address), expected);
    });
  }
});
