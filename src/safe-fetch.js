import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export class SsrfError extends Error {}

// A dns.lookup() call holds a thread pool slot until the resolver answers, even after
// the request that started it has given up. Limit how many run and wait at once.
const MAX_ACTIVE_LOOKUPS = 4;
const MAX_WAITING_LOOKUPS = 32;
let activeLookups = 0;
const waitingLookups = [];

export function boundedLookup(hostname, options, callback) {
  if (activeLookups >= MAX_ACTIVE_LOOKUPS) {
    if (waitingLookups.length >= MAX_WAITING_LOOKUPS) {
      return process.nextTick(callback, new SsrfError('too many DNS lookups'));
    }
    return waitingLookups.push(() => boundedLookup(hostname, options, callback));
  }
  activeLookups++;
  dns.lookup(hostname, options, (...args) => {
    activeLookups--;
    waitingLookups.shift()?.();
    callback(...args);
  });
}

// IPv4 ranges that are not public: "this network", private, shared (CGNAT), loopback,
// link-local (cloud metadata), IETF, documentation, benchmarking, multicast and reserved.
// Source: the IANA IPv4 and IPv6 special-purpose address registries.
const blockedV4 = new net.BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 3],
]) {
  blockedV4.addSubnet(address, prefix, 'ipv4');
}

// IPv6: only global unicast (2000::/3), minus ranges that embed IPv4 or are reserved.
const globalV6 = new net.BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
const blockedV6 = new net.BlockList();
blockedV6.addSubnet('2001::', 23, 'ipv6');
blockedV6.addSubnet('2001:db8::', 32, 'ipv6');
blockedV6.addSubnet('2002::', 16, 'ipv6');
blockedV6.addSubnet('3fff::', 20, 'ipv6');

export function isPublicAddress(address) {
  switch (net.isIP(address)) {
    case 4:
      return !blockedV4.check(address, 'ipv4');
    case 6:
      return globalV6.check(address, 'ipv6') && !blockedV6.check(address, 'ipv6');
    default:
      return false;
  }
}

// Fetches a URL for the server, but only from addresses that isAllowed() accepts.
// The check runs on the address the socket connects to, so a DNS answer that
// changes between a check and the request (DNS rebinding) cannot slip through.
export function createSafeFetch({ isAllowed = isPublicAddress } = {}) {
  function lookup(hostname, options, callback) {
    boundedLookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err);
      const bad = addresses.find((a) => !isAllowed(a.address));
      if (bad) return callback(new SsrfError(`blocked address ${bad.address}`));
      if (options.all) return callback(null, addresses);
      callback(null, addresses[0].address, addresses[0].family);
    });
  }

  return function safeFetch(input, { timeoutMs = 5000, maxBytes = 1_000_000 } = {}) {
    let url;
    try {
      url = new URL(input);
    } catch {
      return Promise.reject(new SsrfError('invalid URL'));
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return Promise.reject(new SsrfError(`scheme ${url.protocol} not allowed`));
    }
    if (url.username || url.password) {
      return Promise.reject(new SsrfError('credentials in URL not allowed'));
    }
    // IP literals never reach lookup(), so check them here.
    const host = url.hostname.replace(/^\[(.*)\]$/, '$1');
    if (net.isIP(host) && !isAllowed(host)) {
      return Promise.reject(new SsrfError(`blocked address ${host}`));
    }
    const client = url.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      let settled = false;
      const settle = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        fn(value);
      };
      const fail = (err) => {
        settle(reject, err);
        req.destroy();
      };
      const req = client.get(url, { lookup, agent: false }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          return fail(new SsrfError('redirects are not followed'));
        }
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) return fail(new SsrfError('response too large'));
          chunks.push(chunk);
        });
        res.on('end', () =>
          settle(resolve, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') })
        );
        res.on('error', fail);
      });
      // One deadline for the whole exchange: lookup, connect, headers and body.
      const deadline = setTimeout(() => fail(new SsrfError('timed out')), timeoutMs);
      req.on('upgrade', (res, socket) => {
        socket.destroy();
        fail(new SsrfError('protocol upgrades are not allowed'));
      });
      req.on('error', fail);
      req.on('close', () => settle(reject, new SsrfError('connection closed early')));
    });
  };
}
