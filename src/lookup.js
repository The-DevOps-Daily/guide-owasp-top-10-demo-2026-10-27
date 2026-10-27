import { boundedLookup, isPublicAddress, SsrfError } from './safe-fetch.js';

// GET /api/lookup?host=example.com: a library call instead of a shell command.
const HOSTNAME =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export async function dnsLookup(req, res) {
  const host = req.query.host;
  if (typeof host !== 'string' || !HOSTNAME.test(host)) {
    return res.status(400).json({ error: 'host must be a hostname' });
  }
  try {
    const all = await new Promise((resolve, reject) =>
      boundedLookup(host, { all: true }, (err, result) => (err ? reject(err) : resolve(result)))
    );
    // Internal names and addresses are not the caller's business.
    const addresses = all.map((a) => a.address).filter(isPublicAddress);
    if (addresses.length === 0) return res.status(404).json({ error: 'host not found' });
    res.json({ host, addresses });
  } catch (err) {
    if (err instanceof SsrfError) return res.status(503).json({ error: 'busy, try again' });
    res.status(404).json({ error: 'host not found' });
  }
}
