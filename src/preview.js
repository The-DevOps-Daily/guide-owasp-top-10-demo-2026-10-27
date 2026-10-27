import { SsrfError } from './safe-fetch.js';

// POST /api/preview: fetch a page title for a link the user pasted.
export function preview({ safeFetch, log }) {
  return async (req, res) => {
    const { url } = req.body ?? {};
    if (typeof url !== 'string' || url.length > 2048) {
      return res.status(400).json({ error: 'url must be a string' });
    }
    try {
      const page = await safeFetch(url, { timeoutMs: 3000, maxBytes: 512 * 1024 });
      const title = /<title>([^<]{0,200})<\/title>/i.exec(page.body)?.[1] ?? null;
      res.json({ status: page.status, title });
    } catch (err) {
      if (err instanceof SsrfError) {
        log.warn(
          {
            event: `input_validation_fail:url,${req.user.name}`,
            ip: req.ip,
            reqId: req.id,
            reason: err.message,
          },
          'ssrf'
        );
        return res.status(400).json({ error: 'URL not allowed' });
      }
      res.status(502).json({ error: 'Could not fetch the URL' });
    }
  };
}
