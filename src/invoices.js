import { Router } from 'express';

export function invoiceRoutes({ db, log }) {
  const r = Router();

  // GET /api/invoices/:id: the owner check is part of the query itself.
  r.get('/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id)) return res.status(400).json({ error: 'Invalid id' });
    const invoice = db
      .prepare('SELECT id, amount_cents, memo FROM invoices WHERE id = ? AND user_id = ?')
      .get(id, req.user.id);
    if (!invoice) {
      // 404 for "missing" and "not yours", so IDs cannot be probed.
      log.warn(
        { event: `authz_fail:${req.user.name},invoice ${id}`, ip: req.ip, reqId: req.id },
        'not found'
      );
      return res.status(404).json({ error: 'Not found' });
    }
    res.json(invoice);
  });

  // GET /api/invoices?memo=text: a parameterized query, scoped to the caller.
  r.get('/', (req, res) => {
    const memo = req.query.memo;
    if (typeof memo !== 'string' || memo.length > 100) {
      return res.status(400).json({ error: 'memo must be a string of up to 100 characters' });
    }
    const rows = db
      .prepare('SELECT id, amount_cents, memo FROM invoices WHERE user_id = ? AND memo = ?')
      .all(req.user.id, memo);
    res.json(rows);
  });

  return r;
}
