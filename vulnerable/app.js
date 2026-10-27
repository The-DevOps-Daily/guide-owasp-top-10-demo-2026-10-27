// The "before" version of the demo app. Each route below has the flaw that the
// guide part named in its comment explains. It exists to show what scanners and
// tests catch. Never deploy it: server.js binds it to 127.0.0.1 only.
import { exec } from 'node:child_process';
import express from 'express';
import { authenticate, login } from '../src/auth.js';

export function createVulnerableApp({ db, log }) {
  const app = express(); // A02: no security headers, X-Powered-By: Express
  app.use(express.json());

  app.get('/', (req, res) => {
    res.send('<h1>Invoices demo</h1><p><a href="/hello?name=reader">Say hello</a></p>');
  });

  // A05: user input written into HTML without encoding (cross-site scripting)
  app.get('/hello', (req, res) => {
    res.send(`<p>Hello, ${req.query.name}!</p>`);
  });

  // A07: no limit on login attempts
  app.post('/api/login', login({ db, log }));
  app.use('/api', authenticate({ db }));

  // A01: any logged-in user can read any invoice by changing the ID
  app.get('/api/invoices/:id', (req, res) => {
    const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json(invoice);
  });

  // A05: user input concatenated into SQL
  app.get('/api/invoices', (req, res) => {
    const sql = `SELECT * FROM invoices WHERE user_id = ${req.user.id} AND memo = '${req.query.memo}'`;
    res.json(db.prepare(sql).all());
  });

  // A01: an admin function that only checks for a login, not for the admin role
  app.get('/api/admin/users', (req, res) => {
    res.json(db.prepare('SELECT id, name, role FROM users ORDER BY id').all());
  });

  // A06: the client sends the total and the server believes it
  app.post('/api/orders', (req, res) => {
    const { totalCents } = req.body;
    const { lastInsertRowid } = db
      .prepare('INSERT INTO orders (user_id, total_cents) VALUES (?, ?)')
      .run(req.user.id, totalCents);
    res.status(201).json({ orderId: Number(lastInsertRowid), totalCents });
  });

  // A08: every field in the request body is copied onto the user (mass assignment)
  app.patch('/api/profile', (req, res) => {
    const user = db
      .prepare('SELECT name, role, display_name AS displayName FROM users WHERE id = ?')
      .get(req.user.id);
    Object.assign(user, req.body);
    db.prepare('UPDATE users SET role = ?, display_name = ? WHERE id = ?').run(
      user.role,
      user.displayName,
      req.user.id
    );
    res.json(user);
  });

  // A01 (SSRF): the server fetches any URL it is given
  app.post('/api/preview', async (req, res) => {
    const page = await fetch(req.body.url);
    const html = await page.text();
    res.json({ status: page.status, title: /<title>(.*?)<\/title>/i.exec(html)?.[1] ?? null });
  });

  // A05: user input in a shell command
  app.get('/api/lookup', (req, res) => {
    exec(`nslookup ${req.query.host}`, (err, stdout) => res.type('text').send(stdout));
  });

  // A10: the debit stays when the credit fails
  app.post('/api/transfers', (req, res) => {
    const { from, to, amountCents } = req.body;
    db.prepare(
      'UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ? AND user_id = ?'
    ).run(amountCents, from, req.user.id);
    const { changes } = db
      .prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?')
      .run(amountCents, to);
    if (changes !== 1) throw new Error(`account ${to} not found`);
    res.status(201).json({ from, to, amountCents });
  });

  // A02 and A10: no error handler of its own, so Express's default handler
  // answers, and outside production it sends the stack trace to the client.
  return app;
}
