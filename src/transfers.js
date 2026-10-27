// POST /api/transfers: move money between two accounts, all or nothing.
export function transfer({ db, log }) {
  const debit = db.prepare(
    'UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ? AND user_id = ?'
  );
  const credit = db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?');

  return (req, res) => {
    const { from, to, amountCents } = req.body ?? {};
    if (![from, to, amountCents].every(Number.isSafeInteger) || amountCents <= 0 || from === to) {
      return res.status(400).json({ error: 'from, to and a positive amountCents are required' });
    }
    db.exec('BEGIN IMMEDIATE');
    try {
      // The CHECK (balance_cents >= 0) constraint throws on overdraft.
      if (debit.run(amountCents, from, req.user.id).changes !== 1) {
        throw Object.assign(new Error('source account not found'), { status: 404, expose: true });
      }
      if (credit.run(amountCents, to).changes !== 1) {
        throw Object.assign(new Error('destination account not found'), {
          status: 404,
          expose: true,
        });
      }
      db.exec('COMMIT');
    } catch (err) {
      if (db.isTransaction) db.exec('ROLLBACK'); // fail closed: undo the debit too
      log.warn({ event: 'transfer_failed', reason: err.message, user: req.user.name }, 'rollback');
      if (err.errstr === 'constraint failed') {
        throw Object.assign(new Error('insufficient funds'), { status: 409, expose: true });
      }
      throw err;
    }
    res.status(201).json({ from, to, amountCents });
  };
}

// GET /api/accounts: the caller's own accounts.
export function listAccounts({ db }) {
  const mine = db.prepare('SELECT id, balance_cents FROM accounts WHERE user_id = ? ORDER BY id');
  return (req, res) => res.json(mine.all(req.user.id));
}
