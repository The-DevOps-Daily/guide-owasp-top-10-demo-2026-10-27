// POST /api/orders: the server sets the price and enforces the business limits.
const MAX_QUANTITY = 10; // a business rule, written down in the user story

export function createOrder({ db }) {
  const product = db.prepare('SELECT id, price_cents FROM products WHERE id = ?');
  const insert = db.prepare('INSERT INTO orders (user_id, total_cents) VALUES (?, ?)');

  return (req, res) => {
    const { productId, quantity } = req.body ?? {};
    if (!Number.isSafeInteger(productId) || !Number.isSafeInteger(quantity)) {
      return res.status(400).json({ error: 'productId and quantity must be integers' });
    }
    if (quantity < 1 || quantity > MAX_QUANTITY) {
      return res.status(422).json({ error: `quantity must be between 1 and ${MAX_QUANTITY}` });
    }
    const p = product.get(productId);
    if (!p) return res.status(404).json({ error: 'Unknown product' });
    // Any price or total in the request body is ignored.
    const totalCents = p.price_cents * quantity;
    const { lastInsertRowid } = insert.run(req.user.id, totalCents);
    res.status(201).json({ orderId: Number(lastInsertRowid), totalCents });
  };
}
