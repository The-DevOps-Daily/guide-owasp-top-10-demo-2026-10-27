import { DatabaseSync } from 'node:sqlite';
import { hashPassword } from './passwords.js';

// An in-memory database with three users, their invoices and two accounts.
// Every run starts from the same data, so tests and examples are repeatable.
export async function openDb({ demoPassword }) {
  if (!demoPassword || demoPassword.length < 15) {
    throw new Error('DEMO_PASSWORD must be set and at least 15 characters long');
  }
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );
    CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE invoices (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount_cents INTEGER NOT NULL,
      memo TEXT NOT NULL
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      total_cents INTEGER NOT NULL
    );
    CREATE TABLE accounts (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0)
    );
    CREATE TABLE transfers (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      from_account INTEGER NOT NULL,
      to_account INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
  `);

  const hash = await hashPassword(demoPassword);
  const addUser = db.prepare(
    'INSERT INTO users (id, name, role, display_name, password_hash) VALUES (?, ?, ?, ?, ?)'
  );
  addUser.run(1, 'alice', 'user', 'Alice', hash);
  addUser.run(2, 'bob', 'user', 'Bob', hash);
  addUser.run(3, 'admin', 'admin', 'Admin', hash);

  const addInvoice = db.prepare(
    'INSERT INTO invoices (id, user_id, amount_cents, memo) VALUES (?, ?, ?, ?)'
  );
  addInvoice.run(1001, 1, 12000, 'Alice: hosting, October');
  addInvoice.run(1002, 2, 45000, 'Bob: consulting, October');
  addInvoice.run(1003, 2, 9900, 'Bob: domain renewal');

  const addProduct = db.prepare('INSERT INTO products (id, name, price_cents) VALUES (?, ?, ?)');
  addProduct.run(1, 'Conference ticket', 49900);
  addProduct.run(2, 'Workshop seat', 19900);

  const addAccount = db.prepare(
    'INSERT INTO accounts (id, user_id, balance_cents) VALUES (?, ?, ?)'
  );
  addAccount.run(1, 1, 10000);
  addAccount.run(2, 2, 5000);

  return db;
}
