import { createHash, randomBytes } from 'node:crypto';
import { DUMMY_HASH, verifyPassword } from './passwords.js';

const SESSION_TTL_MS = 60 * 60 * 1000; // absolute timeout: one hour
const MAX_SESSIONS = 5; // per user
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// POST /api/login: same answer for an unknown user and a wrong password.
export function login({ db, log }) {
  return async (req, res) => {
    const { name, password } = req.body ?? {};
    if (typeof name !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'name and password are required strings' });
    }
    if (name.length > 64 || password.length > 256) {
      return res.status(400).json({ error: 'name or password too long' });
    }
    const user = db.prepare('SELECT id, name, password_hash FROM users WHERE name = ?').get(name);
    const ok = await verifyPassword(password, user?.password_hash ?? DUMMY_HASH);
    if (!user || !ok) {
      log.warn({ event: `authn_login_fail:${name}`, ip: req.ip, reqId: req.id }, 'login failed');
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    // A new random session ID on every login: 32 bytes from the CSPRNG. Expired
    // sessions go, and each user keeps at most MAX_SESSIONS (the oldest end first).
    const token = randomBytes(32).toString('base64url');
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
    db.prepare(
      `DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN (
         SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY expires_at DESC LIMIT ?)`
    ).run(user.id, user.id, MAX_SESSIONS - 1);
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
      sha256(token),
      user.id,
      Date.now() + SESSION_TTL_MS
    );
    log.info({ event: `authn_login_success:${user.name}`, ip: req.ip, reqId: req.id }, 'login');
    res.json({ token, expiresInSeconds: SESSION_TTL_MS / 1000 });
  };
}

// Every protected route runs this first. No valid session, no access.
export function authenticate({ db }) {
  return (req, res, next) => {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.get('authorization') ?? '');
    const row =
      m &&
      db
        .prepare(
          `SELECT u.id, u.name, u.role FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?`
        )
        .get(sha256(m[1]), Date.now());
    if (!row) return res.status(401).json({ error: 'Authentication required' });
    req.user = row;
    req.sessionTokenHash = sha256(m[1]);
    next();
  };
}

// POST /api/logout: the session ends on the server, not only in the client.
export function logout({ db }) {
  return (req, res) => {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.sessionTokenHash);
    res.status(204).end();
  };
}

// Vertical access control: deny unless the role matches.
export function requireRole(role, { log }) {
  return (req, res, next) => {
    if (req.user?.role === role) return next();
    log.warn(
      {
        event: `authz_fail:${req.user?.name},${req.method} ${req.path}`,
        ip: req.ip,
        reqId: req.id,
      },
      'forbidden'
    );
    res.status(403).json({ error: 'Forbidden' });
  };
}
