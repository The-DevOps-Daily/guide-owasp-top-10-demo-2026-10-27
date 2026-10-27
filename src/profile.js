// PATCH /api/profile: copy only the fields a user may change.
const EDITABLE = new Set(['displayName']);

export function updateProfile({ db, log }) {
  return (req, res) => {
    const body = req.body ?? {};
    const rejected = Object.keys(body).filter((k) => !EDITABLE.has(k));
    if (rejected.length > 0) {
      log.warn(
        { event: `input_validation_fail:${rejected},${req.user.name}`, ip: req.ip, reqId: req.id },
        'profile'
      );
      return res.status(400).json({ error: `not editable: ${rejected.join(', ')}` });
    }
    const { displayName } = body;
    if (typeof displayName !== 'string' || displayName.length < 1 || displayName.length > 50) {
      return res.status(400).json({ error: 'displayName must be 1 to 50 characters' });
    }
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, req.user.id);
    const user = db
      .prepare('SELECT name, role, display_name AS displayName FROM users WHERE id = ?')
      .get(req.user.id);
    res.json(user);
  };
}
