import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { createBox } from '../src/crypto-box.js';
import { hashPassword, verifyPassword } from '../src/passwords.js';

describe('A04 cryptographic failures', () => {
  const v1 = randomBytes(32);
  const v2 = randomBytes(32);
  const oldBox = createBox({ keys: { v1 }, current: 'v1' });
  const box = createBox({ keys: { v1, v2 }, current: 'v2' });

  it('round-trips a value with AES-256-GCM', () => {
    const sealed = box.seal('IBAN DE89 3704 0044 0532 0130 00', 'invoice:1001');
    assert.equal(box.open(sealed, 'invoice:1001'), 'IBAN DE89 3704 0044 0532 0130 00');
  });

  it('detects a changed ciphertext', () => {
    const [version, iv, tag, data] = box.seal('amount=100', 'invoice:1001').split('.');
    const bytes = Buffer.from(data, 'base64url');
    bytes[0] ^= 0x01; // flip one bit of the ciphertext
    const tampered = [version, iv, tag, bytes.toString('base64url')].join('.');
    assert.throws(() => box.open(tampered, 'invoice:1001'), /unable to authenticate/);
  });

  it('refuses a ciphertext copied to another record', () => {
    const sealed = box.seal('amount=100', 'invoice:1001');
    assert.throws(() => box.open(sealed, 'invoice:1002'), /unable to authenticate/);
  });

  it('opens data sealed with the previous key and flags it for rotation', () => {
    const old = oldBox.seal('legacy', 'invoice:7');
    assert.equal(box.open(old, 'invoice:7'), 'legacy');
    assert.equal(box.needsRotation(old), true);
  });

  it('hashes passwords with Argon2id and a random salt', async () => {
    const a = await hashPassword('correct horse battery staple');
    const b = await hashPassword('correct horse battery staple');
    assert.match(a, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    assert.notEqual(a, b);
    assert.equal(await verifyPassword('correct horse battery staple', a), true);
    assert.equal(await verifyPassword('Correct horse battery staple', a), false);
  });
});
