import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// keys: { v1: <32-byte Buffer>, v2: ... } loaded from a secrets manager or KMS,
// never from source code. New data always uses the current key.
export function createBox({ keys, current }) {
  for (const [version, key] of Object.entries(keys)) {
    if (!/^v\d+$/.test(version)) throw new Error(`bad key version ${version}`);
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new Error(`key ${version} must be 32 bytes`);
    }
  }
  if (!keys[current]) throw new Error(`no key for current version ${current}`);

  // context binds the ciphertext to one record (for example "invoice:1001"),
  // so a ciphertext copied to another row fails to decrypt.
  function seal(plaintext, context) {
    const iv = randomBytes(12); // 96-bit nonce, new for every message
    const cipher = createCipheriv('aes-256-gcm', keys[current], iv);
    cipher.setAAD(Buffer.from(context));
    const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [current, iv, tag, data]
      .map((p) => (Buffer.isBuffer(p) ? p.toString('base64url') : p))
      .join('.');
  }

  function open(sealed, context) {
    const [version, iv, tag, data] = sealed.split('.');
    const key = Object.hasOwn(keys, version) ? keys[version] : undefined;
    if (!key) throw new Error(`unknown key version ${version}`);
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'), {
      authTagLength: 16,
    });
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(data, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  }

  return { seal, open, needsRotation: (sealed) => !sealed.startsWith(`${current}.`) };
}
