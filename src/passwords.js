import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const argon2Async = promisify(argon2);

// OWASP Password Storage Cheat Sheet minimum for Argon2id:
// 19 MiB of memory, 2 iterations, 1 degree of parallelism.
const PARAMS = { memory: 19456, passes: 2, parallelism: 1, tagLength: 32 };

const b64 = (buf) => buf.toString('base64').replace(/=+$/, '');

// Returns a PHC-format string: algorithm, version, parameters, salt and hash.
export async function hashPassword(password) {
  const nonce = randomBytes(16);
  const hash = await argon2Async('argon2id', { message: password, nonce, ...PARAMS });
  const { memory: m, passes: t, parallelism: p } = PARAMS;
  return `$argon2id$v=19$m=${m},t=${t},p=${p}$${b64(nonce)}$${b64(hash)}`;
}

export async function verifyPassword(password, phc) {
  try {
    const [, alg, , params, salt, expected] = phc.split('$');
    if (alg !== 'argon2id') return false;
    const p = Object.fromEntries(params.split(',').map((kv) => kv.split('=')));
    const want = Buffer.from(expected, 'base64');
    const got = await argon2Async('argon2id', {
      message: password,
      nonce: Buffer.from(salt, 'base64'),
      memory: Number(p.m),
      passes: Number(p.t),
      parallelism: Number(p.p),
      tagLength: want.length,
    });
    return timingSafeEqual(got, want);
  } catch {
    return false; // a malformed hash never verifies
  }
}

// Used when the user does not exist, so a failed login costs the same time either way.
export const DUMMY_HASH = await hashPassword(randomBytes(32).toString('hex'));
