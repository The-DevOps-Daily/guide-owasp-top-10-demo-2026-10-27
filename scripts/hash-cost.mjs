// Compares the cost of a fast hash (SHA-256) with a password hash (Argon2id)
// on this machine. A password cracker pays the same price per guess.
import { argon2Sync, createHash, randomBytes } from 'node:crypto';

const N = 1_000_000;
let t = process.hrtime.bigint();
for (let i = 0; i < N; i++) createHash('sha256').update(`guess-${i}`).digest();
const shaMs = Number(process.hrtime.bigint() - t) / 1e6;

const params = { memory: 19456, passes: 2, parallelism: 1, tagLength: 32 };
t = process.hrtime.bigint();
for (let i = 0; i < 10; i++) {
  argon2Sync('argon2id', { message: `guess-${i}`, nonce: randomBytes(16), ...params });
}
const argonMs = Number(process.hrtime.bigint() - t) / 1e6 / 10;

const perSecond = (ms) => Math.round(1000 / ms).toLocaleString('en-US');
console.log(`SHA-256:  ${perSecond(shaMs / N).padStart(9)} guesses per second`);
console.log(`Argon2id: ${perSecond(argonMs).padStart(9)} guesses per second (19 MiB, t=2, p=1)`);
