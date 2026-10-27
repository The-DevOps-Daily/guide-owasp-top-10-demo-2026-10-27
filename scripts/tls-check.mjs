// Prints the TLS version, cipher and key exchange group that Node.js negotiates.
// Usage: node scripts/tls-check.mjs example.com
import tls from 'node:tls';

const host = process.argv[2];
if (!host) {
  console.error('usage: node scripts/tls-check.mjs <host>');
  process.exit(2);
}
const socket = tls.connect({ host, port: 443, servername: host }, () => {
  const key = socket.getEphemeralKeyInfo();
  console.log(
    `${host}: ${socket.getProtocol()}, ${socket.getCipher().name}, ${key.name ?? key.type}`
  );
  socket.end();
});
socket.setTimeout(10_000, () => socket.destroy(new Error('timed out')));
socket.on('error', (err) => {
  console.error(`${host}: ${err.message}`);
  process.exitCode = 1;
});
