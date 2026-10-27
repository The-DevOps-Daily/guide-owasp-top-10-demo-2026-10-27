import pino from 'pino';

// JSON lines on stdout: one event per line, ready for a log pipeline.
// Secrets are replaced before the line is written.
export function createLogger(destination) {
  return pino(
    {
      base: { service: 'invoices' },
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'password',
          '*.password',
          'token',
          '*.token',
        ],
        censor: '[REDACTED]',
      },
    },
    destination
  );
}
