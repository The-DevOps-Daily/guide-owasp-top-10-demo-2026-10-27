import { randomUUID } from 'node:crypto';

// Gives every request an ID that appears in the logs and in error responses.
export function requestId(req, res, next) {
  req.id = randomUUID();
  res.set('X-Request-Id', req.id);
  next();
}

export function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

// One central error handler: full details go to the log, the client gets a
// short message and the request ID, never a stack trace or a SQL error.
export function errorHandler({ log }) {
  // Express recognizes error handlers by their four parameters.
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, next) => {
    const status =
      Number.isInteger(err.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
    if (status >= 500) {
      log.error({ err, reqId: req.id, method: req.method, path: req.path }, 'request failed');
    }
    if (res.headersSent) return req.socket.destroy();
    res.status(status).json({
      error: status >= 500 ? 'Internal error' : err.expose ? err.message : 'Bad request',
      requestId: req.id,
    });
  };
}
