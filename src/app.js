import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { authenticate, login, logout, requireRole } from './auth.js';
import { errorHandler, notFound, requestId } from './errors.js';
import { invoiceRoutes } from './invoices.js';
import { dnsLookup } from './lookup.js';
import { createOrder } from './orders.js';
import { hello, home } from './pages.js';
import { preview } from './preview.js';
import { updateProfile } from './profile.js';
import { createSafeFetch } from './safe-fetch.js';
import { listAccounts, transfer } from './transfers.js';

export function createApp({ db, log, safeFetch = createSafeFetch() }) {
  const app = express();
  // Security headers; helmet also removes X-Powered-By. The CSP replaces helmet's
  // "https:" and "data:" sources with 'self', since this app loads nothing else.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          'font-src': ["'self'"],
          'img-src': ["'self'"],
          'style-src': ["'self'"],
          'frame-ancestors': ["'none'"],
        },
      },
    })
  );
  app.use((req, res, next) => {
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
  app.use(requestId);
  app.use(express.json({ limit: '10kb' })); // nothing without a limit
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store'); // API responses hold private data and tokens
    next();
  });

  app.get('/', home);
  app.get('/hello', hello);

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5, // failed attempts per client IP per window
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many login attempts, try again later' },
  });
  app.post('/api/login', loginLimiter, login({ db, log }));

  // Everything below needs a valid session.
  app.use('/api', authenticate({ db }));
  app.post('/api/logout', logout({ db }));
  app.use('/api/invoices', invoiceRoutes({ db, log }));
  app.post('/api/orders', createOrder({ db }));
  app.patch('/api/profile', updateProfile({ db, log }));
  app.post('/api/preview', preview({ safeFetch, log }));
  app.get('/api/lookup', dnsLookup);
  app.get('/api/accounts', listAccounts({ db }));
  app.post('/api/transfers', transfer({ db, log }));
  app.get('/api/admin/users', requireRole('admin', { log }), (req, res) => {
    res.json(db.prepare('SELECT id, name, role FROM users ORDER BY id').all());
  });

  app.use(notFound);
  app.use(errorHandler({ log }));
  return app;
}
