import { openDb } from '../src/db.js';
import { createLogger } from '../src/logger.js';
import { createVulnerableApp } from './app.js';

const log = createLogger();
const db = await openDb({ demoPassword: process.env.DEMO_PASSWORD });
const port = Number(process.env.PORT ?? 3001);

createVulnerableApp({ db, log }).listen(port, '127.0.0.1', () => {
  log.info({ event: 'sys_startup', port, variant: 'vulnerable' }, 'listening');
});
