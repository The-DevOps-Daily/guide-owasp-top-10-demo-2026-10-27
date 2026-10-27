import { openDb } from './db.js';
import { createApp } from './app.js';
import { createLogger } from './logger.js';

const log = createLogger();
const db = await openDb({ demoPassword: process.env.DEMO_PASSWORD });
const port = Number(process.env.PORT ?? 3000);
// Loopback by default: this is a teaching app. A container sets HOST=0.0.0.0.
const host = process.env.HOST ?? '127.0.0.1';

createApp({ db, log }).listen(port, host, () => {
  log.info({ event: 'sys_startup', host, port }, 'listening');
});
