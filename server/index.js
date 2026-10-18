import { createApp } from './app.js';
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';

const port = Number(process.env.PORT ?? 3000);
const origin = process.env.ORIGIN ?? `https://localhost:${port}`;
const app = createApp({ origin });
let server;
try {
  server = createServer({
    key: readFileSync(process.env.TLS_KEY_FILE ?? '.certs/localhost-key.pem'),
    cert: readFileSync(process.env.TLS_CERT_FILE ?? '.certs/localhost.pem'),
  }, app);
} catch (error) {
  console.error(`Cannot load HTTPS certificate: ${error.message}`);
  console.error('Run npm run setup:https, then npm start. Custom certificates: TLS_KEY_FILE and TLS_CERT_FILE.');
  process.exit(1);
}
if (!origin.startsWith('https://')) {
  console.error('ORIGIN must use HTTPS for SPC. Set ORIGIN to the HTTPS URL opened in your browser.');
  process.exit(1);
}
server.listen(port, '127.0.0.1', () => {
  console.log(`SPC Playground: ${origin}`);
  console.log('In-memory demo: restarting clears customers, credentials, sessions and transactions.');
});
