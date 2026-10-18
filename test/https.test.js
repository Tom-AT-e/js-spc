import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import https from 'node:https';

test('default startup serves trusted TLS with HTTPS payment URLs and Secure cookies', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'spc-https-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const probe = createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const env = { ...process.env, PORT: String(port), TLS_KEY_FILE: key, TLS_CERT_FILE: cert };
  delete env.ORIGIN;
  const child = spawn(process.execPath, ['server/index.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { child.kill(); });
  const output = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Server startup timed out')), 5000);
    child.stdout.once('data', data => { clearTimeout(timeout); resolve(data.toString()); });
    child.once('exit', code => { clearTimeout(timeout); reject(new Error(`Server exited ${code}`)); });
  });
  assert.match(output, new RegExp(`https://localhost:${port}`), 'SPC requires an HTTPS origin by default');
  const ca = await readFile(cert);
  const request = (path, body) => new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', servername: 'localhost', port, path, ca,
      method: body ? 'POST' : 'GET', headers: { Origin: `https://localhost:${port}`, 'Content-Type': 'application/json' } }, res => {
      let text = '';
      res.on('data', data => { text += data; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end(body && JSON.stringify(body));
  });
  const config = await request('/api/config');
  assert.equal(config.body.origin, `https://localhost:${port}`);
  assert.match(config.body.instrument.icon, /^https:/);
  const registration = await request('/api/register/options', { customerID: 'tls-customer' });
  assert.equal(registration.status, 200);
  assert.match(registration.headers['set-cookie'][0], /^__Host-spc-session=.*Secure/);
});
