import { mkdirSync, chmodSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';

const check = spawnSync('mkcert', ['-version'], { stdio: 'ignore' });
if (check.error || check.status !== 0) {
  console.error('Install mkcert first: brew install mkcert (macOS).');
  console.error('Other platforms: https://github.com/FiloSottile/mkcert#installation');
  process.exit(1);
}
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error || result.status !== 0) process.exit(result.status || 1);
}
mkdirSync('.certs', { recursive: true, mode: 0o700 });
run('mkcert', ['-key-file', '.certs/localhost-key.pem', '-cert-file', '.certs/localhost.pem', 'localhost', '127.0.0.1', '::1']);
chmodSync('.certs/localhost-key.pem', 0o600);
// macOS uses per-user trust rather than changing the system keychain with sudo.
// macOS may still show its own authorization dialog.
if (process.platform === 'darwin') {
  const root = spawnSync('mkcert', ['-CAROOT'], { encoding: 'utf8' });
  if (root.error || root.status !== 0) process.exit(root.status || 1);
  run('security', ['add-trusted-cert', '-r', 'trustRoot', '-k',
    join(homedir(), 'Library/Keychains/login.keychain-db'), join(root.stdout.trim(), 'rootCA.pem')]);
} else {
  run('mkcert', ['-install']);
}
console.log('HTTPS ready. Run npm start and open https://localhost:3000.');
