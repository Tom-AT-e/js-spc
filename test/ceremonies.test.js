import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createApp } from '../server/app.js';

const origin = 'http://localhost:3000';
const hash = value => createHash('sha256').update(value).digest();
const b64 = value => Buffer.from(value).toString('base64url');
const encode = value => Buffer.from(isoCBOR.encode(value));

// Software authenticator: real ES256 keys, CBOR attestation and signed assertions.
// It tests the RP's crypto verification, not Chrome's UI or SPC enrollment support.
function authenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = encode(new Map([[1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  const id = randomBytes(32);
  let counter = 0;
  let userHandle;
  function authData(flags, count) {
    const countBytes = Buffer.alloc(4);
    countBytes.writeUInt32BE(count);
    return Buffer.concat([hash('localhost'), Buffer.from([flags]), countBytes]);
  }
  const envelope = response => ({ id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {}, response });
  return {
    register(options, overrides = {}) {
      userHandle = options.user.id;
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', origin, crossOrigin: false, challenge: options.challenge, ...overrides }));
      const length = Buffer.alloc(2);
      length.writeUInt16BE(id.length);
      const data = Buffer.concat([authData(0x45, 0), Buffer.alloc(16), length, id, cose]);
      const attestation = encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]]));
      return envelope({ clientDataJSON: b64(clientDataJSON), attestationObject: b64(attestation), transports: ['internal'] });
    },
    assert(challenge, { payment, changes = {}, flags = 0x05, count, key = privateKey } = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: payment ? 'payment.get' : 'webauthn.get', challenge, origin, crossOrigin: false,
        ...(payment ? { payment } : {}), ...changes,
      }));
      const data = authData(flags, count ?? ++counter);
      const signature = sign('sha256', Buffer.concat([data, hash(clientDataJSON)]), key);
      return envelope({ clientDataJSON: b64(clientDataJSON), authenticatorData: b64(data), signature: b64(signature), userHandle });
    },
  };
}

async function fixture(t) {
  let time = Date.now();
  const server = createServer(createApp({ now: () => time }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  function client() {
    let cookie = '';
    return async (path, body, extraHeaders = {}) => {
      const response = await fetch(base + path, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { origin, 'content-type': 'application/json', cookie, ...extraHeaders },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.headers.get('set-cookie')) cookie = response.headers.get('set-cookie').split(';')[0];
      return { status: response.status, body: await response.json(), headers: response.headers };
    };
  }
  async function enroll(id, api = client(), payment = true) {
    const auth = authenticator();
    const registration = await api('/register/options', { customerID: id, payment });
    assert.equal(registration.status, 200);
    assert.deepEqual(registration.body.options.extensions?.payment, payment ? { isPayment: true } : undefined);
    assert.equal(registration.body.options.authenticatorSelection.userVerification, 'required');
    assert.equal(registration.body.options.authenticatorSelection.residentKey, 'required');
    const registered = await api('/register/verify', {
      ceremonyID: registration.body.ceremonyID, credential: auth.register(registration.body.options),
    });
    assert.equal(registered.status, 200, JSON.stringify(registered.body));
    assert.equal((await api('/session')).body.customerID, null);
    const login = await api('/login/options', { customerID: id });
    const result = await api('/login/verify', { ceremonyID: login.body.ceremonyID, credential: auth.assert(login.body.options.challenge) });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.match(result.headers.get('set-cookie'), /HttpOnly/i);
    assert.match(result.headers.get('set-cookie'), /SameSite=Strict/i);
    return { api, auth, id };
  }
  async function pending(user) {
    const created = await user.api('/transactions', { amount: '0.01', payee: 'Attacker' });
    assert.equal(created.status, 201);
    assert.equal(created.body.amount, '12.50');
    assert.equal(created.body.payee, 'SPC Demo Shop');
    const tx = created.body;
    const { body: options } = await user.api(`/transactions/${tx.id}/options`, {});
    const payment = { rpId: 'localhost', topOrigin: origin, payeeOrigin: origin,
      payeeName: tx.payee, total: { currency: tx.currency, value: tx.amount },
      instrument: { displayName: options.data.instrument.displayName, icon: options.data.instrument.icon } };
    return { tx, options, payment, verify: credential => user.api(`/transactions/${tx.id}/verify`, { ceremonyID: options.ceremonyID, credential }) };
  }
  return { client, enroll, pending, advance: ms => { time += ms; } };
}

test('real registration, login and SPC approval; transaction is final and assertion cannot replay', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  const { tx, options, payment, verify } = await f.pending(user);
  const credential = user.auth.assert(options.data.challenge, { payment });
  const result = await verify(credential);
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.transaction.status, 'approved');
  assert.equal((await verify(credential)).status, 400);
  assert.equal((await user.api(`/transactions/${tx.id}/options`, {})).status, 409);
});

test('ordinary passkey enrollment supports Safari registration, login and transaction access', async t => {
  const f = await fixture(t);
  const user = await f.enroll('safari-customer', f.client(), false);
  assert.equal((await user.api('/session')).body.customerID, 'safari-customer');
  const { tx } = await f.pending(user);
  assert.equal(tx.status, 'pending');
  // Even ordinary credentials must produce a valid payment.get assertion to approve.
  const { body: options } = await user.api(`/transactions/${tx.id}/options`, {});
  const result = await user.api(`/transactions/${tx.id}/verify`, {
    ceremonyID: options.ceremonyID, credential: user.auth.assert(options.data.challenge),
  });
  assert.equal(result.status, 400);
  assert.equal((await user.api('/transactions')).body[0].status, 'pending');
});

for (const [name, change] of [
  ['amount', p => { p.total.value = '0.01'; }],
  ['currency', p => { p.total.currency = 'USD'; }],
  ['payee', p => { p.payeeName = 'Attacker'; }],
  ['payee origin', p => { p.payeeOrigin = 'https://attacker.example'; }],
  ['top origin', p => { p.topOrigin = 'https://attacker.example'; }],
  ['RP ID', p => { p.rpId = 'attacker.example'; }],
  ['conflicting legacy RP', p => { p.rp = 'attacker.example'; }],
  ['instrument name', p => { p.instrument.displayName = 'Another account'; }],
  ['instrument icon', p => { p.instrument.icon = 'https://attacker.example/icon.png'; }],
  ['extra payment logo', p => { p.paymentEntitiesLogos = [{ url: 'https://attacker.example/logo', label: 'Fake' }]; }],
]) {
  test(`rejects a valid signature over incorrect ${name}; failed attempt is consumed`, async t => {
    const f = await fixture(t);
    const user = await f.enroll('alice');
    const { options, payment, verify } = await f.pending(user);
    change(payment);
    const result = await verify(user.auth.assert(options.data.challenge, { payment }));
    assert.equal(result.status, 400);
    assert.match(result.body.error, /payment details/);
    assert.equal((await verify(user.auth.assert(options.data.challenge, { payment }))).status, 400);
    assert.equal((await user.api('/transactions')).body[0].status, 'pending');
  });
}

for (const [name, modify] of [
  ['wrong challenge', (options, payment) => ({ challenge: 'wrong', payment })],
  ['login assertion used as payment', () => ({})],
  ['wrong caller origin', (_o, payment) => ({ payment, changes: { origin: 'https://attacker.example' } })],
  ['cross-origin assertion', (_o, payment) => ({ payment, changes: { crossOrigin: true } })],
  ['missing user verification', (_o, payment) => ({ payment, flags: 0x01 })],
  ['missing user presence', (_o, payment) => ({ payment, flags: 0x04 })],
  ['counter rollback', (_o, payment) => ({ payment, count: 1 })],
  ['invalid signature', (_o, payment) => ({ payment, key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey })],
]) {
  test(`rejects ${name}`, async t => {
    const f = await fixture(t);
    const user = await f.enroll('alice');
    const { options, payment, verify } = await f.pending(user);
    const args = modify(options, payment);
    const result = await verify(user.auth.assert(args.challenge ?? options.data.challenge, args));
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal((await user.api('/transactions')).body[0].status, 'pending');
  });
}

test('expired payment challenges fail; a fresh challenge permits retry', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  const first = await f.pending(user);
  f.advance(5 * 60 * 1000);
  assert.equal((await first.verify(user.auth.assert(first.options.data.challenge, { payment: first.payment }))).status, 400);
  const retry = await f.pending(user);
  assert.equal((await retry.verify(user.auth.assert(retry.options.data.challenge, { payment: retry.payment }))).status, 200);
});

test('customers cannot read or approve each other’s transactions or use another credential', async t => {
  const f = await fixture(t);
  const alice = await f.enroll('alice');
  const bob = await f.enroll('bob');
  const pending = await f.pending(alice);
  assert.deepEqual((await bob.api('/transactions')).body, []);
  assert.equal((await bob.api(`/transactions/${pending.tx.id}/options`, {})).status, 404);
  assert.equal((await bob.api(`/transactions/${pending.tx.id}/verify`, { ceremonyID: pending.options.ceremonyID })).status, 404);
  assert.equal((await pending.verify(bob.auth.assert(pending.options.data.challenge, { payment: pending.payment }))).status, 400);
});

test('payment assertions cannot establish a login session', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  await user.api('/logout', {});
  const { body: login } = await user.api('/login/options', { customerID: 'alice' });
  const result = await user.api('/login/verify', { ceremonyID: login.ceremonyID,
    credential: user.auth.assert(login.options.challenge, { payment: {} }) });
  assert.equal(result.status, 400);
  assert.equal((await user.api('/transactions')).status, 401);
});

test('ceremonies are bound to the issuing browser session', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  const other = f.client();
  const { body: login } = await user.api('/login/options', { customerID: 'alice' });
  const credential = user.auth.assert(login.options.challenge);
  assert.equal((await other('/login/verify', { ceremonyID: login.ceremonyID, credential })).status, 400);
  assert.equal((await user.api('/login/verify', { ceremonyID: login.ceremonyID, credential })).status, 200);
});

test('registration rejects a foreign origin and consumes the challenge', async t => {
  const f = await fixture(t);
  const api = f.client();
  const auth = authenticator();
  const { body } = await api('/register/options', { customerID: 'alice' });
  assert.equal((await api('/register/verify', { ceremonyID: body.ceremonyID,
    credential: auth.register(body.options, { origin: 'https://attacker.example' }) })).status, 400);
  assert.equal((await api('/register/verify', { ceremonyID: body.ceremonyID,
    credential: auth.register(body.options) })).status, 400);
});

test('duplicate customers rejected; logout invalidates sessions; cross-site requests denied', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  assert.equal((await user.api('/register/options', { customerID: 'alice' })).status, 409);
  assert.equal((await user.api('/transactions', {}, { origin: 'https://attacker.example' })).status, 403);
  assert.equal((await user.api('/transactions', {}, { origin: '' })).status, 403);
  assert.equal((await user.api('/transactions', {}, { 'content-type': 'text/plain' })).status, 403);
  await user.api('/logout', {});
  assert.equal((await user.api('/transactions')).status, 401);
});

test('legacy Chromium payment.rp is accepted only for the configured RP', async t => {
  const f = await fixture(t);
  const user = await f.enroll('alice');
  const { options, payment, verify } = await f.pending(user);
  payment.rp = payment.rpId;
  delete payment.rpId;
  assert.equal((await verify(user.auth.assert(options.data.challenge, { payment }))).status, 200);
});
