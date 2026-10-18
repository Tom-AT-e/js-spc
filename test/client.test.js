import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

// Execute the actual SPA logic with browser API doubles. This is deliberately
// separate from the hardware/browser walkthrough, which remains outstanding.
async function client({ available = true, cancel = false, staticAvailability, noPaymentRequest = false, paymentThrows = false, noWebAuthn = false, insecureOrigin = false } = {}) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', value: 'alice', disabled: false, hidden: false, dataset: {}, handlers: {},
      reportValidity: () => true,
      addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  }
  const requests = [];
  const completions = [];
  let shows = 0;
  let paymentCounter = 0;
  let tx = null;
  let loggedIn = false;
  const credential = {
    id: 'AQ', rawId: new Uint8Array([1]).buffer, type: 'public-key',
    response: { clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer },
    getClientExtensionResults: () => ({}),
  };
  const instrument = { displayName: 'SPC demo account', icon: 'https://localhost:3000/instrument.svg' };
  class PaymentRequest {
    constructor(methods, details) {
      if (paymentThrows) throw new Error('Payment method not supported');
      this.methods = methods; this.details = details;
    }
    async canMakePayment() { return available; }
    show() {
      shows++;
      requests.push('show');
      assert.equal(this.methods[0].supportedMethods, 'secure-payment-confirmation');
      assert.equal(this.details.total.amount.value, '12.50');
      if (cancel) return Promise.reject(Object.assign(new Error('cancel'), { name: 'NotAllowedError' }));
      return Promise.resolve({ details: credential, complete: async result => { completions.push(result); } });
    }
  }
  if (staticAvailability) PaymentRequest.securePaymentConfirmationAvailability = async () => staticAvailability;
  const publicKeyCredential = { isUserVerifyingPlatformAuthenticatorAvailable: async () => true };
  runInNewContext(source, {
    document: { getElementById: element },
    window: { isSecureContext: true, PaymentRequest: noPaymentRequest ? undefined : PaymentRequest,
      PublicKeyCredential: noWebAuthn ? undefined : publicKeyCredential },
    PaymentRequest, PublicKeyCredential: publicKeyCredential,
    Uint8Array, Intl, Date, atob, btoa, console,
    navigator: { credentials: {
      create: async ({ publicKey }) => {
        assert.equal(publicKey.extensions.payment?.isPayment, available && !noPaymentRequest && !paymentThrows && !staticAvailability ? true : undefined);
        assert.ok(publicKey.challenge instanceof Uint8Array);
        return credential;
      },
      get: async ({ publicKey }) => {
        assert.ok(publicKey.allowCredentials[0].id instanceof Uint8Array);
        return credential;
      },
    } },
    fetch: async (url, options) => {
      const path = url.replace('/api', '');
      requests.push(path);
      let body;
      if (path === '/config') body = { origin: insecureOrigin ? 'http://localhost:3000' : 'https://localhost:3000', rpID: 'localhost', instrument };
      else if (path === '/session') body = { customerID: loggedIn ? 'alice' : null };
      else if (path === '/register/options') body = { ceremonyID: 'reg', options: { challenge: 'AQ', user: { id: 'AQ' }, excludeCredentials: [],
        extensions: JSON.parse(options.body).payment ? { payment: { isPayment: true } } : {} } };
      else if (path === '/register/verify') body = { message: 'Registered. Log in.' };
      else if (path === '/login/options') body = { ceremonyID: 'login', options: { challenge: 'AQ', allowCredentials: [{ id: 'AQ' }] } };
      else if (path === '/login/verify') { loggedIn = true; body = { customerID: 'alice', message: 'Logged in.' }; }
      else if (path === '/transactions' && options.method === 'GET') body = tx ? [tx] : [];
      else if (path === '/transactions') { tx ??= { id: 'tx', payee: 'SPC Demo Shop', amount: '12.50', currency: 'EUR', status: 'pending' }; body = tx; }
      else if (path.endsWith('/options')) {
        paymentCounter++;
        body = { ceremonyID: `payment-${paymentCounter}`, expiresAt: Date.now() + 300000,
          data: { challenge: 'AQ', credentialIds: ['AQ'], rpId: 'localhost', instrument },
          details: { total: { label: 'SPC Demo Shop', amount: { currency: 'EUR', value: '12.50' } } } };
      } else if (path.endsWith('/verify')) {
        assert.equal(JSON.parse(options.body).credential.response.signature, 'Aw');
        tx = { ...tx, status: 'approved' };
        body = { transaction: tx, message: 'Server verified SPC approval.' };
      } else throw new Error(`Unexpected request: ${path}`);
      return { ok: true, status: 200, json: async () => body };
    },
  });
  await tick();
  async function click(id, event = 'click') {
    element(id).handlers[event]({ preventDefault() {} });
    await tick();
  }
  return { element, click, requests, completions, shows: () => shows, paymentCounter: () => paymentCounter };
}

test('SPA permits passkey registration but blocks approval when SPC is unavailable', async () => {
  const ui = await client({ available: false });
  assert.equal(ui.element('register').disabled, false);
  assert.equal(ui.element('approve').disabled, true);
  assert.match(ui.element('support').textContent, /unavailable/);
});

test('SPA respects unavailable result from the modern SPC availability API', async () => {
  const ui = await client({ available: true, staticAvailability: 'unavailable-feature-not-enabled' });
  assert.equal(ui.element('register').disabled, false);
  assert.equal(ui.element('approve').disabled, true);
});

for (const [name, settings] of [
  ['Safari rejecting the SPC payment method', { paymentThrows: true }],
  ['browser without PaymentRequest', { noPaymentRequest: true }],
]) {
  test(`registration, login and transaction viewing work in ${name}`, async () => {
    const ui = await client(settings);
    assert.equal(ui.element('register').disabled, false);
    await ui.click('register');
    assert.match(ui.element('message').textContent, /Registered/);
    await ui.click('account-form', 'submit');
    assert.equal(ui.element('signed-in-as').textContent, 'alice');
    await ui.click('create-transaction');
    assert.equal(ui.element('transaction-status').textContent, 'pending');
    assert.equal(ui.element('approve').disabled, true);
    assert.equal(ui.paymentCounter(), 0);
    assert.equal(ui.shows(), 0);
  });
}

test('SPA disables both account ceremonies when WebAuthn is unavailable', async () => {
  const ui = await client({ noWebAuthn: true });
  assert.equal(ui.element('register').disabled, true);
  assert.equal(ui.element('login').disabled, true);
});

test('SPA completes three ceremonies and opens the SPC sheet before the verification fetch', async () => {
  const ui = await client();
  await ui.click('register');
  assert.match(ui.element('message').textContent, /Registered/);
  await ui.click('account-form', 'submit');
  assert.equal(ui.element('signed-in-as').textContent, 'alice');
  await ui.click('create-transaction');
  assert.equal(ui.element('approve').disabled, false);
  const start = ui.requests.length;
  await ui.click('approve');
  assert.deepEqual(ui.requests.slice(start), ['show', '/transactions/tx/verify']);
  assert.deepEqual(ui.completions, ['success']);
  assert.equal(ui.element('transaction-status').textContent, 'approved');
  assert.equal(ui.element('approve').disabled, true);
  assert.match(ui.element('message').textContent, /Server verified/);
});

test('SPA leaves cancelled payment pending and prepares a fresh challenge for retry', async () => {
  const ui = await client({ cancel: true });
  await ui.click('account-form', 'submit');
  await ui.click('create-transaction');
  await ui.click('approve');
  assert.equal(ui.shows(), 1);
  assert.equal(ui.element('transaction-status').textContent, 'pending');
  assert.equal(ui.element('approve').disabled, false);
  assert.equal(ui.paymentCounter(), 2);
  assert.match(ui.element('message').textContent, /cancelled/);
  assert.equal(ui.requests.includes('/transactions/tx/verify'), false);
});

test('HTTP localhost never enables SPC and explains the HTTPS setup', async () => {
  const ui = await client({ insecureOrigin: true });
  assert.equal(ui.element('approve').disabled, true);
  assert.match(ui.element('support').textContent, /SPC requires HTTPS/);
  assert.match(ui.element('support').textContent, /setup:https/);
});
