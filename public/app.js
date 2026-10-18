const $ = id => document.getElementById(id);
let config;
let supported = false;
let passkeysSupported = false;
let signedIn = false;
let busy = false;
let transaction = null;
let prepared = null;

function fromBase64url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')), c => c.charCodeAt(0));
}
function toBase64url(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function serialize(credential) {
  if (!credential) throw new Error('No credential was returned.');
  const response = { clientDataJSON: toBase64url(credential.response.clientDataJSON) };
  for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    const value = credential.response[key];
    if (value != null) response[key] = toBase64url(value);
  }
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return { id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(), response };
}
async function api(path, body) {
  const response = await fetch(`/api${path}`, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401) { signedIn = false; prepared = null; render(); }
    throw new Error(result.error ?? `Request failed (${response.status}).`);
  }
  return result;
}
function message(text, kind = 'info') {
  $('message').textContent = text;
  $('message').dataset.kind = kind;
}
function errorText(error) {
  if (error.name === 'NotAllowedError' || error.name === 'AbortError') {
    return 'The ceremony was cancelled, timed out, or no matching credential was available. Your transaction was not approved. Try again.';
  }
  return error.message || 'The ceremony could not be completed.';
}
function render() {
  $('account-form').hidden = signedIn;
  $('session').hidden = !signedIn;
  $('register').disabled = busy || !passkeysSupported;
  $('login').disabled = busy || !passkeysSupported;
  $('logout').disabled = busy;
  $('create-transaction').disabled = busy || !signedIn;
  $('create-transaction').textContent = transaction?.status === 'pending' ? 'Refresh transaction' :
    transaction?.status === 'approved' ? 'Create another demo transaction' : 'Create demo transaction';
  $('transaction').hidden = !signedIn || !transaction;
  $('transaction-help').textContent = signedIn ? 'The server fixes the payee, amount and currency.' : 'Log in to create a demo transaction.';
  $('approve').disabled = busy || !supported || !prepared || transaction?.status !== 'pending';
  $('approve').textContent = transaction?.status === 'approved' ? 'Transaction approved' : 'Approve with SPC';
  if (transaction) {
    $('payee').textContent = transaction.payee;
    $('amount').textContent = new Intl.NumberFormat(undefined, { style: 'currency', currency: transaction.currency }).format(Number(transaction.amount));
    $('transaction-status').textContent = transaction.status;
    $('transaction-id').textContent = transaction.id;
  }
}
async function run(action) {
  if (busy) return;
  busy = true;
  render();
  try { await action(); } catch (error) { message(errorText(error), 'error'); }
  finally { busy = false; render(); }
}
function getCustomerID() {
  if (!$('account-form').reportValidity()) throw new Error('Enter a valid customer ID.');
  return $('customer-id').value;
}
async function preparePayment() {
  prepared = null;
  if (supported && transaction?.status === 'pending') {
    prepared = await api(`/transactions/${transaction.id}/options`, {});
  }
}
async function refreshTransactions() {
  const transactions = await api('/transactions');
  transaction = transactions.find(tx => tx.status === 'pending') ?? transactions.at(-1) ?? null;
  await preparePayment();
}
async function checkSupport() {
  if (!window.isSecureContext) throw new Error('Open this application on localhost or HTTPS.');
  if (!config.origin.startsWith('https://')) return false;
  if (!window.PublicKeyCredential || !window.PaymentRequest) return false;
  if (!await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) return false;
  if (typeof PaymentRequest.securePaymentConfirmationAvailability === 'function') {
    return await PaymentRequest.securePaymentConfirmationAvailability() === 'available';
  }
  // A dummy request checks SPC support without opening a payment sheet.
  const request = new PaymentRequest([{ supportedMethods: 'secure-payment-confirmation', data: {
    rpId: config.rpID, credentialIds: [new Uint8Array(32)], challenge: new Uint8Array(32),
    payeeOrigin: config.origin, instrument: config.instrument,
  } }], { total: { label: 'Capability check', amount: { currency: 'EUR', value: '0.00' } } });
  return await request.canMakePayment() === true;
}
$('register').addEventListener('click', () => run(async () => {
  const customerID = getCustomerID();
  const { ceremonyID, options } = await api('/register/options', { customerID, payment: supported });
  options.challenge = fromBase64url(options.challenge);
  options.user.id = fromBase64url(options.user.id);
  options.excludeCredentials = options.excludeCredentials.map(c => ({ ...c, id: fromBase64url(c.id) }));
  message(supported ? 'Follow your device’s prompt to register a payment-enabled passkey.' :
    'Follow your device’s prompt to register a login passkey. SPC is unavailable in this browser.');
  const credential = await navigator.credentials.create({ publicKey: options });
  const result = await api('/register/verify', { ceremonyID, credential: serialize(credential) });
  message(result.message);
}));
$('account-form').addEventListener('submit', event => {
  event.preventDefault();
  run(async () => {
    const { ceremonyID, options } = await api('/login/options', { customerID: getCustomerID() });
    options.challenge = fromBase64url(options.challenge);
    options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: fromBase64url(c.id) }));
    message('Use your passkey to log in.');
    const credential = await navigator.credentials.get({ publicKey: options });
    const result = await api('/login/verify', { ceremonyID, credential: serialize(credential) });
    signedIn = true;
    $('signed-in-as').textContent = result.customerID;
    message(result.message);
    await refreshTransactions();
  });
});
$('logout').addEventListener('click', () => run(async () => {
  await api('/logout', {});
  signedIn = false; transaction = null; prepared = null;
  message('Logged out.');
}));
$('create-transaction').addEventListener('click', () => run(async () => {
  transaction = await api('/transactions', {});
  await preparePayment();
  message(supported ? 'Transaction ready. Approve it with SPC.' : 'Transaction created. SPC is unavailable on this device; approval is blocked.');
}));
$('approve').addEventListener('click', () => run(async () => {
  if (!supported || !prepared) throw new Error('SPC is unavailable or the transaction is not ready.');
  if (prepared.expiresAt <= Date.now()) {
    await preparePayment();
    message('The challenge expired and has been refreshed. Click Approve with SPC again.');
    return;
  }
  const options = prepared;
  prepared = null;
  let paymentResponse;
  try {
    const request = new PaymentRequest([{ supportedMethods: 'secure-payment-confirmation', data: {
      ...options.data, challenge: fromBase64url(options.data.challenge),
      credentialIds: options.data.credentialIds.map(fromBase64url),
    } }], options.details);
    // No network await before show(): preserve the click's user activation.
    paymentResponse = await request.show();
    const result = await api(`/transactions/${transaction.id}/verify`, {
      ceremonyID: options.ceremonyID, credential: serialize(paymentResponse.details),
    });
    transaction = result.transaction;
    message(result.message);
    // Approval is final on the server even if the browser sheet cannot close.
    await paymentResponse.complete('success').catch(() => {});
  } catch (error) {
    if (paymentResponse) await paymentResponse.complete('fail').catch(() => {});
    // A lost HTTP response might hide a successful approval; reconcile first.
    try { await refreshTransactions(); } catch { prepared = null; }
    if (transaction?.status === 'approved') {
      message('The server confirms that this transaction is approved.');
    } else {
      throw error;
    }
  }
}));

async function init() {
  try {
    config = await api('/config');
    passkeysSupported = !!(window.isSecureContext && window.PublicKeyCredential &&
      navigator.credentials?.create && navigator.credentials?.get);
    try { supported = await checkSupport(); } catch { supported = false; }
    $('support').textContent = supported
      ? 'SPC is available on this device. Enrollment and approval still require your authenticator.'
      : !config.origin.startsWith('https://')
        ? 'SPC requires HTTPS, including on localhost. Run npm run setup:https, restart the server, and open https://localhost:3000.'
        : passkeysSupported
        ? 'Passkey registration and login are available. SPC approval is unavailable in this browser. Use supported desktop Chrome for SPC; Safari does not currently support it.'
        : 'Passkeys are unavailable. Open this application on localhost or HTTPS in a browser that supports WebAuthn.';
    const session = await api('/session');
    if (session.customerID) {
      signedIn = true;
      $('signed-in-as').textContent = session.customerID;
      await refreshTransactions();
    }
  } catch (error) { message(errorText(error), 'error'); }
  render();
}
init();
