import express from 'express';
import { randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { generateRegistrationOptions, generateAuthenticationOptions } from '@simplewebauthn/server';
import { readClientData, verifyAssertion, verifyRegistrationResponse } from './webauthn.js';

const FIVE_MINUTES = 5 * 60 * 1000;
const SESSION_TTL = 60 * 60 * 1000;
const token = () => randomBytes(32).toString('base64url');
const fail = (status, message) => Object.assign(new Error(message), { status });

export function createApp({ origin = 'http://localhost:3000', now = Date.now } = {}) {
  const url = new URL(origin);
  if (url.origin !== origin || (url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && url.hostname === 'localhost'))) {
    throw new Error('ORIGIN must be an HTTPS origin or http://localhost:<port>, without a trailing slash.');
  }
  const config = {
    origin, rpID: url.hostname,
    instrument: { displayName: 'SPC demo account', icon: `${origin}/instrument.svg`, iconMustBeShown: true },
  };
  const customers = new Map();
  const sessions = new Map();
  const challenges = new Map();
  const transactions = new Map();
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'payment=(self), publickey-credentials-create=(self), publickey-credentials-get=(self)',
    });
    next();
  });
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.headers['sec-fetch-site'] === 'cross-site' ||
        (req.headers.origin && req.headers.origin !== origin)) {
      return next(fail(403, 'Use this application from its configured origin.'));
    }
    if (req.method !== 'GET' &&
        (req.headers.origin !== origin || !req.is('application/json'))) {
      return next(fail(403, 'Same-origin JSON requests are required.'));
    }
    // Expired records are swept on API traffic; no background timers to retain state.
    for (const [id, value] of sessions) if (value.expiresAt <= now()) sessions.delete(id);
    for (const [id, value] of challenges) if (value.expiresAt <= now()) challenges.delete(id);
    next();
  });
  app.use(express.json({ limit: '48kb' }));

  const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: url.protocol === 'https:', path: '/', maxAge: SESSION_TTL };
  const cookieName = url.protocol === 'https:' ? '__Host-spc-session' : 'spc-session';
  function startSession(res, customerID) {
    if (sessions.size >= 1000) throw fail(503, 'Demo session limit reached. Restart the server.');
    const id = token();
    const session = { id, customerID, expiresAt: now() + SESSION_TTL };
    sessions.set(id, session);
    res.cookie(cookieName, id, cookieOptions);
    return session;
  }
  app.use('/api', (req, res, next) => {
    const cookies = Object.fromEntries((req.headers.cookie ?? '').split(';').map(part => {
      const at = part.indexOf('=');
      return [part.slice(0, at).trim(), part.slice(at + 1).trim()];
    }));
    req.session = sessions.get(cookies[cookieName]);
    req.ensureSession = () => req.session ??= startSession(res);
    next();
  });
  function customerID(value) {
    if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,40}$/.test(value)) {
      throw fail(400, 'Customer ID must contain 1–40 letters, digits, underscores or hyphens.');
    }
    return value;
  }
  function authenticated(req) {
    const customer = customers.get(req.session?.customerID);
    if (!customer) throw fail(401, 'Log in with your passkey first.');
    return customer;
  }
  function issue(req, kind, details) {
    const session = req.ensureSession();
    for (const [id, item] of challenges) {
      if (item.sessionID === session.id && item.kind === kind) challenges.delete(id);
    }
    if (challenges.size >= 1000) throw fail(503, 'Demo challenge limit reached.');
    const id = token();
    const record = { ...details, kind, sessionID: session.id, expiresAt: now() + FIVE_MINUTES };
    challenges.set(id, record);
    return id;
  }
  function consume(req, kind) {
    const item = challenges.get(req.body?.ceremonyID);
    if (!item || item.sessionID !== req.session?.id) {
      throw fail(400, 'Ceremony is missing, expired or already used. Start again.');
    }
    challenges.delete(req.body.ceremonyID);
    if (item.kind !== kind || item.expiresAt <= now()) throw fail(400, 'Wrong or expired ceremony. Start again.');
    return item;
  }
  function ownedTransaction(req) {
    const customer = authenticated(req);
    const tx = transactions.get(req.params.id);
    if (!tx || tx.customerID !== customer.id) throw fail(404, 'Transaction not found.');
    return { customer, tx };
  }
  function publicTransaction(tx) {
    const { id, payee, amount, currency, status, approvedAt } = tx;
    return { id, payee, amount, currency, status, approvedAt };
  }

  app.get('/api/config', (_req, res) => res.json({ origin, rpID: config.rpID, instrument: config.instrument }));
  app.get('/api/session', (req, res) => res.json({ customerID: req.session?.customerID ?? null }));
  app.post('/api/register/options', async (req, res) => {
    const id = customerID(req.body.customerID);
    const payment = req.body.payment ?? true;
    if (typeof payment !== 'boolean') throw fail(400, 'payment must be a boolean.');
    if (customers.has(id)) throw fail(409, 'Customer already registered. Log in instead.');
    if (customers.size >= 1000) throw fail(503, 'Demo customer limit reached. Restart the server.');
    const userID = token();
    const options = await generateRegistrationOptions({
      rpName: 'SPC Playground', rpID: config.rpID,
      userName: id, userDisplayName: id, userID: Buffer.from(userID, 'base64url'),
      attestationType: 'none', timeout: FIVE_MINUTES,
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
    });
    if (payment) options.extensions = { ...options.extensions, payment: { isPayment: true } };
    const ceremonyID = issue(req, 'register', { customerID: id, userID, challenge: options.challenge });
    res.json({ ceremonyID, options });
  });
  app.post('/api/register/verify', async (req, res) => {
    const ceremony = consume(req, 'register');
    const response = req.body.credential;
    readClientData(response);
    const result = await verifyRegistrationResponse({
      response, expectedChallenge: ceremony.challenge, expectedOrigin: origin,
      expectedRPID: config.rpID, requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    });
    if (!result.verified || !result.registrationInfo) throw fail(400, 'Registration verification failed.');
    if (customers.has(ceremony.customerID)) throw fail(409, 'Customer already registered. Log in instead.');
    const credential = result.registrationInfo.credential;
    if ([...customers.values()].some(c => c.credential.id === credential.id)) {
      throw fail(409, 'Credential already registered.');
    }
    customers.set(ceremony.customerID, { id: ceremony.customerID, userID: ceremony.userID, credential, busy: false });
    res.json({ message: 'Passkey registered. Log in to continue.' });
  });
  app.post('/api/login/options', async (req, res) => {
    const id = customerID(req.body.customerID);
    const customer = customers.get(id);
    if (!customer) throw fail(404, 'Customer not found. Register a passkey first.');
    const options = await generateAuthenticationOptions({
      rpID: config.rpID, timeout: FIVE_MINUTES, userVerification: 'required',
      allowCredentials: [{ id: customer.credential.id, transports: ['internal'] }],
    });
    const ceremonyID = issue(req, 'login', { customerID: id, challenge: options.challenge });
    res.json({ ceremonyID, options });
  });
  app.post('/api/login/verify', async (req, res) => {
    const ceremony = consume(req, 'login');
    const customer = customers.get(ceremony.customerID);
    if (customer.busy) throw fail(409, 'Another ceremony is being verified. Try again.');
    customer.busy = true;
    try {
      customer.credential.counter = await verifyAssertion({
        response: req.body.credential, credential: customer.credential,
        challenge: ceremony.challenge, customer, config,
      });
      const oldID = req.session.id;
      startSession(res, customer.id);
      sessions.delete(oldID);
      for (const [id, value] of challenges) if (value.sessionID === oldID) challenges.delete(id);
      res.json({ customerID: customer.id, message: 'Passkey login verified.' });
    } finally { customer.busy = false; }
  });
  app.post('/api/logout', (req, res) => {
    if (req.session) {
      sessions.delete(req.session.id);
      for (const [id, value] of challenges) if (value.sessionID === req.session.id) challenges.delete(id);
    }
    res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined });
    res.json({ message: 'Logged out.' });
  });
  app.get('/api/transactions', (req, res) => {
    const customer = authenticated(req);
    res.json([...transactions.values()].filter(tx => tx.customerID === customer.id).map(publicTransaction));
  });
  app.post('/api/transactions', (req, res) => {
    const customer = authenticated(req);
    let tx = [...transactions.values()].find(tx => tx.customerID === customer.id && tx.status === 'pending');
    if (!tx) {
      if (transactions.size >= 1000) throw fail(503, 'Demo transaction limit reached. Restart the server.');
      tx = { id: randomUUID(), customerID: customer.id, payee: 'SPC Demo Shop', amount: '12.50', currency: 'EUR', status: 'pending' };
      transactions.set(tx.id, tx);
    }
    res.status(201).json(publicTransaction(tx));
  });
  app.post('/api/transactions/:id/options', (req, res) => {
    const { customer, tx } = ownedTransaction(req);
    if (tx.status !== 'pending') throw fail(409, 'Transaction already approved.');
    const challenge = token();
    const ceremonyID = issue(req, 'payment', { customerID: customer.id, transactionID: tx.id, challenge });
    res.json({
      ceremonyID, expiresAt: now() + FIVE_MINUTES,
      data: { rpId: config.rpID, credentialIds: [customer.credential.id], challenge,
        payeeName: tx.payee, payeeOrigin: origin, instrument: config.instrument, timeout: FIVE_MINUTES },
      details: { total: { label: tx.payee, amount: { currency: tx.currency, value: tx.amount } } },
    });
  });
  app.post('/api/transactions/:id/verify', async (req, res) => {
    const { customer, tx } = ownedTransaction(req);
    const ceremony = consume(req, 'payment');
    if (ceremony.customerID !== customer.id || ceremony.transactionID !== tx.id) {
      throw fail(400, 'Ceremony belongs to a different transaction or customer.');
    }
    if (tx.status !== 'pending') throw fail(409, 'Transaction already approved.');
    if (customer.busy) throw fail(409, 'Another ceremony is being verified. Try again.');
    customer.busy = true;
    try {
      customer.credential.counter = await verifyAssertion({
        response: req.body.credential, credential: customer.credential,
        challenge: ceremony.challenge, customer, payment: tx, config,
      });
      tx.status = 'approved';
      tx.approvedAt = new Date(now()).toISOString();
      res.json({ message: 'Transaction approved. SPC signature and payment details verified.', transaction: publicTransaction(tx) });
    } finally { customer.busy = false; }
  });
  app.use('/api', (_req, _res, next) => next(fail(404, 'API endpoint not found.')));
  app.use(express.static(fileURLToPath(new URL('../public/', import.meta.url))));
  app.use((error, _req, res, _next) => {
    const status = error.status ?? 400;
    res.status(status >= 400 && status < 600 ? status : 500).json({
      error: status >= 500 ? 'Server could not complete the request.' : error.message,
    });
  });
  return app;
}
