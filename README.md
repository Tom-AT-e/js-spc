# SPC Playground

A minimal plain JavaScript SPA and Node/Express relying party for passkey registration, passkey login, and transaction approval with Secure Payment Confirmation (SPC). The server holds all state in memory. No database, payment processor, or money movement.

## Run locally

Requires Node.js 22 or later and npm. Safari supports the passkey registration/login and transaction-viewing flows. Desktop Chrome on a supported Mac with Touch ID is the target for the full SPC flow; actual SPC availability is checked at runtime.

```sh
npm ci
# macOS, once:
brew install mkcert
npm run setup:https
npm start
```

The setup command installs a local development CA in your trust store (it may request your administrator password) and generates ignored certificates under `.certs/`. Restart the browser if it was already open. Open **https://localhost:3000** with no certificate warning. Use this exact hostname rather than `127.0.0.1`; the configured origin and RP ID must match the browser. For automatic server restart during development, use `npm run dev`.

1. Enter a new demo customer ID and select **Register passkey**. Complete the platform authenticator prompt. The credential is requested with the SPC payment extension, discoverable credential storage and required user verification.
2. Select **Log in with passkey** and authenticate using the same credential. Registration does not log you in.
3. Select **Create demo transaction**. The server fixes the payee to **SPC Demo Shop** and the amount to **EUR 12.50**.
4. Select **Approve with SPC**. Check the amount and payee in Chrome's confirmation sheet, then authenticate. Approval succeeds only after server verification.

When SPC is unavailable, registration creates an ordinary login passkey without the payment extension. Login and transaction creation/viewing remain available; payment approval is blocked, with no ordinary-passkey fallback for payment. Feature detection is a capability check, not proof that a particular enrolled credential is usable for SPC.

### Browser support

| Browser | Register / log in | Create / view transactions | Approve with SPC |
| --- | --- | --- | --- |
| Safari with WebAuthn | Yes, ordinary passkey | Yes | Unavailable in current Safari |
| Desktop Chrome with a supported authenticator | Yes, SPC enrollment requested when available | Yes | Available when runtime checks and enrollment succeed |

Safari's Payment Request API does not implement the `secure-payment-confirmation` method, according to [MDN's compatibility data](https://github.com/mdn/browser-compat-data/blob/main/api/PaymentRequest.json). Apple Pay support is a separate payment method. This application cannot add browser-owned SPC UI to Safari through JavaScript.

A credential created without SPC enrollment in Safari is not guaranteed to work for SPC in Chrome. To demonstrate the full flow, register a fresh demo customer in a supported Chrome environment. The one-credential-per-customer scope does not include upgrading an existing enrollment. Physical Safari and Chrome/Touch ID walkthroughs remain outstanding.

**Demo identity:** choosing an unused customer ID creates a new demo identity. It does not establish ownership of a real customer account. One credential per customer, no recovery or credential management. After a server restart, accounts must be registered again; old credentials can remain in the device's passkey manager until manually removed.

## State and security behavior

- Customers, credential public keys and counters, sessions, challenges and transactions live in process memory and are cleared on restart.
- Sessions expire after one hour. Cookies are `HttpOnly`, `SameSite=Strict`, scoped to `/`, and additionally `Secure` with a `__Host-` name on HTTPS. Login rotates the session; logout invalidates it and its outstanding challenges.
- The default listener binds to loopback. POST endpoints require the exact configured Origin and JSON content type. Framing and cross-site requests are blocked.
- Each challenge is cryptographically random, bound to a browser session and ceremony, and expires after five minutes. Payment challenges are also bound to the customer and transaction. Verification attempts consume the challenge; retries require fresh options. Issuing new options supersedes that session's previous challenge of the same kind.
- The server validates credential ownership, challenge, origin, RP ID hash, user presence and verification, signature and authenticator counter. Login strictly expects `webauthn.get`; SPC strictly expects `payment.get`.
- SPC additionally checks the signed payee name/origin, top-level origin, RP ID, exact amount/currency and instrument name/icon. Both legacy Chromium `payment.rp` and newer `payment.rpId` are accepted for the same configured RP ID; conflicting values fail.
- A customer may have one pending transaction. Approval is final and cannot be replayed. Cancellation or failed verification leaves it pending. A client network error triggers reconciliation with the server before reporting the outcome.
- Verification is serialized per customer to prevent concurrent counter/state updates. Memory records are bounded to 1,000 customers, sessions, outstanding challenges and transactions each; restart this local demo if a limit is reached.

The PoC verifies the passkey assertion; it does not implement the optional browser-bound-key signature/device-binding additions in newer SPC drafts, attestation-based device trust, or production identity enrollment.

## Configuration

```sh
PORT=3001 npm start
```

The server serves HTTPS directly on loopback; its default origin is `https://localhost:<PORT>`. Set `TLS_KEY_FILE` and `TLS_CERT_FILE` for custom PEM files, and `ORIGIN` for a different HTTPS hostname. Certificates must be trusted by the browser and match that hostname. Use one stable HTTPS origin for the SPA and API, without a trailing slash. SPC requires an HTTPS payee origin even though ordinary WebAuthn may work over HTTP localhost. Do not bypass browser certificate validation.

After moving from HTTP to HTTPS, register a fresh demo customer and log in again. Restarting resets server state and HTTP sessions do not transfer to the HTTPS origin.

## REST API

All request/response bodies use JSON. Verification requests contain `{ ceremonyID, credential }`, where binary credential fields are base64url encoded. Errors use `{ error }`; success messages use `{ message }`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/config` | RP origin, ID and payment instrument |
| GET | `/api/session` | Current customer or `null` |
| POST | `/api/register/options` | `{ customerID, payment }` → registration options; `payment` defaults to `true`, Safari sends `false` |
| POST | `/api/register/verify` | Verify registration and store credential |
| POST | `/api/login/options` | `{ customerID }` → ordinary WebAuthn login options |
| POST | `/api/login/verify` | Verify login and rotate session |
| POST | `/api/logout` | Invalidate session |
| GET | `/api/transactions` | List this customer's transactions |
| POST | `/api/transactions` | Create or return the pending demo transaction |
| POST | `/api/transactions/:id/options` | Prepare the SPC request and transaction-bound challenge |
| POST | `/api/transactions/:id/verify` | Verify the SPC assertion and approve |

Options and transaction creation requests without other arguments send `{}`. Amount, currency and payee fields submitted by the client cannot change the server's transaction.

## Verification

```sh
npm test
npm run check
```

The backend tests exercise the real HTTP application and SimpleWebAuthn verification using a software authenticator with real ES256 signatures, COSE keys and CBOR registration data. They do not simulate a Chrome payment sheet or prove Touch ID enrollment works. See [the manual walkthrough](docs/manual-verification.md) for the outstanding hardware checks.

## Protocol references

- [Chrome: register SPC](https://developer.chrome.com/docs/payments/register-secure-payment-confirmation)
- [Chrome: authenticate with SPC](https://developer.chrome.com/docs/payments/authenticate-secure-payment-confirmation)
- [W3C SPC relying-party verification](https://www.w3.org/TR/secure-payment-confirmation/#sctn-verifying-assertion)
- [SimpleWebAuthn server library](https://simplewebauthn.dev/docs/packages/server)
