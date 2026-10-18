# Safari and Chrome / Touch ID walkthrough

Status: **not yet performed on physical hardware**. Automated software-authenticator tests validate the backend; the browser and authenticator behavior below needs a person at the target Mac.

Record macOS version, Chrome version, URL, date and results when running this checklist.

## Safari passkey flow

1. Open the trusted URL `https://localhost:3000` in Safari on a Mac with Touch ID configured. Confirm the page offers passkey registration/login and explains that SPC approval is unavailable.
2. Register a fresh customer ID. Complete the passkey prompt and verify registration succeeds without establishing a login session.
3. Log in with that passkey, create a transaction, and reload. Confirm the customer and pending transaction are shown.
4. Confirm **Approve with SPC** stays disabled and no Apple Pay or ordinary login prompt is offered as a payment substitute.
5. Log out, then log in again. Cancel a login prompt and confirm the error can be retried.
6. Record Safari and macOS versions and results. This flow does not validate SPC; run the Chrome checklist separately using a fresh demo customer.

## Chrome full SPC flow

1. Run `npm ci`, install `mkcert`, run `npm run setup:https`, then `npm start`. Open the trusted URL `https://localhost:3000` in desktop Chrome with Touch ID configured. Confirm the page reports SPC available.
2. Enter a fresh customer ID, select **Register passkey**, and complete the prompt with the local platform authenticator. Confirm registration succeeds but no logged-in session is established.
3. Select **Log in with passkey**. Authenticate and confirm the signed-in customer ID.
4. Create a transaction. Confirm **SPC Demo Shop**, **EUR 12.50**, a transaction ID, and pending status.
5. Select **Approve with SPC**. Confirm a browser-owned payment sheet appears showing the expected payee, amount and instrument, then authenticate with Touch ID.
6. Confirm the browser sheet closes, the application reports server-verified approval, and the transaction becomes approved. Reload and confirm it stays approved while the process lives. The approve button must remain disabled.
7. Log out and log in with the existing credential. Confirm another transaction can be created and approved.

## Failure and recovery

- Cancel registration, login and payment prompts separately. Confirm errors appear. Payment cancellation must leave the transaction pending; retry with a fresh challenge and complete it successfully.
- Wait more than five minutes after preparing a transaction. The first approval click should refresh the challenge and request another click, rather than opening a sheet with expired options.
- In a separate browser profile, register and log in as a different customer. Confirm each sees only their own transactions.
- Use a browser/device with passkeys but without SPC. Confirm the unsupported notice, enabled registration/login, and disabled SPC approval. There must be no passkey-only payment fallback.
- Attempt to register the same customer ID again; expect an error directing you to login.
- Restart Node. Confirm the prior session no longer authenticates and the customer must register again. The device's previous passkey may still exist but cannot log in to the reset server.
- Temporarily interrupt the network while finishing approval. Restore it and use **Refresh transaction** or reload. The server's final status is authoritative; an already-approved transaction must not be approved again.

## Evidence to record

For each ceremony, record pass/fail, the visible result and any browser exception name. Record whether the browser payment sheet showed the exact payee, amount and instrument. A successful ordinary passkey login alone is not evidence of SPC approval.

If SPC is reported unavailable, check the configured origin, Chrome version and platform authenticator availability first. Do not mark the hardware walkthrough as passed using mocked credentials or browser security-bypass flags.
