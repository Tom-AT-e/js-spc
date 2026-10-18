import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';

export { verifyRegistrationResponse };

export function readClientData(response) {
  const encoded = response?.response?.clientDataJSON;
  if (typeof encoded !== 'string' || encoded.length > 24000) {
    throw new Error('Missing or oversized client data.');
  }
  const data = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  if (!data || data.crossOrigin === true || data.topOrigin !== undefined) {
    throw new Error('Only same-origin, top-level ceremonies are supported.');
  }
  return data;
}

// Older Chromium uses payment.rp; newer SPC drafts use payment.rpId.
// Both denote the configured RP ID. Conflicting aliases are always rejected.
export function validatePayment(data, transaction, { origin, rpID, instrument }) {
  const payment = data.payment;
  if (data.type !== 'payment.get' || data.origin !== origin || !payment ||
      (payment.rpId ?? payment.rp) !== rpID ||
      (payment.rp !== undefined && payment.rp !== rpID) ||
      (payment.rpId !== undefined && payment.rpId !== rpID) ||
      payment.topOrigin !== origin || payment.payeeOrigin !== origin ||
      payment.payeeName !== transaction.payee ||
      payment.total?.currency !== transaction.currency ||
      payment.total?.value !== transaction.amount ||
      payment.instrument?.displayName !== instrument.displayName ||
      payment.instrument?.icon !== instrument.icon ||
      (payment.instrument?.details !== undefined && payment.instrument.details !== instrument.details) ||
      (payment.paymentEntitiesLogos !== undefined &&
        (!Array.isArray(payment.paymentEntitiesLogos) || payment.paymentEntitiesLogos.length !== 0))) {
    throw new Error('Signed payment details do not match the server transaction.');
  }
}

export async function verifyAssertion({ response, credential, challenge, customer, payment, config }) {
  if (response?.id !== credential.id || response.rawId !== credential.id) {
    throw new Error('Credential does not belong to this customer.');
  }
  if (response.response?.userHandle != null && response.response.userHandle !== customer.userID) {
    throw new Error('Credential user handle does not match this customer.');
  }
  const data = readClientData(response);
  if (payment) validatePayment(data, payment, config);
  const result = await verifyAuthenticationResponse({
    response,
    credential,
    expectedChallenge: challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    expectedType: payment ? 'payment.get' : 'webauthn.get',
    requireUserVerification: true,
  });
  if (!result.verified) throw new Error('The credential signature is invalid.');
  return result.authenticationInfo.newCounter;
}
