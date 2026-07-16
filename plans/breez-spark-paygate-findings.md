# Breez SDK Spark Paygate Findings

**Date:** `2026-07-06`

## Executive Summary

Breez SDK Spark passed the critical Paygate payer-side preimage test. A funded
Breez SDK wallet paid a real BOLT11 invoice with `prefer_spark=false`, returned
a Lightning preimage, and the client verified `sha256(preimage) == payment_hash`.

This means Breez SDK Spark is viable for the `paygate-client` payer contract:

```text
pay_invoice(bolt11) -> payment_hash + preimage
```

## Proven In The Spike

- Breez SDK Spark wallet connected from `BREEZ_API_KEY`, `BREEZ_MNEMONIC`,
  `network=mainnet`, and `.breez-preimage-doctor` storage.
- Wallet was funded with `1000 sats`.
- A separate Lightning wallet generated a real BOLT11 invoice.
- Breez paid that invoice for `5 sats`.
- Breez reported a final fee of `3 sats`.
- Payment was sent with `prefer_spark=false`.
- Returned payment hash:
  `5ae6443a5ad978c27ef72bb1df8c9b3166be520a6aeebfcdf6a0a055ba44f2da`
- Returned preimage verified successfully.

The preimage is proof material and should be handled like a bearer secret. Do
not log it in production.

## Client Implications

The Paygate client can use Breez SDK Spark as a real-money payer backend if it
keeps these invariants:

- Prepare the payment before sending.
- Require the prepared method to be BOLT11.
- Reject if the prepared Lightning fee exceeds local `max_fee_sats`.
- Send with `SendPaymentOptions.BOLT11_INVOICE(prefer_spark=False, ...)`.
- Fail if Breez reports success without a preimage.
- Verify `sha256(preimage) == payment_hash` before retrying the protected
  request.

Spark-direct settlement must stay disabled for Paygate payments because Paygate
needs Lightning proof material, not just a paid status.

## Reference Service Implications

The Paygate reference service should continue to issue BOLT11 invoices and bind
the challenge to the invoice payment hash. On retry, it should accept only a
credential that proves the preimage for that payment hash.

Recommended server-side rule:

```python
sha256(bytes.fromhex(preimage_hex)).hexdigest() == payment_hash_hex
```

The reference service should not accept `paid=true` alone as sufficient proof.
The retry credential must be tied to the selected challenge, service, request
scope, and payment hash.

## Not Yet Proven

- Breez SDK Spark as the merchant/payee backend for the Paygate reference
  service.
- Server-side Breez invoice lifecycle tracking.
- Breez webhooks/events as settlement notification infrastructure.
- Production wallet operations: backup, rotation, deployment storage, and
  mnemonic handling.

## Recommended Next Steps

1. Use the new Breez payer backend in `paygate-client` for a full Paygate smoke
   test.
2. Keep LND REST as the fallback/proven infrastructure path.
3. Add a separate Breez merchant/payee spike in the reference service.
4. Define production handling for Breez mnemonic storage before any unattended
   deployment.
