# Phoenixd payer backend spike

Paygate's Phoenixd payer uses Phoenixd's HTTP `POST /payinvoice` endpoint with
HTTP Basic auth. Phoenixd validates the password from `phoenixd.password_env`;
the backend uses the same username convention as `phoenix-cli` and never sends
the password outside the `Authorization` header.

## Fee limit capability

Paygate must be able to enforce `max_fee_sats` before submitting an invoice. The
current upstream Phoenixd `payinvoice` API documents `invoice`, optional
`amountSat`, and `sendAll` form parameters, and its v0.8.0 source does not show
a documented per-payment Lightning routing fee cap. For V1, configure this
backend with a fee-limit parameter only after validating the target Phoenixd API
version enforces that parameter. If no enforceable parameter is configured, the
backend raises `FeeLimitUnsupportedError` before posting the invoice.

The forward-compatible default parameter is `maxFeeSat`. Operators must verify
their Phoenixd build supports and enforces it before enabling real payments.

## Preimage capability check

Phoenixd successful `payinvoice` responses are expected to include:

- `recipientAmountSat`
- `routingFeeSat`
- `paymentHash`
- `paymentPreimage`

Paygate treats a successful payment response without `paymentPreimage` as
unsupported for V1. It raises `MissingPreimageError` instead of returning a
payment result or attempting a silent fallback.

## Manual verification procedure

Use a low-value invoice whose payment hash is known from Paygate's selected
challenge:

1. Run `paygate backend doctor` with the Phoenixd config to verify the backend is
   reachable and authenticated.
2. Run `paygate backend pay-invoice <invoice> --max-fee-sats <small cap>` against
   a small invoice.
3. Confirm the command prints a preimage and that the preimage hash matches the
   challenge `payment_hash`.
4. If payment succeeds but no preimage is returned, mark that Phoenixd API as
   unsupported for Paygate V1.

Do not run the payment check with an unlimited fee cap. A Phoenixd API that
cannot reject payments above Paygate's configured fee cap is unsupported until a
documented enforceable fee-limit parameter is available.
