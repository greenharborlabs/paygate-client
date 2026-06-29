# Production Plan: Python Paygate Client + Voltage Payer Node

  ## Summary

  We are currently in a good local-client position: paygate-client has a green test baseline, supports test-mode, verifies preimages, enforces spend policy, and includes an lnd-rest
  backend suitable for Voltage/LND-style real payments.

  LNbits-over-Spark should not be used for payer automation because Paygate needs a returned payment preimage and fee-cap enforcement. The first production setup should connect paygate-
  client directly to Voltage LND REST as a payer-only node with ultra-low payment caps.

  ## Section 1: Lock Down Local Client Readiness

  - Keep test-mode as the default local/dev path.
  - Continue using the Paygate reference service with the predefined test preimage.
  - Verify the full local flow:
      - unauthenticated request
      - 402 challenge parse
      - policy approval
      - preimage verification
      - credential creation
      - paid retry success

  - Add focused edge-case tests:
      - valid predefined preimage succeeds
      - preimage/hash mismatch fails before retry
      - missing test_preimage invokes real payer only when configured
      - paid retry rejection returns paid_retry_rejected
      - host/service/amount/budget denial prevents payer invocation

  Pause Gate

  Summarize:

  - which tests were added or confirmed
  - whether the reference-service flow passed
  - any failures or gaps found

  Then ask whether to move on to Voltage setup.

  ## Section 2: Prepare Voltage As The Real Payer Backend

  - Create or select a dedicated Voltage LND node for Paygate payer automation.
  - Enable or retrieve LND REST access:
      - REST URL
      - macaroon hex
      - TLS certificate path, if required

  - Prefer a least-privilege macaroon if Voltage supports it.
  - Store credentials only in environment variables:
      - PAYGATE_CLIENT_LND_REST_URL
      - PAYGATE_CLIENT_LND_MACAROON_HEX
      - PAYGATE_CLIENT_LND_TLS_CERT_PATH

  Pause Gate

  Summarize:

  - Voltage node status
  - REST credential status
  - whether secrets are configured locally
  - any permission/security concerns

  Then ask whether to move on to funding and channel setup.

  ## Section 3: Fund And Prepare Outbound Liquidity

  - Fund the Voltage node on-chain with the smallest practical production amount.
  - Open one small outbound channel, either through Voltage tooling or to a well-connected peer.
  - Confirm outbound Lightning payments work before connecting Paygate automation.
  - Do not increase channel size or caps until diagnostics and live smoke tests pass.

  Pause Gate

  Summarize:

  - on-chain funding status
  - channel status
  - outbound liquidity available
  - any routing or fee concerns

  Then ask whether to move on to configuring paygate-client.

  ## Section 4: Configure paygate-client For Production Payer Use

  Use this initial production config shape:

  payer:
    backend: lnd-rest

  protocol:
    preferred: Payment
    allow_l402: true

  policy:
    max_request_sats: 10
    max_fee_sats: 2
    daily_budget_sats: 100
    allowed_hosts:
      - <production-paygate-host>:443
    allowed_services:
      - paygate-reference-service

  lnd:
    rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
    macaroon_hex_env: "PAYGATE_CLIENT_LND_MACAROON_HEX"
    tls_cert_path_env: "PAYGATE_CLIENT_LND_TLS_CERT_PATH"

  - Keep allowlists explicit.
  - Do not use wildcard hosts or services.
  - Prefer Payment; allow L402 only for compatible services.
  - Keep caps ultra-low for the first production run.

  Pause Gate

  Summarize:

  - final config values, excluding secrets
  - active host/service allowlists
  - spend caps
  - selected protocol behavior

  Then ask whether to move on to diagnostics and live validation.

  ## Section 5: Production Validation Gates

  Run backend diagnostics:

  paygate backend doctor --config ~/.config/paygate-client/config.yaml --json

  Required:

  - ok: true
  - backend is lnd-rest
  - maxFeeLimitSupported: true

  Pay a 1-sat standalone invoice:

  paygate backend pay-invoice <bolt11> \
    --config ~/.config/paygate-client/config.yaml \
    --max-fee-sats 2 \
    --json

  Required:

  - ok: true
  - preimageVerified: true
  - fee within cap

  Then run one full Paygate request against the reference service using real Lightning payment.

  Pause Gate

  Summarize:

  - doctor result
  - standalone invoice result
  - real Paygate request result
  - amount paid, fee paid, and payment hash
  - any failures or unsafe behavior

  Then ask whether to move on to broader rollout or keep investigating.

  ## Section 6: Broader Rollout

  Only after all prior gates pass:

  - Add additional production Paygate hosts/services to allowlists one at a time.
  - Keep the first rollout under ultra-low caps.
  - Monitor failures, fee behavior, retries, and budget ledger behavior.
  - Increase caps only after repeated successful low-value payments.
  - Keep LNbits-over-Spark out of the payer path unless it later exposes payer-side preimages and enforceable fee caps.

  Pause Gate

  Summarize:

  - services enabled
  - observed payment reliability
  - total spend and fees
  - recommended next cap increase or hold

  Then ask whether to expand rollout or stop at the current safety level.

  ## Assumptions

  - Voltage exposes standard LND REST compatible with POST /v2/router/send.
  - Voltage/LND returns terminal payment_preimage on successful sends.
  - First production architecture is payer-only.
  - Initial caps are ultra-low: max_request_sats around 1-10, max_fee_sats around 1-2, and daily_budget_sats around 50-100.
  - LNbits-over-Spark remains unsupported for automated payer use.