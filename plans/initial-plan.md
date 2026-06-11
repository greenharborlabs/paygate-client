  # Paygate Client V1 Plan

  ## Summary

  Build paygate-client as a standalone Python CLI for agents. It hides the Paygate 402 -> pay invoice -> get preimage -> retry with Authorization loop, while keeping the preimage-proof
  security model.

  The key product adjustment is to make Phoenixd the first low-friction payer backend to test, with LND/Voltage as the production-grade fallback. LNbits remains useful for API owners as
  the merchant/payee backend, but not as the automated payer backend unless it exposes preimages.

  ## Key Changes

  - Create a new Python repo/package: paygate-client.
  - Main command:

    paygate request GET "https://api.example.com/protected"

  - Flow:
      1. Call the API.
      2. If response is not 402, return a JSON envelope.
      3. If 402, parse Payment and/or L402 challenges.
      4. Enforce host/service allowlists and spend caps.
      5. Pay the invoice through the configured payer backend.
      6. Require the backend to return the payment preimage.
      7. Build the Paygate credential.
      8. Retry with Authorization.
      9. Return JSON with response, payment metadata, and receipt if present.

  - Supported v1 protocols:
      - Payment / MPP: retry with Authorization: Payment <credential>.
      - L402: retry with Authorization: L402 <token>:<preimage_hex>.

  - Payer backend priority:
      1. phoenixd: first backend spike and preferred default if it returns preimages reliably.
      2. lnd-rest: supported fallback for Voltage/LND.
      3. test-mode: local development backend for Paygate test challenges.
      4. breez-sdk: research candidate after Phoenixd, not required for v1.

  - Explicitly unsupported in v1:
      - LNbits SaaS as payer when it does not expose preimages.
      - Consumer phone wallets as automated payer backends.
      - Hosted custodial Paygate wallet service.

  ## Public Interface

  - Example config:

    payer:
      backend: phoenixd

    phoenixd:
      url: "http://127.0.0.1:9740"
      password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"

    lnd:
      rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
      macaroon_hex_env: "PAYGATE_CLIENT_LND_MACAROON_HEX"
      tls_cert_path_env: "PAYGATE_CLIENT_LND_TLS_CERT_PATH"

    policy:
      max_request_sats: 50
      max_fee_sats: 10
      daily_budget_sats: 500
      allowed_hosts:
        - localhost:8080
        - paygate-reference.greenharborlabs.com
      allowed_services:
        - paygate-reference-service

    protocol:
      preferred: Payment
      allow_l402: true

  - Success output:

    {
      "ok": true,
      "paid": true,
      "protocol": "Payment",
      "payerBackend": "phoenixd",
      "amountSats": 10,
      "feeSats": 0,
      "paymentHash": "...",
      "receipt": "...",
      "response": {
        "status": 200,
        "headers": {},
        "body": {}
      }
    }

  ## Test Plan

  - Backend spike first:
      - Run Phoenixd locally.
      - Fund with a small amount.
      - Pay a Paygate LNbits invoice.
      - Confirm Phoenixd returns the payment preimage.
      - If not, mark Phoenixd unsupported and fall back to LND REST.

  - Unit tests:
      - Parse Payment and L402 challenges.
      - Build valid credentials for both protocols.
      - Enforce allowlists and spend caps.
      - Normalize preimage formats to lowercase 64-char hex.
      - Fail clearly when backend pays but no preimage is available.

  - Integration tests:
      - Mock Paygate 402 -> 200 flow.
      - Mock Phoenixd successful payment with preimage.
      - Mock LND REST successful payment with preimage.
      - Local Paygate 0.1.3 test-mode flow.
      - Optional real-sats smoke test only after Phoenixd backend is proven.

  ## Assumptions

  - The current Paygate protocol remains preimage-proof based.
  - API owners can continue using LNbits as the merchant/payee backend.
  - Agents should not need to understand channels, invoices, macaroons, or preimages.
  - The client can hide Paygate mechanics, but cannot avoid the need for a payer backend that exposes preimages.
  - We should test Phoenixd before funding Voltage, because it may remove most of the channel/liquidity setup friction for US developers.
