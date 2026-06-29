# Voltage Mainnet Node Setup Guide for Paygate Testing

## Goal

Set up the already-deployed Voltage mainnet LND node as a dedicated, low-risk Paygate payer backend.

This guide is ordered by dependency:

1. Make sure the node is safe and ready.
2. Fund the node on-chain.
3. Open one outbound Lightning channel.
4. Then configure Paygate API access.
5. Then run low-cap Paygate validation.

Do not configure Paygate first and then wonder why payments fail. Paygate can only pay once the node has spendable outbound Lightning liquidity.

Voltage references:

- [REST API examples](https://docs.voltage.cloud/rest-api-examples)
- [Outbound liquidity](https://docs.voltage.cloud/outbound-liquidity)
- [Node-backed setup](https://docs.voltageapi.com/node-backed-setup)

## Phase 1: Verify and Secure the Voltage Node

1. Log into Voltage.
2. Open the node dashboard.
3. Confirm the node is:

   - Mainnet, not testnet or regtest.
   - Synced.
   - Unlocked.
   - Accessible from the Voltage dashboard.

4. Confirm recovery material is saved somewhere safe outside this repo:

   - Seed phrase.
   - Node password, if applicable.
   - Backup export.
   - Static channel backup access.

5. Keep secrets out of unsafe places:

   - Do not paste seed words, passwords, macaroon values, or TLS keys into chat.
   - Do not commit them to the repo.
   - Do not put them in docs or screenshots.
   - Avoid pasting them into shell commands that may be saved in history.

Stop here if the node is not synced, not unlocked, or backups are not understood.

## Phase 2: Fund the Node On-Chain

1. In Voltage, open ThunderHub or Terminal Web for the node.
2. Generate a fresh on-chain receive address.
3. Send enough sats for one practical mainnet Lightning channel plus on-chain fees.

   Planning default:

   ```text
   Channel capacity: about 1,000,000 sats
   Extra for fees: enough to open the channel safely in current mempool conditions
   ```

   Voltage docs recommend not opening production channels below `1,000,000` sats. You can use less only if you knowingly accept higher routing-failure risk.

4. Wait for the funding transaction to confirm.
5. Confirm the on-chain balance appears in the Voltage node tools.

Do not move to channel setup until the on-chain funds are confirmed and available.

## Phase 3: Open One Outbound Channel

1. In ThunderHub or Terminal Web, choose a well-connected peer.

   Good first peer traits:

   - Public node.
   - High uptime.
   - Good connectivity.
   - Reasonable fees.
   - Visible in common Lightning node rankings or recommendations.

2. Open one public channel from your Voltage node to that peer.
3. Use roughly `1,000,000` sats capacity unless budget or mempool conditions require a different amount.
4. Use Voltage's on-screen or automatic fee guidance unless the mempool is unusually expensive.
5. Wait for the channel open transaction to confirm.
6. Confirm the channel status is open/active, not pending.
7. Confirm outbound liquidity appears in ThunderHub or Terminal Web.

At this point, the node should be able to attempt Lightning payments. One outbound channel improves payment ability, but it does not guarantee every route will work.

## Phase 4: Create API Access for Paygate

Only do this after the node is funded and has outbound liquidity.

1. In Voltage, open the node dashboard.
2. Go to **Manage Access > Macaroon Bakery**.
3. Prefer the narrowest payment-capable macaroon Voltage allows.

   Paygate needs authorization for LND Router payment calls, including the REST endpoint behind:

   ```text
   /v2/router/send
   ```

   The underlying LND method is:

   ```text
   /routerrpc.Router/SendPaymentV2
   ```

4. If Voltage only offers **Read only**, **Invoice**, and **Support** bake options, those are not enough for Paygate payments.
5. If no narrower payment-capable macaroon is available, use the existing **Admin** macaroon only as a short-lived local test fallback for this low-cap phase.

   Do not use **Super Admin** unless there is no other working option. Do not use **BTCPay Server** for Paygate unless you have separately verified it authorizes Router payment calls.

6. Capture these values:

   ```text
   LND REST URL: https://<node>.m.voltageapp.io:8080
   Macaroon: hex string
   TLS cert: only if Voltage explicitly provides/requires one
   ```

Voltage hosted REST commonly uses CA-signed TLS, so a custom TLS cert is usually not required.

Security warning: a stolen admin macaroon can spend funds outside Paygate's local caps. Keep the node low-funded for this phase and rotate credentials if Voltage later provides a narrower Router payment macaroon.

## Phase 5: Configure Local Paygate Secrets

Keep credentials local and outside tracked files.

Prefer the local setup wizard, which reads the macaroon with hidden input and writes secrets to a `chmod 600` env file outside the repo:

```bash
scripts/setup-voltage-paygate.sh
```

The client automatically loads `voltage-env.sh` when it sits next to
`config.yaml`. You only need to `source ~/.config/paygate-client/voltage-env.sh`
if you want those values in your current shell for manual debugging.

If configuring manually, set secrets only in your local environment:

```bash
export PAYGATE_CLIENT_LND_REST_URL="https://<node>.m.voltageapp.io:8080"
export PAYGATE_CLIENT_LND_MACAROON_HEX="<macaroon-hex>"
# only if Voltage requires a custom TLS cert:
export PAYGATE_CLIENT_LND_TLS_CERT_PATH="/path/to/tls.cert"
```

If Voltage gives you a `.macaroon` file instead of a copied hex string, hex encode the file first:

```bash
xxd -p -c 1000 /path/to/admin.macaroon
```

Verify the environment variables are present without printing their values:

```bash
for v in PAYGATE_CLIENT_LND_REST_URL PAYGATE_CLIENT_LND_MACAROON_HEX; do
  if [ -n "${!v:-}" ]; then
    printf '%s=SET\n' "$v"
  else
    printf '%s=unset\n' "$v"
  fi
done
```

Only check `PAYGATE_CLIENT_LND_TLS_CERT_PATH` if your config includes `tls_cert_path_env`.

## Phase 6: Create the Local Paygate Config

Create or update a local config outside tracked files, such as `~/.config/paygate-client/config.yaml`:

```yaml
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
  # Include only if Voltage requires a custom TLS cert:
  # tls_cert_path_env: "PAYGATE_CLIENT_LND_TLS_CERT_PATH"
```

Keep the first caps intentionally tiny:

```text
max_request_sats: 10
max_fee_sats: 2
daily_budget_sats: 100
```

Raise them only after repeated successful live tests.

## Phase 7: Run Local Backend Diagnostics

Run:

```bash
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
```

Required result:

- `ok: true`
- `backend: lnd-rest`
- `capabilities.maxFeeLimitSupported: true`

Important limitation: this validates local config loading, secret presence, and backend capabilities. It does not fully prove the Voltage REST URL, TLS verification, macaroon permissions, channel liquidity, or Lightning routability.

The standalone invoice payment in the next phase is the first real end-to-end check.

## Phase 8: Pay One Standalone Low-Value Invoice

Create or obtain a tiny invoice from another node, wallet, or trusted service.

Then run:

```bash
paygate backend pay-invoice <bolt11> \
  --config ~/.config/paygate-client/config.yaml \
  --max-fee-sats 2 \
  --json
```

Required result:

- `ok: true`
- `preimageVerified: true`
- `feeSats <= 2`

This proves the practical path:

```text
Paygate config -> Voltage REST -> macaroon auth -> Router payment API -> outbound liquidity -> route -> preimage verification
```

If the payment fails only because the `2` sat fee cap is too strict, treat that as a safe routing failure rather than a setup failure. Raise the cap only deliberately and within the configured test budget.

## Phase 9: Run One Full Paygate Request

1. Keep the low caps:

   ```text
   max_request_sats: 10
   max_fee_sats: 2
   daily_budget_sats: 100
   ```

2. First inspect the challenge without paying:

   ```bash
   paygate request GET \
     "http://localhost:8080/api/v1/trust/report?domain=example.com&checks=dns" \
     --config ~/.config/paygate-client/config.yaml \
     --no-pay --trace-json
   ```

   Required:

   - `ok: true`
   - `paid: false`
   - `wouldPay: true`
   - `amountSats` is within policy
   - `service` matches an allowlisted service

3. Run one full Paygate request against the reference service:

   ```bash
   paygate request GET \
     "http://localhost:8080/api/v1/trust/report?domain=example.com&checks=dns" \
     --config ~/.config/paygate-client/config.yaml \
     --verbose
   ```

4. Confirm the final envelope has:

   - `ok: true`
   - `paid: true`
   - `payerBackend: lnd-rest`
   - verified `paymentHash`

5. For a repeat request, the client should try a cached credential first. A
   successful cache reuse returns `paid: false` and `credentialCache.hit: true`.
   Use `--refresh-credential` only when you deliberately want to pay a fresh
   challenge.

## Completion Checklist

- Voltage node is mainnet, synced, unlocked, and backed up.
- Node has confirmed on-chain funds.
- Node has one confirmed, active outbound channel.
- Outbound liquidity is visible in ThunderHub or Terminal Web.
- Paygate local env vars are set without revealing values.
- Local config uses `lnd-rest`.
- `paygate backend doctor` passes.
- A standalone low-value invoice payment succeeds and returns a verified preimage.
- A full Paygate request succeeds with a real Lightning payment.

## Stop Conditions

Stop immediately if:

- Node backups are not understood.
- Node is not synced or unlocked.
- Funding transaction is unconfirmed.
- Channel is still pending.
- Outbound liquidity is missing.
- `paygate backend doctor` fails.
- Backend cannot enforce max fees.
- Macaroon is rejected by the Router payment call.
- Preimage verification fails.
- Routing fees exceed the configured cap.
- Paid retry is rejected.
- Routing is unreliable enough that repeated low-value tests fail.

## Assumptions

- You will reuse the already-deployed Voltage mainnet node.
- Initial funding target is about `1,000,000` sats plus fees for the first practical channel.
- The first liquidity path is one outbound public channel opened via Voltage ThunderHub or Terminal Web.
- Paygate remains payer-only for this node.
- Secrets stay in environment variables only.
- Caps remain ultra-low until repeated live tests pass.
