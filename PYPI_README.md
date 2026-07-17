# Paygate Client

Paygate Client is a command-line client for services protected by the Paygate
payment protocol.

## Install

Install the client and the optional Breez SDK Spark payer support:

```bash
pipx install "paygate-client[breez]"
```

## Compatibility

The declared CPython support range is 3.9 through 3.14, but these interpreter
and platform combinations are unverified until W2 CI validation is in place.
Breez SDK Spark is available through the optional extra, but its platform and
interpreter combinations are also unverified. Do not treat an unverified
combination as supported.

For configuration, supported payer details, and source code, see the
[documentation](https://github.com/greenharborlabs/paygate-client/tree/main/docs)
and [source repository](https://github.com/greenharborlabs/paygate-client).
