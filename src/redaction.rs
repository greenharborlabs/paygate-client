//! Small, dependency-free redaction helpers for errors and diagnostics.

pub const REDACTED_SECRET: &str = "[REDACTED_SECRET]";
pub const REDACTED_CREDENTIAL: &str = "[REDACTED_CREDENTIAL]";
pub const REDACTED_PROOF: &str = "[REDACTED_PAYMENT_PROOF]";

pub fn redact_header(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "authorization" | "proxy-authorization") {
        let scheme = value.split_ascii_whitespace().next().filter(|scheme| {
            matches!(
                scheme.to_ascii_lowercase().as_str(),
                "basic" | "bearer" | "payment" | "l402"
            )
        });
        return scheme.map_or_else(
            || REDACTED_CREDENTIAL.into(),
            |scheme| format!("{scheme} {REDACTED_CREDENTIAL}"),
        );
    }
    if matches!(lower.as_str(), "www-authenticate" | "set-cookie" | "cookie") {
        return REDACTED_CREDENTIAL.into();
    }
    if sensitive_key(name) {
        return REDACTED_SECRET.into();
    }
    redact_text(value, &[])
}

pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if sensitive_key(key) {
                    *value = serde_json::Value::String(REDACTED_SECRET.into());
                } else {
                    redact_json(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        serde_json::Value::String(text) => *text = redact_text(&*text, &[]),
        _ => {}
    }
}

/// Replace supplied secrets and 32-byte hex payment material before rendering a
/// diagnostic.  This is intentionally conservative: successful response fields
/// are formatted by their owning serialization layer, not this helper.
pub fn redact_text(value: impl AsRef<str>, secrets: &[&str]) -> String {
    let mut value = value.as_ref().to_owned();
    let mut secrets = secrets.to_vec();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    for secret in secrets.into_iter().filter(|secret| !secret.is_empty()) {
        value = value.replace(secret, REDACTED_SECRET);
    }
    let lower = value.to_ascii_lowercase();
    if [
        "authorization",
        "preimage",
        "invoice",
        "macaroon",
        "password",
        "api_key",
        "api-key",
        "secret",
        "token=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || lower
            .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '=' | ':' | ','))
            .any(|part| {
                part.starts_with("lnbc") || part.starts_with("lntb") || part.starts_with("lnbcrt")
            })
    {
        return REDACTED_SECRET.into();
    }
    redact_hex_payment_material(&value)
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace(['-', '_'], "");
    [
        "authorization",
        "preimage",
        "invoice",
        "paymentrequest",
        "macaroon",
        "password",
        "apikey",
        "secret",
        "token",
    ]
    .iter()
    .any(|sensitive| key == *sensitive || key.ends_with(sensitive))
}

/// Redact contiguous hexadecimal material even when it is embedded in a JSON,
/// query-string, or `key=value` diagnostic. Splitting on whitespace is not
/// sufficient because payment proofs commonly appear without surrounding
/// whitespace.
fn redact_hex_payment_material(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;

    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_hexdigit() {
            let character = value[cursor..]
                .chars()
                .next()
                .expect("cursor remains on a UTF-8 boundary");
            redacted.push(character);
            cursor += character.len_utf8();
            continue;
        }

        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() {
            cursor += 1;
        }
        let candidate = &value[start..cursor];
        if candidate.len() >= 64 && candidate.len() % 2 == 0 {
            redacted.push_str(REDACTED_PROOF);
        } else {
            redacted.push_str(candidate);
        }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_payment_material_in_structured_diagnostics() {
        let proof = "ab".repeat(32);
        for (diagnostic, expected_redaction) in [
            (format!("preimage={proof}"), REDACTED_SECRET),
            (
                format!("?payment_hash={proof}&status=failed"),
                REDACTED_PROOF,
            ),
            (format!(r#"{{"preimage":"{proof}"}}"#), REDACTED_SECRET),
        ] {
            let rendered = redact_text(&diagnostic, &[]);
            assert!(!rendered.contains(&proof));
            assert!(rendered.contains(expected_redaction));
        }
    }

    #[test]
    fn header_redaction_preserves_auth_scheme_and_safe_headers() {
        assert_eq!(
            redact_header("Authorization", "Payment opaque"),
            "Payment [REDACTED_CREDENTIAL]"
        );
        assert_eq!(
            redact_header("Proxy-Authorization", "L402 token:proof"),
            "L402 [REDACTED_CREDENTIAL]"
        );
        assert_eq!(
            redact_header("Authorization", "malformed"),
            REDACTED_CREDENTIAL
        );
        for name in [
            "X-Api-Key",
            "X-Auth-Token",
            "Password",
            "client-secret",
            "invoice",
        ] {
            assert_eq!(redact_header(name, "sensitive"), REDACTED_SECRET);
        }
        assert_eq!(redact_header("X-Request-Id", "safe-value"), "safe-value");
    }
}
