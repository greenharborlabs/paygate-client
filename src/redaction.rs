//! Small, dependency-free redaction helpers for errors and diagnostics.

pub const REDACTED_SECRET: &str = "[REDACTED_SECRET]";
pub const REDACTED_CREDENTIAL: &str = "[REDACTED_CREDENTIAL]";
pub const REDACTED_PROOF: &str = "[REDACTED_PAYMENT_PROOF]";

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
    redact_hex_payment_material(&value)
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
        for diagnostic in [
            format!("preimage={proof}"),
            format!("?payment_hash={proof}&status=failed"),
            format!(r#"{{"preimage":"{proof}"}}"#),
        ] {
            let rendered = redact_text(&diagnostic, &[]);
            assert!(!rendered.contains(&proof));
            assert!(rendered.contains(REDACTED_PROOF));
        }
    }
}
