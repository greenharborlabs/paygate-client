//! Deterministic fuzz-smoke coverage for parser and diagnostic trust boundaries.
//!
//! This intentionally has no network, payer, state, or keyring dependency, so
//! it can be run in the locked/offline integration qualification gate.

use paygate::invoice::ValidatedBolt11;
use paygate::redaction::{REDACTED_PROOF, redact_text};

#[test]
fn hostile_text_corpus_never_panics_or_leaks_hex_payment_material() {
    let proof = "ab".repeat(32);
    let corpus = [
        String::new(),
        "not-a-bolt11".into(),
        "lnbc1".into(),
        "\0\u{fffd}\n\t".into(),
        "f".repeat(8 * 1024),
        format!("invoice={proof}"),
        format!("prefix{proof}suffix"),
        format!("{{\"preimage\":\"{proof}\"}}"),
    ];

    for candidate in corpus {
        let _ = ValidatedBolt11::parse(&candidate);
        let rendered = redact_text(&candidate, &[]);
        assert!(!rendered.contains(&proof));
        if candidate.contains(&proof) {
            assert!(rendered.contains(REDACTED_PROOF));
        }
    }
}
