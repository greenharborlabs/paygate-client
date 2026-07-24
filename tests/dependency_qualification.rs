use std::str::FromStr;

use bech32::Bech32;
use lightning_invoice::Bolt11Invoice;
use paygate::config::{ConfigInputError, from_safe_yaml};
use serde::Deserialize;

// BOLT #11 amount-bearing signed example, also carried by lightning-invoice's corpus.
const SIGNED_AMOUNT_VECTOR: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";

#[test]
fn signed_amount_vector_rejects_checksum_and_signature_corruption() {
    let valid = Bolt11Invoice::from_str(SIGNED_AMOUNT_VECTOR).expect("official vector is valid");
    assert_eq!(valid.amount_milli_satoshis(), Some(250_000_000));

    let mut checksum_corrupt = SIGNED_AMOUNT_VECTOR.as_bytes().to_vec();
    let last = checksum_corrupt.last_mut().expect("vector is nonempty");
    *last = if *last == b'q' { b'p' } else { b'q' };
    let checksum_corrupt = String::from_utf8(checksum_corrupt).expect("ASCII vector");
    assert!(Bolt11Invoice::from_str(&checksum_corrupt).is_err());

    // Decode and re-encode after changing a byte in the recoverable signature. The new
    // Bech32 checksum is valid, so rejection independently proves signature validation.
    let (hrp, mut payload) = bech32::decode(SIGNED_AMOUNT_VECTOR).expect("valid Bech32");
    let recovery_id = payload.last_mut().expect("signature recovery byte");
    *recovery_id = 0xff;
    let signature_corrupt = bech32::encode::<Bech32>(hrp, &payload).expect("rechecksummed");
    assert!(Bolt11Invoice::from_str(&signature_corrupt).is_err());
}

#[test]
fn direct_dependency_versions_and_breez_source_are_immutable() {
    let manifest = include_str!("../Cargo.toml");
    let lock = include_str!("../Cargo.lock");
    for pin in [
        "lightning-invoice = { version = \"=0.34.1\"",
        "keyring = \"=4.1.5\"",
        "serde-saphyr = { version = \"=0.0.29\"",
        "rev = \"f660f5a3bf24323e5c14235efcd28e5aef06c8aa\"",
    ] {
        assert!(manifest.contains(pin), "missing immutable pin: {pin}");
    }
    assert!(lock.contains("https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa"));
}

#[derive(Debug, Deserialize, PartialEq)]
struct YamlProbe {
    enabled: bool,
    label: String,
    nested: std::collections::BTreeMap<String, String>,
}

#[test]
fn safe_yaml_boundary_accepts_only_the_qualified_subset() {
    let parsed: YamlProbe =
        from_safe_yaml(b"enabled: true\nlabel: 'yes'\nnested: {first: one, second: two}\n")
            .expect("safe document");
    assert!(parsed.enabled);
    assert_eq!(parsed.label, "yes");

    for (name, input) in [
        ("empty", ""),
        ("comment-only empty", "# no configuration\n"),
        ("multiple", "---\na: b\n---\na: c\n"),
        ("trailing", "a: b\n...\nc: d\n"),
        ("duplicate block", "a: b\na: c\n"),
        ("duplicate nested", "a: {b: c, b: d}\n"),
        ("alias", "a: &x b\nc: *x\n"),
        ("merge", "a: {<<: b}\n"),
        ("local tag", "a: !secret b\n"),
        ("global tag", "a: !<tag:example.com,2026:x> b\n"),
        ("directive", "%YAML 1.2\n---\na: b\n"),
        (
            "unused tag directive",
            "%TAG !e! tag:example.com,2026:\n---\na: b\n",
        ),
        ("composite key", "? [a, b]\n: c\n"),
        ("yaml11 boolean", "enabled: ON\nlabel: ok\nnested: {}\n"),
        ("malformed", "a: [b\n"),
    ] {
        let result = from_safe_yaml::<serde_json::Value>(input.as_bytes());
        assert!(result.is_err(), "{name} unexpectedly accepted");
    }
    assert_eq!(
        from_safe_yaml::<serde_json::Value>(&[0xff]),
        Err(ConfigInputError::Utf8)
    );
}

#[test]
fn source_policy_routes_yaml_deserialization_through_config_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fn inspect(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).expect("read Rust source tree") {
            let entry = entry.expect("entry");
            if entry.path().is_dir() {
                inspect(&entry.path());
            } else if entry.file_name() != "config.rs" {
                let source = std::fs::read_to_string(entry.path()).expect("Rust source");
                assert!(
                    !source.contains("serde_saphyr::from_")
                        && !source.contains("serde_saphyr::Deserializer"),
                    "permissive YAML use outside config.rs"
                );
            }
        }
    }
    inspect(&root);
}

#[test]
fn breez_qualification_source_cannot_submit_payment() {
    let source = include_str!("breez_lifecycle_qualification.rs");
    let forbidden = [".send", "_payment("].concat();
    assert!(!source.contains(&forbidden));
    assert!(source.contains(".prepare_send_payment("));
}
