use std::fs;

use paygate::state::cache::{CachedCredential, CredentialScope, FileCredentialCache};

fn credential(id: &str, host: &str, service: &str, rejected: bool) -> CachedCredential {
    CachedCredential {
        credential_id: id.into(),
        scope: CredentialScope {
            namespace: "default".into(),
            request_key: format!("request-{id}"),
            origin_host: Some(host.into()),
            service: Some(service.into()),
            protocol: "Payment".into(),
            payer_backend: "test-mode".into(),
            policy_hash: "policy".into(),
        },
        authorization: format!("Payment secret-{id}"),
        created_at: 1,
        expires_at: Some(2),
        max_uses: None,
        use_count: 0,
        last_success_at: None,
        last_rejected_at: rejected.then_some(3),
        payment_hash: None,
        challenge_id: None,
        secret_storage: None,
    }
}

#[test]
fn purge_filters_raw_expired_and_rejected_metadata_by_host_and_service() {
    let root = std::env::temp_dir().join(format!(
        "paygate-credential-purge-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&root);
    let path = root.join("credentials.json");
    let cache = FileCredentialCache::new(&path, Some("default")).unwrap();
    cache
        .put(credential("one", "a.test:443", "orders", false))
        .unwrap();
    cache
        .put(credential("two", "a.test:443", "billing", true))
        .unwrap();
    cache
        .put(credential("three", "b.test:443", "orders", false))
        .unwrap();

    assert_eq!(
        cache
            .purge(Some("a.test:443"), Some("orders"), false)
            .unwrap(),
        1
    );
    let remaining: Vec<_> = cache
        .list()
        .unwrap()
        .into_iter()
        .map(|credential| credential.credential_id)
        .collect();
    assert_eq!(remaining, vec!["two", "three"]);
    assert_eq!(cache.purge(Some("a.test:443"), None, false).unwrap(), 1);
    assert_eq!(cache.list().unwrap()[0].credential_id, "three");
    assert_eq!(cache.purge(None, None, true).unwrap(), 1);
    assert_eq!(cache.purge(None, None, true).unwrap(), 0);

    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["credentials"].as_array().unwrap().len(), 0);
    let fallback = path.with_extension("keyring.json");
    if fallback.exists() {
        let secrets: serde_json::Value =
            serde_json::from_slice(&fs::read(fallback).unwrap()).unwrap();
        assert_eq!(secrets["credentials"].as_array().unwrap().len(), 0);
    }
    let _ = fs::remove_dir_all(root);
}
