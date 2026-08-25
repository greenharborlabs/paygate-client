use paygate::state::cache::{CredentialScope, FileCredentialCache};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn concurrent_cache_instances_can_claim_a_single_use_credential_only_once() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "paygate-credential-claim-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("credentials.json");
    let scope = CredentialScope {
        namespace: "default".into(),
        request_key: "request".into(),
        origin_host: Some("paygate.test:443".into()),
        service: Some("svc".into()),
        protocol: "Payment".into(),
        payer_backend: "breez".into(),
        policy_hash: "policy".into(),
    };
    let state = serde_json::json!({
        "version": 1,
        "credentials": [{
            "id": "single-use",
            "scope": scope,
            "authorization": "Payment one-use-secret",
            "createdAt": 1,
            "expiresAt": null,
            "maxUses": 1,
            "useCount": 0,
            "lastSuccessAt": null,
            "lastRejectedAt": null,
            "paymentHash": null,
            "challengeId": null
        }]
    });
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let path = path.clone();
        let scope = scope.clone();
        workers.push(std::thread::spawn(move || {
            let cache = FileCredentialCache::new(path, Some("default")).unwrap();
            barrier.wait();
            cache.claim_scoped_fail_closed(&scope, 100).unwrap()
        }));
    }
    barrier.wait();
    let claims = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    assert_eq!(
        claims.iter().flatten().next().unwrap().authorization,
        "Payment one-use-secret"
    );
    let persisted = FileCredentialCache::new(&path, Some("default"))
        .unwrap()
        .list()
        .unwrap();
    assert_eq!(persisted[0].use_count, 1);
    assert!(
        FileCredentialCache::new(&path, Some("default"))
            .unwrap()
            .claim_scoped_fail_closed(&scope, 100)
            .unwrap()
            .is_none()
    );

    fs::remove_dir_all(root).unwrap();
}
