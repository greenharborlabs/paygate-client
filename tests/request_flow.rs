use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use paygate::challenge::{
    ChallengeError, ChallengeProtocol, ProtocolPreference, parse_www_authenticate,
};
use paygate::challenge::{L402WireChallenge, ParsedChallenge, PaymentWireChallenge};
use paygate::commands::request::{
    RequestCache, RequestOptions, RequestTransport, build_request_policy_hash, execute_with,
};
use paygate::config::{PayerConfig, PaygateConfig, ProtocolConfig};
use paygate::http::{HttpError, HttpRequest, HttpResponse};
use paygate::invoice::ValidatedBolt11;
use paygate::orchestrator::{RealPayerFactory, TransactionError, execute_payment_transaction};
use paygate::payers::base::PaymentError;
use paygate::payers::base::{CancellationSemantics, PaymentAttemptOutcome, RealPayer};
use paygate::policy::PolicyConfig;
use paygate::state::cache::{
    CachedCredential, CredentialScope, FileCredentialCache, build_request_key,
};
use paygate::state::ledger::{
    DailySpendLedger, LedgerError, LedgerMutationOutcome, LedgerWriteFault,
};
use std::{
    collections::BTreeMap,
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";

struct NeverPayer;
#[async_trait]
impl RealPayer for NeverPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        unreachable!()
    }
    async fn pay(
        &self,
        _: &ValidatedBolt11,
        _: u64,
        _: CancellationSemantics,
    ) -> PaymentAttemptOutcome {
        unreachable!()
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        unreachable!()
    }
}

struct ConfirmedPayer {
    raw: paygate::payers::RawPaymentResult,
    pays: Arc<AtomicUsize>,
}
#[async_trait]
impl RealPayer for ConfirmedPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        Ok(())
    }
    async fn pay(
        &self,
        _: &ValidatedBolt11,
        _: u64,
        _: CancellationSemantics,
    ) -> PaymentAttemptOutcome {
        self.pays.fetch_add(1, Ordering::SeqCst);
        PaymentAttemptOutcome::confirmed(self.raw.clone())
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

struct ScriptTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpError>>>,
    auth: Mutex<Vec<Option<String>>>,
}
#[async_trait]
impl RequestTransport for ScriptTransport {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        self.auth.lock().unwrap().push(
            request
                .headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        );
        self.responses.lock().unwrap().pop_front().unwrap()
    }
}

#[derive(Default)]
struct MemoryCache {
    values: Mutex<Vec<CachedCredential>>,
    fail_get: bool,
    fail_put: bool,
    fail_mark: bool,
    fail_delete: bool,
}
impl RequestCache for MemoryCache {
    fn get_scoped(&self, _: &CredentialScope, _: i64) -> Result<Option<CachedCredential>, ()> {
        if self.fail_get {
            Err(())
        } else {
            Ok(self.values.lock().unwrap().first().cloned())
        }
    }
    fn put(&self, c: CachedCredential) -> Result<(), ()> {
        if self.fail_put {
            Err(())
        } else {
            self.values.lock().unwrap().push(c);
            Ok(())
        }
    }
    fn mark_success(&self, _: &str, _: i64) -> Result<(), ()> {
        if self.fail_mark { Err(()) } else { Ok(()) }
    }
    fn mark_rejected(&self, _: &str, _: i64) -> Result<(), ()> {
        if self.fail_mark { Err(()) } else { Ok(()) }
    }
    fn delete(&self, id: &str) -> Result<(), ()> {
        if self.fail_delete {
            Err(())
        } else {
            self.values
                .lock()
                .unwrap()
                .retain(|c| c.credential_id != id);
            Ok(())
        }
    }
}

fn matching_invoice() -> (ValidatedBolt11, String, String) {
    let preimage = [7_u8; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let key = SecretKey::from_slice(&[42_u8; 32]).unwrap();
    let secp = Secp256k1::new();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("request flow".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .unwrap();
    (
        ValidatedBolt11::parse(invoice.to_string()).unwrap(),
        payment_hash.to_string(),
        hex::encode(preimage),
    )
}

fn config() -> PaygateConfig {
    PaygateConfig {
        payer: PayerConfig {
            backend: "breez".into(),
        },
        breez: None,
        policy: paygate::config::PolicyConfig {
            max_request_sats: 10,
            max_fee_sats: 5,
            daily_budget_sats: 20,
            allowed_hosts: vec!["paygate.test:443".into()],
            allowed_services: vec!["svc".into()],
        },
        protocol: ProtocolConfig {
            preferred: "Payment".into(),
            allow_l402: true,
        },
    }
}

fn request_and_402(invoice: &ValidatedBolt11, hash: &str) -> (HttpRequest, HttpResponse) {
    let payload = serde_json::json!({"amountSats":invoice.amount_sats(),"invoice":invoice.original(),"service":"svc","methodDetails":{"paymentHash":hash}});
    let encoded = paygate::serialization::base64_url_nopad(
        serde_json::to_string(&payload).unwrap().as_bytes(),
    );
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::WWW_AUTHENTICATE,
        format!("Basic, Payment id=flow, request={encoded}, expires=4102444800")
            .parse()
            .unwrap(),
    );
    let request = HttpRequest {
        method: reqwest::Method::GET,
        url: reqwest::Url::parse("https://paygate.test/resource").unwrap(),
        headers: reqwest::header::HeaderMap::new(),
        body: None,
        phase_timeout: std::time::Duration::from_secs(5),
    };
    let response = HttpResponse {
        status: reqwest::StatusCode::PAYMENT_REQUIRED,
        headers,
        body: vec![],
    };
    (request, response)
}

fn l402_request(invoice: &ValidatedBolt11) -> (HttpRequest, HttpResponse) {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::WWW_AUTHENTICATE,
        format!("L402 token=l402-token, invoice={}", invoice.original())
            .parse()
            .unwrap(),
    );
    let request = HttpRequest {
        method: reqwest::Method::GET,
        url: reqwest::Url::parse("https://paygate.test/resource").unwrap(),
        headers: reqwest::header::HeaderMap::new(),
        body: None,
        phase_timeout: std::time::Duration::from_secs(5),
    };
    (
        request,
        HttpResponse {
            status: reqwest::StatusCode::PAYMENT_REQUIRED,
            headers,
            body: vec![],
        },
    )
}

#[tokio::test]
async fn invalid_l402_token_and_optional_hash_fail_before_reservation_or_payer() {
    let (invoice, _, _) = matching_invoice();
    for (token, hash) in [
        ("bad:token", None),
        ("token", Some("abcd".into())),
        ("token", Some("00".repeat(32))),
    ] {
        let mut auth_params = BTreeMap::new();
        if let Some(hash) = hash {
            auth_params.insert("payment_hash".into(), hash);
        }
        let challenge = ParsedChallenge::L402(L402WireChallenge {
            auth_params,
            token: token.into(),
            invoice: invoice.original().into(),
        });
        let made = Arc::new(AtomicUsize::new(0));
        let seen = made.clone();
        let path = temp_path("invalid-l402");
        let result = execute_payment_transaction::<NeverPayer, _>(
            &challenge,
            "paygate.test:443",
            "scope",
            &PolicyConfig {
                allowed_hosts: vec!["paygate.test:443".into()],
                allowed_services: vec!["svc".into()],
                max_request_sats: 10,
                max_fee_sats: 5,
            },
            20,
            &DailySpendLedger::new(&path),
            Some("breez"),
            RealPayerFactory::new(true, move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Err(PaymentError::Transport)
            }),
        )
        .await;
        assert_eq!(result.error, Some(TransactionError::Challenge));
        assert_eq!(made.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
    }
}

fn ok_response() -> HttpResponse {
    HttpResponse {
        status: reqwest::StatusCode::OK,
        headers: reqwest::header::HeaderMap::new(),
        body: b"ok".to_vec(),
    }
}

#[tokio::test]
async fn payment_success_persists_then_commits_and_retries_once_with_verified_authorization() {
    let (invoice, hash, preimage) = matching_invoice();
    let (request, challenge) = request_and_402(&invoice, &hash);
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(challenge), Ok(ok_response())])),
        auth: Mutex::new(vec![]),
    };
    let cache = MemoryCache::default();
    let ledger = DailySpendLedger::new(temp_path("success"));
    let pays = Arc::new(AtomicUsize::new(0));
    let raw = paygate::payers::RawPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 1,
        payment_hash: Some(hash),
        preimage_hex: Some(preimage),
    };
    let seen = pays.clone();
    let output = execute_with::<ConfirmedPayer, _, _, _>(
        request,
        &config(),
        &ledger,
        &transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Ok(ConfirmedPayer { raw, pays: seen })),
    )
    .await;
    assert_eq!(output["ok"], true, "{output}");
    assert_eq!(output["paid"], true, "{output}");
    assert_eq!(pays.load(Ordering::SeqCst), 1);
    let auth = transport.auth.lock().unwrap();
    assert_eq!(auth.len(), 2);
    assert!(auth[0].is_none());
    assert!(auth[1].as_deref().unwrap().starts_with("Payment "));
    assert_eq!(ledger.spent_today().unwrap(), invoice.amount_sats());
    assert_eq!(cache.values.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn enabled_l402_selection_uses_verified_token_preimage_format_once() {
    let (invoice, hash, preimage) = matching_invoice();
    let (request, challenge) = l402_request(&invoice);
    let mut cfg = config();
    cfg.protocol.preferred = "L402".into();
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(challenge), Ok(ok_response())])),
        auth: Mutex::new(vec![]),
    };
    let ledger = DailySpendLedger::new(temp_path("l402"));
    let expected = preimage.clone();
    let raw = paygate::payers::RawPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 1,
        payment_hash: Some(hash),
        preimage_hex: Some(preimage),
    };
    let output = execute_with::<ConfirmedPayer, _, _, _>(
        request,
        &cfg,
        &ledger,
        &transport,
        &MemoryCache::default(),
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: true,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| {
            Ok(ConfirmedPayer {
                raw,
                pays: Arc::new(AtomicUsize::new(0)),
            })
        }),
    )
    .await;
    assert_eq!(output["ok"], true, "{output}");
    let auth = transport.auth.lock().unwrap();
    assert_eq!(auth.len(), 2);
    assert_eq!(
        auth[1].as_deref(),
        Some(format!("L402 l402-token:{expected}").as_str())
    );
}

#[tokio::test]
async fn cache_put_failure_retries_in_memory_but_retains_restart_guard() {
    let (invoice, hash, preimage) = matching_invoice();
    let (request, challenge) = request_and_402(&invoice, &hash);
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(challenge), Ok(ok_response())])),
        auth: Mutex::new(vec![]),
    };
    let cache = MemoryCache {
        fail_put: true,
        ..Default::default()
    };
    let ledger = DailySpendLedger::new(temp_path("put-fail"));
    let pays = Arc::new(AtomicUsize::new(0));
    let raw = paygate::payers::RawPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 1,
        payment_hash: Some(hash.clone()),
        preimage_hex: Some(preimage),
    };
    let seen = pays.clone();
    let output = execute_with::<ConfirmedPayer, _, _, _>(
        request.clone(),
        &config(),
        &ledger,
        &transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Ok(ConfirmedPayer { raw, pays: seen })),
    )
    .await;
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(output["paid"], true, "{output}");
    assert_eq!(transport.auth.lock().unwrap().len(), 2);
    let transport2 = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(request_and_402(&invoice, &hash).1)])),
        auth: Mutex::new(vec![]),
    };
    let made = Arc::new(AtomicUsize::new(0));
    let seen = made.clone();
    let second = execute_with::<NeverPayer, _, _, _>(
        request,
        &config(),
        &ledger,
        &transport2,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: true,
            no_cache: true,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(second["paid"], false);
    assert_eq!(second["error"]["code"], "budget_ledger_failure");
    assert_eq!(made.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn classified_commit_and_rollback_warnings_update_public_retention_state() {
    let (invoice, hash, preimage) = matching_invoice();
    let parsed = ValidatedBolt11::parse(invoice.original()).unwrap();
    let challenge = ParsedChallenge::Payment(PaymentWireChallenge {
        auth_params: BTreeMap::new(),
        request: "request".into(),
        invoice: invoice.original().into(),
        amount_sats: parsed.amount_sats(),
        payment_hash: Some(hash.clone()),
        service: Some("svc".into()),
        description: None,
        expires: None,
    });
    let policy = PolicyConfig {
        allowed_hosts: vec!["paygate.test:443".into()],
        allowed_services: vec!["svc".into()],
        max_request_sats: 10,
        max_fee_sats: 5,
    };
    let ledger = DailySpendLedger::new(temp_path("public-commit-warning"));
    let raw = paygate::payers::RawPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 1,
        payment_hash: Some(hash),
        preimage_hex: Some(preimage),
    };
    let mut result = execute_payment_transaction::<ConfirmedPayer, _>(
        &challenge,
        "paygate.test:443",
        "scope",
        &policy,
        20,
        &ledger,
        Some("breez"),
        RealPayerFactory::new(true, move |_| {
            Ok(ConfirmedPayer {
                raw,
                pays: Arc::new(AtomicUsize::new(0)),
            })
        }),
    )
    .await;
    ledger.set_write_fault_for_tests(LedgerWriteFault::AfterRename);
    assert_eq!(result.commit(), Err(TransactionError::Commit));
    assert!(result.paid);
    assert!(!result.reservation_retained);
    assert_eq!(
        DailySpendLedger::new(&ledger.path).spent_today().unwrap(),
        invoice.amount_sats()
    );

    let ledger = DailySpendLedger::new(temp_path("public-rollback-warning"));
    let injected = ledger.clone();
    let result = execute_payment_transaction::<NeverPayer, _>(
        &challenge,
        "paygate.test:443",
        "other-scope",
        &policy,
        20,
        &ledger,
        Some("breez"),
        RealPayerFactory::new(true, move |_| {
            injected.set_write_fault_for_tests(LedgerWriteFault::AfterRename);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(result.error, Some(TransactionError::Rollback));
    assert!(!result.paid);
    assert!(!result.reservation_retained);
    assert_eq!(
        DailySpendLedger::new(&ledger.path)
            .counting_today()
            .unwrap(),
        0
    );
}

fn seeded_credential() -> CachedCredential {
    CachedCredential {
        credential_id: "cached".into(),
        scope: CredentialScope {
            namespace: "default".into(),
            request_key: "ignored-by-test-cache".into(),
            origin_host: Some("paygate.test:443".into()),
            service: Some("svc".into()),
            protocol: "Payment".into(),
            payer_backend: "breez".into(),
            policy_hash: "policy".into(),
        },
        authorization: "Payment cached-secret".into(),
        created_at: 1,
        expires_at: None,
        max_uses: None,
        use_count: 0,
        last_success_at: None,
        last_rejected_at: None,
        payment_hash: None,
        challenge_id: None,
        secret_storage: None,
    }
}

#[tokio::test]
async fn cache_hit_and_rejection_paths_precede_initial_request_and_wallet() {
    let request = HttpRequest {
        method: reqwest::Method::GET,
        url: reqwest::Url::parse("https://paygate.test/resource").unwrap(),
        headers: reqwest::header::HeaderMap::new(),
        body: None,
        phase_timeout: std::time::Duration::from_secs(5),
    };
    let cache = MemoryCache {
        values: Mutex::new(vec![seeded_credential()]),
        ..Default::default()
    };
    let hit_transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(ok_response())])),
        auth: Mutex::new(vec![]),
    };
    let output = execute_with::<NeverPayer, _, _, _>(
        request.clone(),
        &config(),
        &DailySpendLedger::new(temp_path("hit")),
        &hit_transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(output["ok"], true, "{output}");
    assert_eq!(hit_transport.auth.lock().unwrap().len(), 1);
    assert!(hit_transport.auth.lock().unwrap()[0].is_some());

    let cache = MemoryCache {
        values: Mutex::new(vec![seeded_credential()]),
        ..Default::default()
    };
    let reject_transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([
            Ok(HttpResponse {
                status: reqwest::StatusCode::UNAUTHORIZED,
                headers: reqwest::header::HeaderMap::new(),
                body: vec![],
            }),
            Ok(ok_response()),
        ])),
        auth: Mutex::new(vec![]),
    };
    let output = execute_with::<NeverPayer, _, _, _>(
        request,
        &config(),
        &DailySpendLedger::new(temp_path("reject")),
        &reject_transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(output["ok"], true, "{output}");
    assert!(cache.values.lock().unwrap().is_empty());
    let auth = reject_transport.auth.lock().unwrap();
    assert!(auth[0].is_some());
    assert!(auth[1].is_none());
}

#[tokio::test]
async fn cache_read_and_mark_failures_are_phase_specific() {
    let request = HttpRequest {
        method: reqwest::Method::GET,
        url: reqwest::Url::parse("https://paygate.test/resource").unwrap(),
        headers: reqwest::header::HeaderMap::new(),
        body: None,
        phase_timeout: std::time::Duration::from_secs(5),
    };
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::new()),
        auth: Mutex::new(vec![]),
    };
    let cache = MemoryCache {
        fail_get: true,
        ..Default::default()
    };
    let output = execute_with::<NeverPayer, _, _, _>(
        request.clone(),
        &config(),
        &DailySpendLedger::new(temp_path("get-fail")),
        &transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(output["error"]["code"], "credential_state_failure");
    assert!(transport.auth.lock().unwrap().is_empty());
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(ok_response())])),
        auth: Mutex::new(vec![]),
    };
    let cache = MemoryCache {
        values: Mutex::new(vec![seeded_credential()]),
        fail_mark: true,
        ..Default::default()
    };
    let output = execute_with::<NeverPayer, _, _, _>(
        request,
        &config(),
        &DailySpendLedger::new(temp_path("mark-fail")),
        &transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(output["ok"], false);
    assert_eq!(output["response"]["statusCode"], 200);
}

#[tokio::test]
async fn concrete_matching_missing_keyring_secret_fails_before_transport_or_payer() {
    let request = HttpRequest {
        method: reqwest::Method::GET,
        url: reqwest::Url::parse("https://paygate.test/resource").unwrap(),
        headers: reqwest::header::HeaderMap::new(),
        body: None,
        phase_timeout: std::time::Duration::from_secs(5),
    };
    let cfg = config();
    let request_key = build_request_key("GET", request.url.as_str(), None);
    let policy_hash = build_request_policy_hash(&cfg.policy);
    let cache_path = temp_path("strict-cache");
    let state = serde_json::json!({"version":1,"credentials":[{"id":format!("missing-{}",SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()),"scope":{"namespace":"default","requestKey":request_key,"originHost":"paygate.test:443","service":"svc","protocol":"Payment","payerBackend":"breez","policyHash":policy_hash},"authorization":null,"createdAt":1,"expiresAt":null,"maxUses":null,"useCount":0,"lastSuccessAt":null,"lastRejectedAt":null,"paymentHash":null,"challengeId":null,"secretStorage":"keyring"}]});
    std::fs::write(&cache_path, serde_json::to_vec(&state).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let cache = FileCredentialCache::new(&cache_path, Some("default")).unwrap();
    let requested = CredentialScope {
        namespace: "default".into(),
        request_key: build_request_key("GET", request.url.as_str(), None),
        origin_host: Some("paygate.test:443".into()),
        service: None,
        protocol: "Payment".into(),
        payer_backend: "breez".into(),
        policy_hash: build_request_policy_hash(&cfg.policy),
    };
    assert!(
        cache
            .get_scoped_fail_closed(&requested, unix_now_for_test())
            .is_err()
    );
    let mut unrelated = requested.clone();
    unrelated.request_key = "unrelated".into();
    assert!(
        cache
            .get_scoped_fail_closed(&unrelated, unix_now_for_test())
            .unwrap()
            .is_none()
    );
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::new()),
        auth: Mutex::new(vec![]),
    };
    let made = Arc::new(AtomicUsize::new(0));
    let seen = made.clone();
    let output = execute_with::<NeverPayer, _, _, _>(
        request,
        &cfg,
        &DailySpendLedger::new(temp_path("strict-ledger")),
        &transport,
        &cache,
        &RequestOptions {
            no_pay: false,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "single-use".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(output["error"]["code"], "credential_state_failure");
    assert!(transport.auth.lock().unwrap().is_empty());
    assert_eq!(made.load(Ordering::SeqCst), 0);
}

fn unix_now_for_test() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn classified_ledger_outcomes_match_restart_visible_state() {
    let commit_path = temp_path("commit-warning");
    let ledger = DailySpendLedger::new(&commit_path);
    let mut reservation = ledger.reserve(3, 10).unwrap();
    ledger.set_write_fault_for_tests(LedgerWriteFault::AfterRename);
    assert_eq!(
        reservation.commit_classified(),
        LedgerMutationOutcome::AppliedWithDurabilityWarning
    );
    assert_eq!(
        DailySpendLedger::new(&commit_path).spent_today().unwrap(),
        3
    );
    assert_eq!(
        DailySpendLedger::new(&commit_path)
            .counting_today()
            .unwrap(),
        3
    );

    let rollback_path = temp_path("rollback-warning");
    let ledger = DailySpendLedger::new(&rollback_path);
    let mut reservation = ledger.reserve(3, 10).unwrap();
    ledger.set_write_fault_for_tests(LedgerWriteFault::AfterRename);
    assert_eq!(
        reservation.rollback_classified(),
        LedgerMutationOutcome::AppliedWithDurabilityWarning
    );
    assert_eq!(
        DailySpendLedger::new(&rollback_path)
            .counting_today()
            .unwrap(),
        0
    );

    let pre_path = temp_path("pre-rename");
    let ledger = DailySpendLedger::new(&pre_path);
    let mut reservation = ledger.reserve(4, 10).unwrap();
    ledger.set_write_fault_for_tests(LedgerWriteFault::BeforeRename);
    let before = std::fs::read(&pre_path).unwrap();
    assert_eq!(
        reservation.commit_classified(),
        LedgerMutationOutcome::NotApplied(LedgerError::Io)
    );
    assert_eq!(std::fs::read(&pre_path).unwrap(), before);
    assert_eq!(
        DailySpendLedger::new(&pre_path).counting_today().unwrap(),
        4
    );
}

#[tokio::test]
async fn no_pay_runs_full_validation_and_returns_bound_metadata_without_wallet() {
    let (invoice, hash, _) = matching_invoice();
    let (request, challenge) = request_and_402(&invoice, &hash);
    let made = Arc::new(AtomicUsize::new(0));
    let seen = made.clone();
    let transport = ScriptTransport {
        responses: Mutex::new(VecDeque::from([Ok(challenge)])),
        auth: Mutex::new(vec![]),
    };
    let output = execute_with::<NeverPayer, _, _, _>(
        request,
        &config(),
        &DailySpendLedger::new(temp_path("no-pay")),
        &transport,
        &MemoryCache::default(),
        &RequestOptions {
            no_pay: true,
            refresh_credential: false,
            no_cache: false,
            cache_policy: "challenge-defined".into(),
            namespace: "default".into(),
            verbose: false,
            trace_json: false,
        },
        RealPayerFactory::new(true, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(output["wouldPay"], true, "{output}");
    assert_eq!(output["amountSats"], invoice.amount_sats());
    assert_eq!(output["service"], "svc");
    assert_eq!(made.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn incapable_backend_is_policy_denied_consistently_in_no_pay_and_paid_modes() {
    let (invoice, hash, _) = matching_invoice();
    let (request, challenge) = request_and_402(&invoice, &hash);
    let made = Arc::new(AtomicUsize::new(0));

    for no_pay in [true, false] {
        let transport = ScriptTransport {
            responses: Mutex::new(VecDeque::from([Ok(challenge.clone())])),
            auth: Mutex::new(vec![]),
        };
        let seen = made.clone();
        let output = execute_with::<NeverPayer, _, _, _>(
            request.clone(),
            &config(),
            &DailySpendLedger::new(temp_path(if no_pay {
                "incapable-no-pay"
            } else {
                "incapable-paid"
            })),
            &transport,
            &MemoryCache::default(),
            &RequestOptions {
                no_pay,
                refresh_credential: false,
                no_cache: false,
                cache_policy: "challenge-defined".into(),
                namespace: "default".into(),
                verbose: false,
                trace_json: false,
            },
            RealPayerFactory::new(false, move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Err(PaymentError::Transport)
            }),
        )
        .await;

        assert_eq!(output["ok"], false, "no_pay={no_pay}: {output}");
        assert_eq!(output["paid"], false, "no_pay={no_pay}: {output}");
        assert_eq!(
            output["error"]["code"], "policy_denied",
            "no_pay={no_pay}: {output}"
        );
        assert_ne!(output["wouldPay"], true, "no_pay={no_pay}: {output}");
    }

    assert_eq!(made.load(Ordering::SeqCst), 0);
}

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("paygate-{label}-{nonce}.json"))
}

#[test]
fn repeated_challenges_follow_preference_and_l402_opt_in() {
    let values = vec![
        "L402 token=token, invoice=invoice".to_owned(),
        "Payment request=eyJhbW91bnRTYXRzIjoxLCJpbnZvaWNlIjoiaW52b2ljZSJ9".to_owned(),
    ];
    let payment = parse_www_authenticate(&values, ProtocolPreference::Payment, true, 0).unwrap();
    assert_eq!(payment.protocol(), ChallengeProtocol::Payment);
    let l402 = parse_www_authenticate(&values, ProtocolPreference::L402, true, 0).unwrap();
    assert_eq!(l402.protocol(), ChallengeProtocol::L402);
    let payment_only = parse_www_authenticate(&values[..1], ProtocolPreference::Payment, false, 0);
    assert!(payment_only.is_err());
}

#[test]
fn reference_payment_rfc3339_expiry_remains_preferred_over_l402() {
    let request = paygate::serialization::base64_url_nopad(
        serde_json::to_string(&serde_json::json!({
            "amount": "10",
            "currency": "BTC",
            "methodDetails": {
                "invoice": "lnbc10n1reference",
                "network": "mainnet",
                "paymentHash": "ab".repeat(32),
            },
        }))
        .unwrap()
        .as_bytes(),
    );
    let values = vec![
        format!(
            "Payment id=pay_reference, request=\"{request}\", \
             expires=\"2026-06-12T03:37:12.085906Z\""
        ),
        "L402 token=l402-token, invoice=lnbc10n1fallback".to_owned(),
    ];

    let parsed =
        parse_www_authenticate(&values, ProtocolPreference::Payment, true, 1_700_000_000).unwrap();

    let ParsedChallenge::Payment(payment) = parsed else {
        panic!("valid preferred Payment challenge fell back to L402");
    };
    assert_eq!(payment.amount_sats, 10);
    assert_eq!(payment.expires, Some(1_781_235_432));

    assert_eq!(
        parse_www_authenticate(
            &values[..1],
            ProtocolPreference::Payment,
            true,
            1_781_235_433,
        ),
        Err(ChallengeError::Expired),
    );
}

#[tokio::test]
async fn policy_precedes_factory_and_factory_failure_rolls_back_daily_reservation() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let challenge = ParsedChallenge::Payment(PaymentWireChallenge {
        auth_params: BTreeMap::new(),
        request: "request".into(),
        invoice: INVOICE.into(),
        amount_sats: invoice.amount_sats(),
        payment_hash: Some(hex::encode(invoice.payment_hash())),
        service: Some("svc".into()),
        description: None,
        expires: None,
    });
    let policy = PolicyConfig {
        allowed_hosts: vec!["paygate.test:443".into()],
        allowed_services: vec!["svc".into()],
        max_request_sats: 3_000_000,
        max_fee_sats: 5,
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ledger = DailySpendLedger::new(
        std::env::temp_dir().join(format!("paygate-request-flow-{nonce}.json")),
    );
    let made = Arc::new(AtomicUsize::new(0));
    let seen = made.clone();
    let denied = execute_payment_transaction::<NeverPayer, _>(
        &challenge,
        "denied.test:443",
        "scope",
        &policy,
        4_000_000,
        &ledger,
        Some("test"),
        RealPayerFactory::new(true, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(denied.error, Some(TransactionError::Policy));
    assert_eq!(made.load(Ordering::SeqCst), 0);

    let made = Arc::new(AtomicUsize::new(0));
    let seen = made.clone();
    let failed = execute_payment_transaction::<NeverPayer, _>(
        &challenge,
        "paygate.test:443",
        "scope",
        &policy,
        4_000_000,
        &ledger,
        Some("test"),
        RealPayerFactory::new(true, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(PaymentError::Transport)
        }),
    )
    .await;
    assert_eq!(failed.error, Some(TransactionError::Payer));
    assert!(!failed.reservation_retained);
    assert_eq!(made.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.spent_today().unwrap(), 0);
}

#[tokio::test]
async fn reservation_budget_and_io_failures_remain_distinct() {
    let (invoice, hash, _) = matching_invoice();
    let challenge = ParsedChallenge::Payment(PaymentWireChallenge {
        auth_params: BTreeMap::new(),
        request: "request".into(),
        invoice: invoice.original().into(),
        amount_sats: invoice.amount_sats(),
        payment_hash: Some(hash),
        service: Some("svc".into()),
        description: None,
        expires: None,
    });
    let policy = PolicyConfig {
        allowed_hosts: vec!["paygate.test:443".into()],
        allowed_services: vec!["svc".into()],
        max_request_sats: 10,
        max_fee_sats: 5,
    };
    let budget = execute_payment_transaction::<NeverPayer, _>(
        &challenge,
        "paygate.test:443",
        "budget",
        &policy,
        0,
        &DailySpendLedger::new(temp_path("budget")),
        Some("breez"),
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(budget.error, Some(TransactionError::ReservationBudget));
    let path = temp_path("ledger-io");
    std::fs::create_dir_all(&path).unwrap();
    let io = execute_payment_transaction::<NeverPayer, _>(
        &challenge,
        "paygate.test:443",
        "io",
        &policy,
        20,
        &DailySpendLedger::new(path),
        Some("breez"),
        RealPayerFactory::new(true, move |_| Err(PaymentError::Transport)),
    )
    .await;
    assert_eq!(io.error, Some(TransactionError::Reservation));
}
