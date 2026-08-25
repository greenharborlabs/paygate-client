use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::challenge::{ChallengeProtocol, ParsedChallenge, ProtocolPreference};
use crate::cli::{RequestArgs, parse_headers};
use crate::commands::{CommandResult, config_error};
use crate::config::{PaygateConfig, expand_path, load_config};
use crate::http::{HttpError, HttpRequest, HttpResponse};
use crate::orchestrator::{
    RealPayerFactory, TransactionError, execute_payment_transaction, prepare_challenge,
};
use crate::payers::base::{
    CancellationSemantics, PaymentAttemptOutcome, PaymentError, RealPayer, ValidatedBolt11,
};
use crate::policy::PolicyConfig;
use crate::state::cache::{
    CachedCredential, CredentialScope, FileCredentialCache, build_credential_id, build_request_key,
};
use crate::state::ledger::DailySpendLedger;

#[async_trait]
pub trait RequestTransport: Send + Sync {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestCacheError;

pub trait RequestCache: Send + Sync {
    /// Return a matching bearer credential only after durably consuming one
    /// use. The claim must remain consumed when transport outcome is unknown.
    fn claim_scoped(
        &self,
        scope: &CredentialScope,
        now: i64,
    ) -> Result<Option<CachedCredential>, RequestCacheError>;
    fn put(&self, credential: CachedCredential) -> Result<(), RequestCacheError>;
    fn mark_success(&self, id: &str, now: i64) -> Result<(), RequestCacheError>;
    fn mark_rejected(&self, id: &str, now: i64) -> Result<(), RequestCacheError>;
    fn delete(&self, id: &str) -> Result<(), RequestCacheError>;
}

pub struct ReqwestTransport {
    client: reqwest::Client,
}
impl ReqwestTransport {
    fn new() -> Result<Self, HttpError> {
        Ok(Self {
            client: crate::http::client()?,
        })
    }
}
#[async_trait]
impl RequestTransport for ReqwestTransport {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        crate::http::send(&self.client, request).await
    }
}

pub struct NullRequestCache;
impl RequestCache for NullRequestCache {
    fn claim_scoped(
        &self,
        _: &CredentialScope,
        _: i64,
    ) -> Result<Option<CachedCredential>, RequestCacheError> {
        Ok(None)
    }
    fn put(&self, _: CachedCredential) -> Result<(), RequestCacheError> {
        Ok(())
    }
    fn mark_success(&self, _: &str, _: i64) -> Result<(), RequestCacheError> {
        Ok(())
    }
    fn mark_rejected(&self, _: &str, _: i64) -> Result<(), RequestCacheError> {
        Ok(())
    }
    fn delete(&self, _: &str) -> Result<(), RequestCacheError> {
        Ok(())
    }
}

impl RequestCache for FileCredentialCache {
    fn claim_scoped(
        &self,
        requested: &CredentialScope,
        now: i64,
    ) -> Result<Option<CachedCredential>, RequestCacheError> {
        self.claim_scoped_fail_closed(requested, now)
            .map_err(|_| RequestCacheError)
    }
    fn put(&self, credential: CachedCredential) -> Result<(), RequestCacheError> {
        self.put(credential).map_err(|_| RequestCacheError)
    }
    fn mark_success(&self, id: &str, now: i64) -> Result<(), RequestCacheError> {
        self.mark_success(id, now).map_err(|_| RequestCacheError)
    }
    fn mark_rejected(&self, id: &str, now: i64) -> Result<(), RequestCacheError> {
        self.mark_rejected(id, now).map_err(|_| RequestCacheError)
    }
    fn delete(&self, id: &str) -> Result<(), RequestCacheError> {
        self.delete(id).map_err(|_| RequestCacheError)
    }
}

#[derive(Clone, Debug)]
pub struct RequestOptions {
    pub no_pay: bool,
    pub refresh_credential: bool,
    pub no_cache: bool,
    pub cache_policy: String,
    pub namespace: String,
    pub verbose: bool,
    pub trace_json: bool,
}

pub async fn execute_with<P, F, T, C>(
    request: HttpRequest,
    config: &PaygateConfig,
    ledger: &DailySpendLedger,
    transport: &T,
    cache: &C,
    options: &RequestOptions,
    factory: RealPayerFactory<F>,
) -> Value
where
    P: RealPayer,
    F: FnOnce(crate::policy::PolicyApproval) -> Result<P, PaymentError>,
    T: RequestTransport,
    C: RequestCache,
{
    let now = unix_now();
    let request_key = build_request_key(
        request.method.as_str(),
        request.url.as_str(),
        request.body.as_deref(),
    );
    let origin = origin_host(&request.url);
    let policy_hash = build_request_policy_hash(&config.policy);
    let preliminary_scope = CredentialScope {
        namespace: options.namespace.clone(),
        request_key: request_key.clone(),
        origin_host: origin.clone(),
        service: None,
        protocol: config.protocol.preferred.clone(),
        payer_backend: config.payer.backend.clone(),
        policy_hash: policy_hash.clone(),
    };
    emit_trace(
        options,
        "request.start",
        json!({"method":request.method.as_str(),"host":origin}),
    );

    if !options.no_cache && !options.refresh_credential && !options.no_pay {
        let cached = match cache.claim_scoped(&preliminary_scope, now) {
            Ok(value) => value,
            Err(RequestCacheError) => {
                return failure(
                    false,
                    "credential_state_failure",
                    "credential cache lookup failed",
                    None,
                );
            }
        };
        emit_trace(
            options,
            "cache.lookup",
            json!({"hit":cached.is_some(),"scope":request_key}),
        );
        if let Some(credential) = cached {
            let cached_request = with_authorization(&request, &credential.authorization);
            let response = match transport.send(&cached_request).await {
                Ok(value) => value,
                Err(error) => return http_failure(false, "cached", error),
            };
            if response.status.is_success() {
                let serialized = crate::http::serialize_response(&response).ok();
                if cache.mark_success(&credential.credential_id, now).is_err() {
                    return failure(
                        false,
                        "credential_state_failure",
                        "credential success state could not be saved",
                        serialized,
                    );
                }
                emit_trace(
                    options,
                    "cache.accepted",
                    json!({"statusCode":response.status.as_u16()}),
                );
                return json!({"ok":true,"paid":false,"credentialCache":{"hit":true,"credentialId":credential.credential_id,"expiresAt":credential.expires_at},"response":serialized});
            }
            if matches!(response.status.as_u16(), 401 | 402) {
                if cache.mark_rejected(&credential.credential_id, now).is_err()
                    || cache.delete(&credential.credential_id).is_err()
                {
                    return failure(
                        false,
                        "credential_state_failure",
                        "rejected credential could not be evicted",
                        crate::http::serialize_response(&response).ok(),
                    );
                }
                emit_trace(
                    options,
                    "cache.rejected",
                    json!({"statusCode":response.status.as_u16()}),
                );
            } else {
                return failure(
                    false,
                    "cached_credential_rejected",
                    "cached credential was rejected",
                    crate::http::serialize_response(&response).ok(),
                );
            }
        }
    }

    let initial = match transport.send(&request).await {
        Ok(value) => value,
        Err(error) => return http_failure(false, "initial", error),
    };
    if initial.status != reqwest::StatusCode::PAYMENT_REQUIRED {
        return match crate::http::serialize_response(&initial) {
            Ok(response) => json!({"ok":true,"paid":false,"response":response}),
            Err(error) => http_failure(false, "initial", error),
        };
    }
    let preference = if config.protocol.preferred == "L402" {
        ProtocolPreference::L402
    } else {
        ProtocolPreference::Payment
    };
    let challenge = match crate::challenge::parse_www_authenticate(
        &crate::http::www_authenticate_values(&initial.headers),
        preference,
        config.protocol.allow_l402,
        now,
    ) {
        Ok(value) => value,
        Err(_) => {
            return failure(
                false,
                "unsupported_402_challenge",
                "response did not include a supported payment challenge",
                None,
            );
        }
    };
    let host = match origin.as_deref() {
        Some(value) => value,
        None => return failure(false, "invalid_request", "request origin is invalid", None),
    };
    let local_policy = rust_policy(config);
    let prepared = match prepare_challenge(
        &challenge,
        host,
        &request_key,
        &local_policy,
        factory.supports_fee_limit(),
        Some(&config.payer.backend),
    ) {
        Ok(value) => value,
        Err(TransactionError::Policy) => {
            return failure(
                false,
                "policy_denied",
                "payment policy rejected request",
                None,
            );
        }
        Err(_) => {
            return failure(
                false,
                "unsupported_402_challenge",
                "payment challenge validation failed",
                None,
            );
        }
    };
    emit_trace(
        options,
        "challenge.received",
        json!({"protocol":protocol_name(&challenge),"amountSats":prepared.approval.challenge().amount_sats(),"service":prepared.approval.challenge().service()}),
    );
    emit_trace(
        options,
        "policy.approved",
        json!({"maxFeeSats":prepared.approval.max_fee_sats(),"amountSats":prepared.approval.challenge().amount_sats()}),
    );
    if options.no_pay {
        let counting = match ledger.counting_today() {
            Ok(value) => value,
            Err(_) => {
                return failure(
                    false,
                    "state_unavailable",
                    "payment state is unavailable",
                    None,
                );
            }
        };
        if counting
            .checked_add(prepared.approval.challenge().amount_sats())
            .is_none_or(|total| total > config.policy.daily_budget_sats)
        {
            return failure(
                false,
                "policy_denied",
                "daily payment budget would be exceeded",
                None,
            );
        }
        return no_pay_envelope(config, &prepared);
    }

    let mut payment = execute_payment_transaction::<P, F>(
        &challenge,
        host,
        &request_key,
        &local_policy,
        config.policy.daily_budget_sats,
        ledger,
        Some(&config.payer.backend),
        factory,
    )
    .await;
    if !payment.paid {
        let (code, message) = match payment.error {
            Some(TransactionError::ReservationBudget) => {
                ("policy_denied", "daily payment budget is unavailable")
            }
            Some(TransactionError::ReservationDuplicate) => (
                "budget_ledger_failure",
                "payment challenge already has retained counting state",
            ),
            Some(TransactionError::Reservation) => (
                "budget_ledger_failure",
                "payment reservation state is unavailable",
            ),
            Some(TransactionError::SubmissionUnknown) => (
                "payment_submission_unknown",
                "payment submission outcome is unknown",
            ),
            Some(TransactionError::Rollback) => {
                ("state_unavailable", "payment reservation rollback failed")
            }
            Some(TransactionError::Proof) => (
                "preimage_verification_failed",
                "payment proof verification failed",
            ),
            _ => ("payer_failure", "payer operation failed"),
        };
        return failure(false, code, message, None);
    }
    let authorization = match payment.authorization.as_deref() {
        Some(value) => value.to_owned(),
        None => {
            return paid_failure(
                "credential_failure",
                "confirmed authorization could not be rendered",
                None,
                &payment,
                &challenge,
                config,
            );
        }
    };
    emit_trace(
        options,
        "payment.succeeded",
        json!({"amountSats":prepared.approval.challenge().amount_sats(),"feeSats":payment.fee_sats,"paymentHash":payment.payment_hash}),
    );
    let actual_scope = credential_scope(&preliminary_scope, &challenge);
    let cached = if options.no_cache {
        None
    } else {
        cache_record(
            &challenge,
            actual_scope,
            authorization.clone(),
            payment.payment_hash.clone(),
            &options.cache_policy,
            now,
        )
        .map(|mut credential| {
            // The authenticated retry must never leave the process before its
            // one use is durable. Transport ambiguity therefore leaves this
            // credential consumed across restarts.
            credential.use_count = 1;
            credential
        })
    };
    let mut state_error = None;
    if let Some(record) = cached.clone() {
        if cache.put(record).is_err() {
            return paid_failure(
                "credential_state_failure",
                "confirmed credential could not be saved",
                None,
                &payment,
                &challenge,
                config,
            );
        } else if payment.commit().is_err() {
            state_error = Some((
                "state_unavailable",
                "confirmed payment state could not be committed",
            ));
        }
        if state_error.is_none() {
            emit_trace(
                options,
                "credential.cached",
                json!({"scope":request_key,"expires":cached.as_ref().and_then(|value|value.expires_at)}),
            );
        }
    } else if payment.commit().is_err() {
        state_error = Some((
            "state_unavailable",
            "confirmed payment state could not be committed",
        ));
    }

    // Redirects are surfaced by the transport before any Location can alter the
    // immutable request URL, so this assertion protects the authorization seam.
    let retry_request = with_authorization(&request, &authorization);
    if !crate::http::same_origin(&request.url, &retry_request.url) {
        return failure(
            true,
            "retry_origin_mismatch",
            "authenticated retry origin changed",
            None,
        );
    }
    let retry = match transport.send(&retry_request).await {
        Ok(value) => value,
        Err(error) => {
            return merge_paid_error(
                payment,
                state_error,
                http_failure(true, "retry", error),
                None,
            );
        }
    };
    let response = crate::http::serialize_response(&retry).ok();
    if let Some(record) = &cached {
        if retry.status.is_success() {
            if cache.mark_success(&record.credential_id, now).is_err() && state_error.is_none() {
                state_error = Some((
                    "credential_state_failure",
                    "credential success state could not be saved",
                ));
            }
        } else if matches!(retry.status.as_u16(), 401 | 402)
            && (cache.mark_rejected(&record.credential_id, now).is_err()
                || cache.delete(&record.credential_id).is_err())
            && state_error.is_none()
        {
            state_error = Some((
                "credential_state_failure",
                "rejected credential could not be evicted",
            ));
        }
    }
    let retry_error = if retry.status.is_success() {
        None
    } else {
        Some(("paid_retry_rejected", "paid retry was rejected"))
    };
    let condition_error = if payment.error == Some(TransactionError::PostSubmit) {
        Some((
            "payer_post_submit_failure",
            "confirmed payment completed with safety conditions",
        ))
    } else {
        None
    };
    let error = state_error.or(condition_error).or(retry_error);
    if retry.status.is_success() {
        emit_trace(
            options,
            "retry.succeeded",
            json!({"statusCode":retry.status.as_u16()}),
        );
    }
    match error {
        Some((code, message)) => {
            paid_failure(code, message, response, &payment, &challenge, config)
        }
        None => {
            json!({"ok":true,"paid":true,"protocol":protocol_name(&challenge),"payerBackend":config.payer.backend,"amountSats":prepared.approval.challenge().amount_sats(),"feeSats":payment.fee_sats,"paymentHash":payment.payment_hash,"response":response})
        }
    }
}

fn merge_paid_error(
    _payment: crate::orchestrator::PaymentTransactionResult,
    state: Option<(&'static str, &'static str)>,
    fallback: Value,
    response: Option<Value>,
) -> Value {
    match state {
        Some((code, message)) => failure(true, code, message, response),
        None => fallback,
    }
}

fn paid_failure(
    code: &str,
    message: &str,
    response: Option<Value>,
    payment: &crate::orchestrator::PaymentTransactionResult,
    challenge: &ParsedChallenge,
    config: &PaygateConfig,
) -> Value {
    json!({"ok":false,"paid":true,"protocol":protocol_name(challenge),"payerBackend":config.payer.backend,"feeSats":payment.fee_sats,"paymentHash":payment.payment_hash,"response":response,"error":{"code":code,"message":message}})
}

fn no_pay_envelope(
    config: &PaygateConfig,
    prepared: &crate::orchestrator::PreparedChallenge,
) -> Value {
    let challenge = &prepared.parsed;
    let (service, id, expires, metadata) = match challenge {
        ParsedChallenge::Payment(value) => {
            let mut metadata = crate::serialization::decode_base64_url_nopad(&value.request)
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .unwrap_or_else(|| json!({}));
            crate::redaction::redact_json(&mut metadata);
            (
                value.service.clone(),
                value.auth_params.get("id").cloned(),
                value.expires,
                metadata,
            )
        }
        ParsedChallenge::L402(_) => (None, None, None, json!({"invoice":"[REDACTED_SECRET]"})),
    };
    json!({"ok":true,"paid":false,"wouldPay":true,"payerBackend":config.payer.backend,"protocol":protocol_name(challenge),"amountSats":prepared.approval.challenge().amount_sats(),"maxFeeSats":prepared.approval.max_fee_sats(),"service":service,"paymentHash":hex::encode(prepared.approval.challenge().payment_hash()),"challenge":{"id":id,"expiresAt":expires,"metadata":metadata}})
}

fn cache_record(
    challenge: &ParsedChallenge,
    scope: CredentialScope,
    authorization: String,
    payment_hash: Option<String>,
    policy: &str,
    now: i64,
) -> Option<CachedCredential> {
    let expires = match challenge {
        ParsedChallenge::Payment(value) => value.expires,
        ParsedChallenge::L402(_) => None,
    };
    let max_uses = match policy.to_ascii_lowercase().as_str() {
        "single-use" | "max-requests" => Some(1),
        "challenge-defined" | "until-expiry" if expires.is_none() => return None,
        _ if expires.is_none() => return None,
        _ => None,
    };
    let challenge_id = match challenge {
        ParsedChallenge::Payment(value) => value.auth_params.get("id").cloned(),
        _ => None,
    };
    Some(CachedCredential {
        credential_id: build_credential_id(&scope, &authorization),
        scope,
        authorization,
        created_at: now,
        expires_at: expires,
        max_uses,
        use_count: 0,
        last_success_at: None,
        last_rejected_at: None,
        payment_hash,
        challenge_id,
        secret_storage: None,
    })
}

fn credential_scope(base: &CredentialScope, challenge: &ParsedChallenge) -> CredentialScope {
    let mut value = base.clone();
    value.protocol = protocol_name(challenge).into();
    value.service = match challenge {
        ParsedChallenge::Payment(value) => value.service.clone(),
        _ => None,
    };
    value
}

fn with_authorization(request: &HttpRequest, authorization: &str) -> HttpRequest {
    let mut request = request.clone();
    request.headers.remove(reqwest::header::AUTHORIZATION);
    if let Ok(value) = reqwest::header::HeaderValue::from_str(authorization) {
        request
            .headers
            .insert(reqwest::header::AUTHORIZATION, value);
    }
    request
}

fn protocol_name(challenge: &ParsedChallenge) -> &'static str {
    match challenge.protocol() {
        ChallengeProtocol::Payment => "Payment",
        ChallengeProtocol::L402 => "L402",
    }
}
fn rust_policy(config: &PaygateConfig) -> PolicyConfig {
    PolicyConfig {
        allowed_hosts: config.policy.allowed_hosts.clone(),
        allowed_services: config.policy.allowed_services.clone(),
        max_request_sats: config.policy.max_request_sats,
        max_fee_sats: config.policy.max_fee_sats,
    }
}
pub fn build_request_policy_hash(policy: &crate::config::PolicyConfig) -> String {
    let py_tuple = |values: &[String]| {
        let members = values
            .iter()
            .map(|value| format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect::<Vec<_>>();
        match members.as_slice() {
            [] => "()".into(),
            [only] => format!("({only},)"),
            _ => format!("({})", members.join(", ")),
        }
    };
    let repr = format!(
        "PolicyConfig(max_request_sats={}, max_fee_sats={}, daily_budget_sats={}, allowed_hosts={}, allowed_services={})",
        policy.max_request_sats,
        policy.max_fee_sats,
        policy.daily_budget_sats,
        py_tuple(&policy.allowed_hosts),
        py_tuple(&policy.allowed_services)
    );
    hex::encode(Sha256::digest(
        serde_json::to_string(&repr).unwrap_or_default(),
    ))
}
fn origin_host(url: &reqwest::Url) -> Option<String> {
    Some(format!(
        "{}:{}",
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default()?
    ))
}
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn failure(paid: bool, code: &str, message: &str, response: Option<Value>) -> Value {
    let mut value = json!({"ok":false,"paid":paid,"error":{"code":code,"message":message}});
    if let Some(response) = response {
        value["response"] = response;
    }
    value
}
fn http_failure(paid: bool, phase: &str, error: HttpError) -> Value {
    let (code, message) = match error {
        HttpError::Timeout => ("network_timeout", "target request timed out"),
        HttpError::ResponseTooLarge => ("response_too_large", "target response is too large"),
        HttpError::Redirect => ("redirect_rejected", "target redirect was not followed"),
        HttpError::InvalidRequest => ("invalid_request", "request input is invalid"),
        HttpError::Transport => ("network_failure", "target request failed"),
    };
    let _ = phase;
    failure(paid, code, message, None)
}

fn emit_trace(options: &RequestOptions, event: &str, fields: Value) {
    if !options.verbose && !options.trace_json {
        return;
    }
    let fields = fields.as_object().cloned().unwrap_or_default();
    let event = crate::trace::TraceEvent::new(event, fields);
    if options.verbose {
        eprintln!("{}", event.verbose_line());
    }
    if options.trace_json {
        eprintln!("{}", event.json_line());
    }
}

struct UnsupportedRequestPayer;
#[async_trait]
impl RealPayer for UnsupportedRequestPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        Err(PaymentError::Unsupported)
    }
    async fn pay(
        &self,
        _: &ValidatedBolt11,
        _: u64,
        _: CancellationSemantics,
    ) -> PaymentAttemptOutcome {
        PaymentAttemptOutcome::NotSubmitted(PaymentError::Unsupported)
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

pub async fn run(args: RequestArgs) -> CommandResult {
    parse_headers(&args.headers).map_err(|_| ("invalid_request", "invalid request input"))?;
    if args.method.trim().is_empty()
        || !args.url.starts_with("http://") && !args.url.starts_with("https://")
        || args.timeout.is_some_and(|v| !v.is_finite() || v <= 0.0)
    {
        return Err(("invalid_request", "invalid request input"));
    }
    let namespace = crate::state::normalize_namespace(Some(&args.profile))
        .map_err(|_| ("invalid_request", "invalid profile"))?;
    let config = load_config(expand_path(&args.config)).map_err(config_error)?;
    let cache_path = args.cache_path.clone().map(expand_path).unwrap_or(
        FileCredentialCache::default_path(Some(&namespace))
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?,
    );
    let cache = FileCredentialCache::new(cache_path, Some(&namespace))
        .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    let ledger_path = args.ledger_path.clone().map(expand_path).unwrap_or(
        DailySpendLedger::default_path(Some(&namespace))
            .map_err(|_| ("state_unavailable", "spend state is unavailable"))?,
    );
    let ledger = DailySpendLedger::new(ledger_path);
    let url =
        reqwest::Url::parse(&args.url).map_err(|_| ("invalid_request", "invalid request input"))?;
    let method = reqwest::Method::from_bytes(args.method.trim().as_bytes())
        .map_err(|_| ("invalid_request", "invalid request input"))?;
    let raw_headers = args
        .headers
        .iter()
        .map(|header| {
            let (name, value) = header.split_once(':').expect("validated");
            (name.trim().to_owned(), value.trim_start().to_owned())
        })
        .collect::<Vec<_>>();
    let headers = crate::http::parse_headers(&raw_headers)
        .map_err(|_| ("invalid_request", "invalid request input"))?;
    let request = HttpRequest {
        method,
        url,
        headers,
        body: args.body.map(String::into_bytes),
        phase_timeout: Duration::from_secs_f64(args.timeout.unwrap_or(5.0)),
    };
    let options = RequestOptions {
        no_pay: args.no_pay,
        refresh_credential: args.refresh_credential,
        no_cache: args.no_cache,
        cache_policy: args.cache_policy,
        namespace,
        verbose: args.verbose,
        trace_json: args.trace_json,
    };
    let transport =
        ReqwestTransport::new().map_err(|_| ("network_failure", "target request failed"))?;
    let output = if config.payer.backend == "breez" {
        let breez = config
            .breez
            .clone()
            .ok_or(("config_invalid", "configuration is invalid or unavailable"))?;
        execute_with::<
            crate::payers::breez::BreezSparkPayer<crate::payers::breez::ProductionBreezSparkSdk>,
            _,
            _,
            _,
        >(
            request,
            &config,
            &ledger,
            &transport,
            &cache,
            &options,
            RealPayerFactory::new(true, move |_| {
                crate::payers::breez::BreezSparkPayer::production(breez)
            }),
        )
        .await
    } else {
        execute_with::<UnsupportedRequestPayer, _, _, _>(
            request,
            &config,
            &ledger,
            &transport,
            &cache,
            &options,
            RealPayerFactory::new(false, move |_| Err(PaymentError::Unsupported)),
        )
        .await
    };
    emit_trace(
        &options,
        "request.complete",
        json!({"ok":output.get("ok"),"paid":output.get("paid")}),
    );
    Ok(output)
}
