//! Breez Spark adapter behind a narrow SDK seam.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use breez_sdk_spark::{
    BreezSdk, ConnectRequest, GetInfoRequest, Network, PaymentDetails, PaymentRequest,
    PaymentStatus, PrepareSendPaymentRequest, PrepareSendPaymentResponse, Seed, SendPaymentMethod,
    SendPaymentOptions, SendPaymentRequest, connect, default_config,
};
use tokio::sync::OnceCell;

use super::base::{
    CancellationSemantics, PaymentAttemptOutcome, PaymentError, PostSubmitCondition,
    RawPaymentResult, RealPayer, SubmissionOutcome, ValidatedBolt11, verify_payment_result,
};
use crate::config::{BreezConfig, BreezNetwork, EnvRef, load_config_env};

/// Exclusive marker for a wallet storage directory.  It is deliberately an
/// atomic `create_new` claim, so two payer instances cannot share SQLite state.
#[derive(Debug)]
pub struct BreezStorage {
    marker: PathBuf,
    claim: Mutex<Option<File>>,
    released: AtomicBool,
}

impl BreezStorage {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, PaymentError> {
        let path = path.as_ref();
        std::fs::create_dir_all(path).map_err(|_| PaymentError::Transport)?;
        let marker = path.join(".paygate-breez-owner.lock");
        let claim = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
            .map_err(|_| PaymentError::InvalidInput)?;
        Ok(Self {
            marker,
            claim: Mutex::new(Some(claim)),
            released: AtomicBool::new(false),
        })
    }

    /// Explicitly relinquish this instance's exclusive claim.  Only lifecycle
    /// code may call this: dropping a claim is not evidence that the SDK was
    /// disconnected successfully.
    fn release(&self) -> Result<(), PaymentError> {
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }
        self.claim
            .lock()
            .expect("Breez storage claim mutex poisoned")
            .take();
        std::fs::remove_file(&self.marker).map_err(|_| PaymentError::Transport)?;
        self.released.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for BreezStorage {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub struct PreparedPayment<T> {
    pub fee_sats: u64,
    opaque: T,
}

impl<T> PreparedPayment<T> {
    pub fn new(fee_sats: u64, opaque: T) -> Self {
        Self { fee_sats, opaque }
    }

    fn into_opaque(self) -> T {
        self.opaque
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparkPaymentResult {
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub payment_hash: Option<String>,
    pub preimage_hex: Option<String>,
    pub outcome: SubmissionOutcome,
}

#[async_trait]
pub trait BreezSparkSdk: Send + Sync {
    type Prepared: Send;

    async fn check_ready(&self) -> Result<(), PaymentError>;
    /// This seam intentionally accepts BOLT11 text only; no generic payment
    /// request or LNURL route is exposed by the production adapter.
    async fn prepare_bolt11(
        &self,
        bolt11: &str,
    ) -> Result<PreparedPayment<Self::Prepared>, PaymentError>;
    async fn send_prepared(
        &self,
        prepared: Self::Prepared,
    ) -> Result<SparkPaymentResult, PaymentError>;
    async fn disconnect(&self) -> Result<(), PaymentError>;
}

pub struct BreezSparkPayer<S> {
    sdk: S,
    storage: BreezStorage,
    connected: AtomicBool,
}

impl<S> BreezSparkPayer<S> {
    pub fn new(sdk: S, storage: BreezStorage) -> Self {
        Self {
            sdk,
            storage,
            connected: AtomicBool::new(false),
        }
    }
    pub fn storage(path: impl AsRef<Path>) -> Result<BreezStorage, PaymentError> {
        BreezStorage::acquire(path)
    }
}

#[async_trait]
impl<S: BreezSparkSdk> RealPayer for BreezSparkPayer<S> {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        // A failed readiness check can still have allocated SDK resources, so
        // mark it as connected before the call and let the lifecycle cleanup
        // path disconnect it.
        self.connected.store(true, Ordering::Release);
        self.sdk.check_ready().await
    }

    async fn pay(
        &self,
        invoice: &ValidatedBolt11,
        max_fee_sats: u64,
        cancellation: CancellationSemantics,
    ) -> PaymentAttemptOutcome {
        if cancellation == CancellationSemantics::AfterSubmissionUnknown {
            return PaymentAttemptOutcome::SubmittedUnknown(PaymentError::AmbiguousSubmission);
        }
        let prepared = match self.sdk.prepare_bolt11(invoice.original()).await {
            Ok(prepared) => prepared,
            Err(error) => return PaymentAttemptOutcome::NotSubmitted(error),
        };
        if prepared.fee_sats > max_fee_sats {
            return PaymentAttemptOutcome::NotSubmitted(PaymentError::FeeExceeded);
        }
        let sent = match self.sdk.send_prepared(prepared.into_opaque()).await {
            Ok(sent) => sent,
            Err(error) => return PaymentAttemptOutcome::SubmittedUnknown(error),
        };
        match sent.outcome {
            SubmissionOutcome::FailedFinal => {
                PaymentAttemptOutcome::SubmittedFailedFinal(PaymentError::Transport)
            }
            SubmissionOutcome::SubmittedUnknown | SubmissionOutcome::NotSubmitted => {
                PaymentAttemptOutcome::SubmittedUnknown(PaymentError::AmbiguousSubmission)
            }
            SubmissionOutcome::Succeeded => {
                let raw = RawPaymentResult {
                    amount_sats: sent.amount_sats,
                    fee_sats: sent.fee_sats,
                    payment_hash: sent.payment_hash,
                    preimage_hex: sent.preimage_hex,
                };
                // A backend's Completed status is not authorization evidence.
                // Keep the attempt submitted/ambiguous unless the one common
                // proof verifier binds all material to this invoice.
                if verify_payment_result(invoice, raw.clone()).is_err() {
                    return PaymentAttemptOutcome::SubmittedUnknown(
                        PaymentError::AmbiguousSubmission,
                    );
                }
                let mut outcome = PaymentAttemptOutcome::confirmed(raw);
                if sent.fee_sats > max_fee_sats {
                    outcome.add_post_submit_condition(PostSubmitCondition::FinalFeeExceeded);
                }
                outcome
            }
        }
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        if !self.connected.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        match self.sdk.disconnect().await {
            Ok(()) => self.storage.release(),
            Err(error) => {
                // Preserve the lifecycle state so a caller can retry cleanup;
                // do not pretend ownership was released.
                self.connected.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

/// Secret resolution is injected so tests can prove values are not retained in
/// parsed config. The production implementation reloads the same supported
/// config-adjacent file plus process environment when the wallet is first
/// constructed.
pub trait BreezSecretProvider: Send + Sync {
    fn resolve(&self, reference: &EnvRef) -> Result<String, PaymentError>;
}

#[derive(Debug, Clone)]
pub struct ProcessBreezSecrets {
    config_path: PathBuf,
}

impl ProcessBreezSecrets {
    pub fn for_config(config: &BreezConfig) -> Self {
        Self {
            config_path: config.secret_source_config().to_path_buf(),
        }
    }
}

impl BreezSecretProvider for ProcessBreezSecrets {
    fn resolve(&self, reference: &EnvRef) -> Result<String, PaymentError> {
        let merged = load_config_env(&self.config_path);
        reference
            .resolve(&merged)
            .map_err(|_| PaymentError::InvalidInput)
    }
}

pub struct ProductionPrepared(PrepareSendPaymentResponse);

/// Concrete adapter for the pinned SDK. No secret value is a field and Debug
/// intentionally exposes only fixed metadata.
pub struct ProductionBreezSparkSdk {
    config: BreezConfig,
    secrets: Arc<dyn BreezSecretProvider>,
    sdk: OnceCell<Arc<BreezSdk>>,
    disconnected: AtomicBool,
}

impl std::fmt::Debug for ProductionBreezSparkSdk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBreezSparkSdk")
            .field("network", &self.config.network)
            .field("storage_dir", &self.config.storage_dir)
            .field(
                "completion_timeout_secs",
                &self.config.completion_timeout_secs,
            )
            .finish_non_exhaustive()
    }
}

impl ProductionBreezSparkSdk {
    pub fn new(config: BreezConfig) -> Self {
        let secrets = Arc::new(ProcessBreezSecrets::for_config(&config));
        Self::with_secret_provider(config, secrets)
    }

    pub fn with_secret_provider(
        config: BreezConfig,
        secrets: Arc<dyn BreezSecretProvider>,
    ) -> Self {
        Self {
            config,
            secrets,
            sdk: OnceCell::new(),
            disconnected: AtomicBool::new(false),
        }
    }

    async fn sdk(&self) -> Result<Arc<BreezSdk>, PaymentError> {
        let sdk = self
            .sdk
            .get_or_try_init(|| async {
                let api_key = self.secrets.resolve(&self.config.api_key_env)?;
                let mnemonic = self.secrets.resolve(&self.config.mnemonic_env)?;
                let network = match self.config.network {
                    BreezNetwork::Mainnet => Network::Mainnet,
                };
                let mut config = default_config(network);
                config.api_key = Some(api_key);
                let sdk = connect(ConnectRequest {
                    config,
                    seed: Seed::Mnemonic {
                        mnemonic,
                        passphrase: None,
                    },
                    storage_dir: self.config.storage_dir.to_string_lossy().into_owned(),
                })
                .await
                .map_err(classify_sdk_error)?;
                Ok::<Arc<BreezSdk>, PaymentError>(Arc::new(sdk))
            })
            .await?;
        Ok(Arc::clone(sdk))
    }
}

impl BreezSparkPayer<ProductionBreezSparkSdk> {
    pub fn production(config: BreezConfig) -> Result<Self, PaymentError> {
        let storage = BreezStorage::acquire(&config.storage_dir)?;
        Ok(Self::new(ProductionBreezSparkSdk::new(config), storage))
    }
}

#[async_trait]
impl BreezSparkSdk for ProductionBreezSparkSdk {
    type Prepared = ProductionPrepared;

    async fn check_ready(&self) -> Result<(), PaymentError> {
        let timeout = Duration::from_secs(u64::from(self.config.completion_timeout_secs));
        tokio::time::timeout(timeout, async {
            self.sdk()
                .await?
                .get_info(GetInfoRequest {
                    ensure_synced: Some(true),
                })
                .await
                .map_err(classify_sdk_error)?;
            Ok(())
        })
        .await
        .map_err(|_| PaymentError::Timeout)?
    }

    async fn prepare_bolt11(
        &self,
        bolt11: &str,
    ) -> Result<PreparedPayment<Self::Prepared>, PaymentError> {
        let prepared = self
            .sdk()
            .await?
            .prepare_send_payment(PrepareSendPaymentRequest {
                payment_request: PaymentRequest::Input {
                    input: bolt11.to_owned(),
                },
                amount: None,
                token_identifier: None,
                conversion_options: None,
                fee_policy: None,
            })
            .await
            .map_err(classify_sdk_error)?;
        let fee_sats = match &prepared.payment_method {
            SendPaymentMethod::Bolt11Invoice {
                lightning_fee_sats, ..
            } => *lightning_fee_sats,
            _ => return Err(PaymentError::MalformedResponse),
        };
        Ok(PreparedPayment::new(fee_sats, ProductionPrepared(prepared)))
    }

    async fn send_prepared(
        &self,
        prepared: Self::Prepared,
    ) -> Result<SparkPaymentResult, PaymentError> {
        let response = self
            .sdk()
            .await?
            .send_payment(SendPaymentRequest {
                prepare_response: prepared.0,
                options: Some(SendPaymentOptions::Bolt11Invoice {
                    prefer_spark: false,
                    completion_timeout_secs: Some(self.config.completion_timeout_secs),
                }),
                idempotency_key: None,
            })
            .await
            .map_err(classify_sdk_error)?;
        let payment = response.payment;
        let amount_sats =
            u64::try_from(payment.amount).map_err(|_| PaymentError::MalformedResponse)?;
        let fee_sats = u64::try_from(payment.fees).map_err(|_| PaymentError::MalformedResponse)?;
        let (payment_hash, preimage_hex) = match payment.details {
            Some(PaymentDetails::Lightning { htlc_details, .. }) => {
                (Some(htlc_details.payment_hash), htlc_details.preimage)
            }
            _ => (None, None),
        };
        let outcome = match payment.status {
            PaymentStatus::Failed => SubmissionOutcome::FailedFinal,
            PaymentStatus::Pending => SubmissionOutcome::SubmittedUnknown,
            PaymentStatus::Completed if payment_hash.is_some() && preimage_hex.is_some() => {
                SubmissionOutcome::Succeeded
            }
            PaymentStatus::Completed => SubmissionOutcome::SubmittedUnknown,
        };
        Ok(SparkPaymentResult {
            amount_sats,
            fee_sats,
            payment_hash,
            preimage_hex,
            outcome,
        })
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        if self.disconnected.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if let Some(sdk) = self.sdk.get() {
            if let Err(error) = sdk.disconnect().await {
                self.disconnected.store(false, Ordering::Release);
                return Err(classify_sdk_error(error));
            }
        }
        Ok(())
    }
}

fn classify_sdk_error(error: breez_sdk_spark::SdkError) -> PaymentError {
    use breez_sdk_spark::SdkError;
    match error {
        SdkError::InvalidInput(_) | SdkError::InvalidUuid(_) => PaymentError::InvalidInput,
        SdkError::NetworkError(_) | SdkError::ChainServiceError(_) => PaymentError::Transport,
        SdkError::StorageError(_) => PaymentError::Transport,
        _ => PaymentError::Transport,
    }
}

impl<S> Drop for BreezSparkPayer<S> {
    fn drop(&mut self) {
        // A payer which never connected owns no SDK resource and can release
        // its claim.  Once connected, only a successful async disconnect may
        // release it; Drop cannot safely make that assertion.
        if !self.connected.load(Ordering::Acquire) {
            let _ = self.storage.release();
        }
    }
}

pub fn qualification_stub() -> Result<(), PaymentError> {
    Ok(())
}
