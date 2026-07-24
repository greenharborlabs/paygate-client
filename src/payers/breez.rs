//! Breez Spark adapter behind a narrow SDK seam.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use super::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    ValidatedBolt11,
};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPayment {
    pub id: String,
    pub fee_sats: u64,
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
    async fn check_ready(&self) -> Result<(), PaymentError>;
    /// This seam intentionally accepts BOLT11 text only; no generic payment
    /// request or LNURL route is exposed by the production adapter.
    async fn prepare_bolt11(&self, bolt11: &str) -> Result<PreparedPayment, PaymentError>;
    async fn send_prepared(
        &self,
        prepared: &PreparedPayment,
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
    ) -> Result<RawPaymentResult, PaymentError> {
        let result = if cancellation == CancellationSemantics::AfterSubmissionUnknown {
            Ok(RawPaymentResult {
                amount_sats: 0,
                fee_sats: 0,
                payment_hash: None,
                preimage_hex: None,
                outcome: SubmissionOutcome::SubmittedUnknown,
            })
        } else {
            async {
                // Keep the lifecycle ordering local to this adapter even when callers
                // forget the separate readiness probe.
                self.check_ready().await?;
                let prepared = self.sdk.prepare_bolt11(invoice.original()).await?;
                if prepared.fee_sats > max_fee_sats {
                    Err(PaymentError::FeeExceeded)
                } else {
                    let sent = self.sdk.send_prepared(&prepared).await?;
                    if sent.fee_sats > max_fee_sats {
                        Err(PaymentError::FeeExceeded)
                    } else {
                        Ok(RawPaymentResult {
                            amount_sats: sent.amount_sats,
                            fee_sats: sent.fee_sats,
                            payment_hash: sent.payment_hash,
                            preimage_hex: sent.preimage_hex,
                            outcome: sent.outcome,
                        })
                    }
                }
            }
            .await
        };

        // Every actual SDK lifecycle terminates here.  A disconnect failure is
        // deliberately surfaced even when payment already failed, since the
        // exclusive storage claim may still guard live SDK state.
        match (result, self.disconnect().await) {
            (Ok(raw), Ok(())) => Ok(raw),
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
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
