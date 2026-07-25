//! Local policy binding for already-normalized payment challenges.

use crate::challenge::NormalizedPaymentChallenge;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("challenge host is not permitted")]
    HostDenied,
    #[error("challenge service is not permitted")]
    ServiceDenied,
    #[error("payment amount exceeds local policy")]
    AmountExceeded,
    #[error("payer cannot enforce the configured fee limit")]
    FeeLimitUnsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub allowed_hosts: Vec<String>,
    pub allowed_services: Vec<String>,
    pub max_request_sats: u64,
    pub max_fee_sats: u64,
}

/// A policy approval carries the validated invoice, so callers cannot reserve an
/// amount for one input and submit a different invoice later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyApproval {
    challenge: NormalizedPaymentChallenge,
    max_fee_sats: u64,
}

impl PolicyApproval {
    pub fn challenge(&self) -> &NormalizedPaymentChallenge {
        &self.challenge
    }
    pub fn max_fee_sats(&self) -> u64 {
        self.max_fee_sats
    }
}

pub fn bind_policy(
    config: &PolicyConfig,
    host: &str,
    challenge: NormalizedPaymentChallenge,
    payer_supports_fee_limit: bool,
) -> Result<PolicyApproval, PolicyError> {
    let host = normalize_host(host).ok_or(PolicyError::HostDenied)?;
    if !config
        .allowed_hosts
        .iter()
        .filter_map(|h| normalize_host(h))
        .any(|h| h == host)
    {
        return Err(PolicyError::HostDenied);
    }
    if let Some(service) = challenge.service()
        && !config
            .allowed_services
            .iter()
            .any(|allowed| allowed == service)
    {
        return Err(PolicyError::ServiceDenied);
    }
    if challenge.amount_sats() > config.max_request_sats {
        return Err(PolicyError::AmountExceeded);
    }
    if !payer_supports_fee_limit {
        return Err(PolicyError::FeeLimitUnsupported);
    }
    Ok(PolicyApproval {
        challenge,
        max_fee_sats: config.max_fee_sats,
    })
}

fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains([',', '/', '\\', '@']) {
        return None;
    }
    let (name, port) = value.rsplit_once(':')?;
    if name.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    Some(format!("{}:{port}", name.to_ascii_lowercase()))
}
