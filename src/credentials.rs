//! Credential construction from verified proofs only.

use crate::challenge::{NormalizedPaymentChallenge, ParsedChallenge, PaymentWireChallenge};
use crate::payers::base::VerifiedPaymentResult;
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum CredentialTemplate {
    Payment {
        challenge: serde_json::Map<String, serde_json::Value>,
        source: Option<String>,
    },
    L402 {
        token: String,
    },
}

impl CredentialTemplate {
    pub fn prepare(
        challenge: &ParsedChallenge,
        normalized: &NormalizedPaymentChallenge,
        source: Option<&str>,
    ) -> Result<Self, CredentialError> {
        match challenge {
            ParsedChallenge::Payment(challenge) => Ok(Self::Payment {
                challenge: payment_challenge_payload(challenge),
                source: source.map(ToOwned::to_owned),
            }),
            ParsedChallenge::L402(challenge) => {
                validate_token(&challenge.token)?;
                if let Some(hash) = challenge.auth_params.get("payment_hash") {
                    let expected: [u8; 32] = hex::decode(hash)
                        .map_err(|_| CredentialError::InvalidChallenge)?
                        .try_into()
                        .map_err(|_| CredentialError::InvalidChallenge)?;
                    if &expected != normalized.payment_hash() {
                        return Err(CredentialError::ProofMismatch);
                    }
                }
                Ok(Self::L402 {
                    token: challenge.token.clone(),
                })
            }
        }
    }

    /// All untrusted fields were validated during `prepare`; rendering only
    /// combines trusted verified proof with an owned canonical template.
    pub fn render(&self, payment: &VerifiedPaymentResult) -> Result<String, CredentialError> {
        match self {
            Self::L402 { token } => Ok(format!("L402 {token}:{}", hex::encode(payment.preimage()))),
            Self::Payment { challenge, source } => {
                let mut credential = serde_json::Map::new();
                credential.insert(
                    "challenge".into(),
                    serde_json::Value::Object(challenge.clone()),
                );
                credential.insert(
                    "payload".into(),
                    serde_json::json!({"preimage": hex::encode(payment.preimage())}),
                );
                if let Some(source) = source {
                    credential.insert("source".into(), serde_json::Value::String(source.clone()));
                }
                let json = serde_json::to_vec(&serde_json::Value::Object(credential))
                    .map_err(|_| CredentialError::InvalidChallenge)?;
                Ok(format!(
                    "Payment {}",
                    crate::serialization::base64_url_nopad(&json)
                ))
            }
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialError {
    #[error("credential token is invalid")]
    InvalidToken,
    #[error("payment proof does not belong to the selected challenge")]
    ProofMismatch,
    #[error("credential challenge is invalid")]
    InvalidChallenge,
}

/// Build either wire protocol from common verified proof material. Payment
/// credentials intentionally reproduce the Python/oracle canonical JSON shape.
pub fn build_authorization(
    challenge: &ParsedChallenge,
    payment: &VerifiedPaymentResult,
    source: Option<&str>,
) -> Result<String, CredentialError> {
    match challenge {
        ParsedChallenge::Payment(challenge) => {
            build_payment_authorization(challenge, payment, source)
        }
        ParsedChallenge::L402(challenge) => {
            if let Some(hash) = challenge.auth_params.get("payment_hash") {
                let expected = hex::decode(hash).map_err(|_| CredentialError::InvalidChallenge)?;
                if expected.as_slice() != payment.payment_hash() {
                    return Err(CredentialError::ProofMismatch);
                }
            }
            validate_token(&challenge.token)?;
            Ok(format!(
                "L402 {}:{}",
                challenge.token,
                hex::encode(payment.preimage())
            ))
        }
    }
}

pub fn build_payment_authorization(
    challenge: &PaymentWireChallenge,
    payment: &VerifiedPaymentResult,
    source: Option<&str>,
) -> Result<String, CredentialError> {
    if let Some(hash) = &challenge.payment_hash {
        let expected = hex::decode(hash).map_err(|_| CredentialError::InvalidChallenge)?;
        if expected.as_slice() != payment.payment_hash() {
            return Err(CredentialError::ProofMismatch);
        }
    }
    let challenge_payload = payment_challenge_payload(challenge);
    let template = CredentialTemplate::Payment {
        challenge: challenge_payload,
        source: source.map(ToOwned::to_owned),
    };
    template.render(payment)
}

fn payment_challenge_payload(
    challenge: &PaymentWireChallenge,
) -> serde_json::Map<String, serde_json::Value> {
    let mut challenge_payload = serde_json::Map::new();
    for key in [
        "id",
        "realm",
        "method",
        "intent",
        "expires",
        "digest",
        "description",
        "opaque",
    ] {
        if let Some(value) = challenge.auth_params.get(key) {
            challenge_payload.insert(key.into(), serde_json::Value::String(value.clone()));
        }
    }
    if !challenge_payload.contains_key("description")
        && let Some(value) = &challenge.description
    {
        challenge_payload.insert(
            "description".into(),
            serde_json::Value::String(value.clone()),
        );
    }
    if !challenge_payload.contains_key("expires")
        && let Some(value) = challenge.expires
    {
        challenge_payload.insert(
            "expires".into(),
            serde_json::Value::String(value.to_string()),
        );
    }
    challenge_payload.insert(
        "request".into(),
        serde_json::Value::String(challenge.request.clone()),
    );
    challenge_payload
}

fn validate_token(token: &str) -> Result<(), CredentialError> {
    if token.is_empty()
        || token.contains([':', ',', '\r', '\n'])
        || token.chars().any(char::is_control)
    {
        Err(CredentialError::InvalidToken)
    } else {
        Ok(())
    }
}

/// Build an L402 value without exposing proof data through errors.
pub fn build_l402_authorization(
    token: &str,
    challenge: &NormalizedPaymentChallenge,
    payment: &VerifiedPaymentResult,
) -> Result<String, CredentialError> {
    validate_token(token)?;
    if payment.payment_hash() != challenge.payment_hash() {
        return Err(CredentialError::ProofMismatch);
    }
    Ok(format!("L402 {token}:{}", hex::encode(payment.preimage())))
}
