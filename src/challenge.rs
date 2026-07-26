//! Challenge normalization.  Strings received from an HTTP header are never a
//! payment capability; they must be bound to a [`ValidatedBolt11`].

use crate::invoice::{InvoiceError, ValidatedBolt11};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChallengeError {
    #[error("payment challenge is malformed")]
    Malformed,
    #[error("payment challenge is missing an invoice")]
    MissingInvoice,
    #[error("payment challenge amount does not match the invoice")]
    AmountMismatch,
    #[error("payment challenge hash does not match the invoice")]
    HashMismatch,
    #[error("payment challenge hash is malformed")]
    InvalidHash,
    #[error("payment challenge invoice is invalid")]
    InvalidInvoice,
    #[error("response did not include a supported challenge")]
    Unsupported,
    #[error("L402 challenge is disabled")]
    ProtocolDisabled,
    #[error("payment challenge is expired")]
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeProtocol {
    Payment,
    L402,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolPreference {
    Payment,
    L402,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentWireChallenge {
    pub auth_params: BTreeMap<String, String>,
    pub request: String,
    pub invoice: String,
    pub amount_sats: u64,
    pub payment_hash: Option<String>,
    pub service: Option<String>,
    pub description: Option<String>,
    pub expires: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L402WireChallenge {
    pub auth_params: BTreeMap<String, String>,
    pub token: String,
    pub invoice: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedChallenge {
    Payment(PaymentWireChallenge),
    L402(L402WireChallenge),
}

impl ParsedChallenge {
    pub const fn protocol(&self) -> ChallengeProtocol {
        match self {
            Self::Payment(_) => ChallengeProtocol::Payment,
            Self::L402(_) => ChallengeProtocol::L402,
        }
    }
    pub fn invoice(&self) -> &str {
        match self {
            Self::Payment(value) => &value.invoice,
            Self::L402(value) => &value.invoice,
        }
    }
}

pub fn parse_www_authenticate(
    headers: &[String],
    preferred: ProtocolPreference,
    allow_l402: bool,
    now_epoch_secs: i64,
) -> Result<ParsedChallenge, ChallengeError> {
    let mut parsed = Vec::new();
    let mut first_error = None;
    let mut disabled_l402 = false;
    for header in headers {
        for raw in split_challenges(header) {
            let Some((scheme, rest)) = raw.split_once(char::is_whitespace) else {
                first_error.get_or_insert(ChallengeError::Malformed);
                continue;
            };
            let params = match parse_auth_params(rest.trim()) {
                Ok(value) => value,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let challenge = if scheme.eq_ignore_ascii_case("Payment") {
                parse_payment_wire(params, now_epoch_secs)
            } else if scheme.eq_ignore_ascii_case("L402") {
                if !allow_l402 {
                    disabled_l402 = true;
                    continue;
                }
                parse_l402_wire(params)
            } else {
                continue;
            };
            match challenge {
                Ok(value) => parsed.push(value),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
    }
    let wanted = match preferred {
        ProtocolPreference::Payment => ChallengeProtocol::Payment,
        ProtocolPreference::L402 => ChallengeProtocol::L402,
    };
    if let Some(index) = parsed.iter().position(|value| value.protocol() == wanted) {
        return Ok(parsed.remove(index));
    }
    if let Some(value) = parsed.into_iter().next() {
        return Ok(value);
    }
    if disabled_l402 {
        return Err(ChallengeError::ProtocolDisabled);
    }
    Err(first_error.unwrap_or(ChallengeError::Unsupported))
}

fn parse_payment_wire(
    params: BTreeMap<String, String>,
    now: i64,
) -> Result<ParsedChallenge, ChallengeError> {
    let request = params
        .get("request")
        .cloned()
        .ok_or(ChallengeError::Malformed)?;
    let bytes =
        crate::serialization::decode_base64_url_nopad(&request).ok_or(ChallengeError::Malformed)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ChallengeError::Malformed)?;
    let object = payload.as_object().ok_or(ChallengeError::Malformed)?;
    let details = object
        .get("methodDetails")
        .and_then(serde_json::Value::as_object);
    let invoice = object
        .get("invoice")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            details
                .and_then(|value| value.get("invoice"))
                .and_then(serde_json::Value::as_str)
        })
        .filter(|value| !value.is_empty())
        .ok_or(ChallengeError::MissingInvoice)?
        .to_owned();
    let amount_sats = object
        .get("amountSats")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            object
                .get("amount_sats")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            object
                .get("amount")
                .and_then(serde_json::Value::as_str)?
                .parse()
                .ok()
        })
        .ok_or(ChallengeError::Malformed)?;
    let expires = params
        .get("expires")
        .map(|value| value.parse::<i64>().map_err(|_| ChallengeError::Malformed))
        .transpose()?;
    if expires.is_some_and(|expires| expires <= now) {
        return Err(ChallengeError::Expired);
    }
    let payment_hash = details
        .and_then(|value| {
            value
                .get("paymentHash")
                .or_else(|| value.get("payment_hash"))
        })
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| params.get("realm").cloned());
    let description = object
        .get("description")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| params.get("description").cloned());
    Ok(ParsedChallenge::Payment(PaymentWireChallenge {
        auth_params: params,
        request,
        invoice,
        amount_sats,
        payment_hash,
        service,
        description,
        expires,
    }))
}

fn parse_l402_wire(params: BTreeMap<String, String>) -> Result<ParsedChallenge, ChallengeError> {
    let invoice = params
        .get("invoice")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(ChallengeError::MissingInvoice)?;
    let token = params
        .get("token")
        .or_else(|| params.get("macaroon"))
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(ChallengeError::Malformed)?;
    Ok(ParsedChallenge::L402(L402WireChallenge {
        auth_params: params,
        token,
        invoice,
    }))
}

fn split_challenges(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if *byte == b'\\' && quoted {
            escaped = true;
            continue;
        }
        if *byte == b'"' {
            quoted = !quoted;
            continue;
        }
        if *byte == b',' && !quoted {
            let tail = value[index + 1..].trim_start();
            if ["Payment ", "L402 ", "Basic ", "Bearer "]
                .iter()
                .any(|prefix| {
                    tail.get(..prefix.len())
                        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
                })
            {
                out.push(value[start..index].trim());
                start = index + 1;
            }
        }
    }
    let final_value = value[start..].trim();
    if !final_value.is_empty() {
        out.push(final_value);
    }
    out
}

fn parse_auth_params(value: &str) -> Result<BTreeMap<String, String>, ChallengeError> {
    let mut out = BTreeMap::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b',') {
            index += 1;
        }
        let key_start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'-' | b'_'))
        {
            index += 1;
        }
        if key_start == index {
            return Err(ChallengeError::Malformed);
        }
        let key = &value[key_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            return Err(ChallengeError::Malformed);
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let parsed;
        if bytes.get(index) == Some(&b'"') {
            index += 1;
            let mut text = String::new();
            let mut closed = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => {
                        index += 1;
                        text.push(*bytes.get(index).ok_or(ChallengeError::Malformed)? as char);
                        index += 1;
                    }
                    b'"' => {
                        index += 1;
                        closed = true;
                        break;
                    }
                    byte if byte.is_ascii() => {
                        text.push(byte as char);
                        index += 1;
                    }
                    _ => return Err(ChallengeError::Malformed),
                }
            }
            if !closed {
                return Err(ChallengeError::Malformed);
            }
            parsed = text;
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b',' {
                index += 1;
            }
            parsed = value[start..index].trim().to_owned();
            if parsed.is_empty() || parsed.chars().any(char::is_whitespace) {
                return Err(ChallengeError::Malformed);
            }
        }
        out.insert(key.to_owned(), parsed);
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] != b',' {
            return Err(ChallengeError::Malformed);
        }
    }
    Ok(out)
}

impl From<InvoiceError> for ChallengeError {
    fn from(_: InvoiceError) -> Self {
        Self::InvalidInvoice
    }
}

/// Payment input whose amount and hash are both signed by the BOLT11 invoice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPaymentChallenge {
    invoice: ValidatedBolt11,
    service: Option<String>,
    request: String,
}

impl NormalizedPaymentChallenge {
    pub fn invoice(&self) -> &ValidatedBolt11 {
        &self.invoice
    }
    pub fn amount_sats(&self) -> u64 {
        self.invoice.amount_sats()
    }
    pub fn payment_hash(&self) -> &[u8; 32] {
        self.invoice.payment_hash()
    }
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }
    pub fn request(&self) -> &str {
        &self.request
    }
}

/// Normalize separately parsed challenge fields before policy or payer use.
pub fn normalize_payment_challenge(
    invoice: &str,
    challenge_amount_sats: u64,
    challenge_payment_hash: Option<&str>,
    service: Option<String>,
    request: String,
) -> Result<NormalizedPaymentChallenge, ChallengeError> {
    if invoice.is_empty() {
        return Err(ChallengeError::MissingInvoice);
    }
    let invoice = ValidatedBolt11::parse(invoice)?;
    if challenge_amount_sats != invoice.amount_sats() {
        return Err(ChallengeError::AmountMismatch);
    }
    if let Some(hash) = challenge_payment_hash {
        let bytes = hex::decode(hash).map_err(|_| ChallengeError::InvalidHash)?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| ChallengeError::InvalidHash)?;
        if hash != *invoice.payment_hash() {
            return Err(ChallengeError::HashMismatch);
        }
    }
    Ok(NormalizedPaymentChallenge {
        invoice,
        service,
        request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOLE_SAT_INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";

    #[test]
    fn rejects_challenge_amount_and_hash_mismatches() {
        let invoice = ValidatedBolt11::parse(WHOLE_SAT_INVOICE).expect("valid fixture");
        assert_eq!(
            normalize_payment_challenge(
                WHOLE_SAT_INVOICE,
                invoice.amount_sats() + 1,
                None,
                None,
                "/resource".to_owned(),
            ),
            Err(ChallengeError::AmountMismatch)
        );
        assert_eq!(
            normalize_payment_challenge(
                WHOLE_SAT_INVOICE,
                invoice.amount_sats(),
                Some(&"00".repeat(32)),
                None,
                "/resource".to_owned(),
            ),
            Err(ChallengeError::HashMismatch)
        );
    }
}
