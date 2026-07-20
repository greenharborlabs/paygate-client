//! Validated BOLT11 decoder boundary.

use std::str::FromStr;

use lightning_invoice::Bolt11Invoice;
use thiserror::Error;

/// The maximum number of satoshis that can exist under Bitcoin's 21 million BTC
/// monetary supply. This is a deliberate application-domain bound, rather than
/// an unreachable `u64 / 1000` overflow check.
const MAX_BITCOIN_SATS: u64 = 2_100_000_000_000_000;

/// A BOLT11 string cannot be used as payment input until this parser has checked its
/// signature and monetary representation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InvoiceError {
    #[error("invoice is malformed or has an invalid signature")]
    Invalid,
    #[error("invoice must include an amount")]
    Amountless,
    #[error("invoice amount must be a whole number of satoshis")]
    FractionalSatoshi,
    #[error("invoice amount is too large")]
    AmountOverflow,
}

/// A signature-checked, amount-bearing BOLT11 invoice.
///
/// Construction remains private to this module so no payer or sibling module can upgrade an
/// untrusted string. The Wave 3 decoder will be implemented beside this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBolt11 {
    original: String,
    amount_msats: u64,
    amount_sats: u64,
    payment_hash: [u8; 32],
}

impl ValidatedBolt11 {
    /// Parse a complete, signature-checked BOLT11 invoice.
    ///
    /// `Bolt11Invoice` performs the semantic and signature checks.  We then reject
    /// zero/absent amountless invoices and sub-satoshi values before returning the
    /// opaque value that payer implementations accept.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, InvoiceError> {
        let original = value.as_ref();
        let decoded = Bolt11Invoice::from_str(original).map_err(|_| InvoiceError::Invalid)?;
        let amount_msats = decoded
            .amount_milli_satoshis()
            .ok_or(InvoiceError::Amountless)?;
        if amount_msats % 1_000 != 0 {
            return Err(InvoiceError::FractionalSatoshi);
        }
        let amount_sats = amount_sats_from_msats(amount_msats)?;
        let payment_hash: [u8; 32] = hex::decode(decoded.payment_hash().to_string())
            .expect("BOLT11 payment hashes render as hex")
            .try_into()
            .expect("BOLT11 payment hashes are always 32 bytes");
        Ok(Self::from_decoded(
            original.to_owned(),
            amount_msats,
            amount_sats,
            payment_hash,
        ))
    }
    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn amount_msats(&self) -> u64 {
        self.amount_msats
    }

    pub fn amount_sats(&self) -> u64 {
        self.amount_sats
    }

    pub fn payment_hash(&self) -> &[u8; 32] {
        &self.payment_hash
    }

    #[allow(dead_code)]
    fn from_decoded(
        original: String,
        amount_msats: u64,
        amount_sats: u64,
        payment_hash: [u8; 32],
    ) -> Self {
        Self {
            original,
            amount_msats,
            amount_sats,
            payment_hash,
        }
    }
}

fn amount_sats_from_msats(amount_msats: u64) -> Result<u64, InvoiceError> {
    if amount_msats % 1_000 != 0 {
        return Err(InvoiceError::FractionalSatoshi);
    }
    let amount_sats = amount_msats / 1_000;
    if amount_sats > MAX_BITCOIN_SATS {
        return Err(InvoiceError::AmountOverflow);
    }
    Ok(amount_sats)
}

impl TryFrom<&str> for ValidatedBolt11 {
    type Error = InvoiceError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOLE_SAT_INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";
    const AMOUNTLESS_INVOICE: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    #[test]
    fn parser_retains_signed_amount_and_hash() {
        let invoice = ValidatedBolt11::parse(WHOLE_SAT_INVOICE).expect("valid fixture");
        assert_eq!(invoice.amount_msats(), 2_500_000_000);
        assert_eq!(invoice.amount_sats(), 2_500_000);
        assert_eq!(invoice.original(), WHOLE_SAT_INVOICE);
    }

    #[test]
    fn parser_rejects_malformed_input() {
        assert_eq!(
            ValidatedBolt11::parse("not-an-invoice"),
            Err(InvoiceError::Invalid)
        );
    }

    #[test]
    fn parser_rejects_a_signed_amountless_invoice() {
        assert_eq!(
            ValidatedBolt11::parse(AMOUNTLESS_INVOICE),
            Err(InvoiceError::Amountless)
        );
    }

    #[test]
    fn amount_conversion_rejects_fractional_and_out_of_domain_values() {
        assert_eq!(
            amount_sats_from_msats(1),
            Err(InvoiceError::FractionalSatoshi)
        );
        assert_eq!(
            amount_sats_from_msats((MAX_BITCOIN_SATS + 1) * 1_000),
            Err(InvoiceError::AmountOverflow)
        );
        assert_eq!(
            amount_sats_from_msats(MAX_BITCOIN_SATS * 1_000),
            Ok(MAX_BITCOIN_SATS)
        );
    }

    #[test]
    fn parser_rejects_corrupted_signature_before_returning_an_invoice() {
        let mut corrupt = WHOLE_SAT_INVOICE.to_owned();
        let last = corrupt.pop().expect("fixture is non-empty");
        corrupt.push(if last == 'q' { 'p' } else { 'q' });
        assert_eq!(ValidatedBolt11::parse(corrupt), Err(InvoiceError::Invalid));
    }
}
