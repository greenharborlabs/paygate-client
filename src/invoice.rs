//! Validated BOLT11 decoder boundary; decoding implementation belongs to Wave 3.

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
