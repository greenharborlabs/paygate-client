//! Stable JSON helpers shared by persistent state.

use serde::Serialize;
use serde_json::Value;

/// Encode JSON deterministically enough for state files and machine output.
/// `serde_json::Map` is ordered by default, so objects created through this
/// boundary have a stable lexical representation without leaking internals.
pub fn to_pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn parse_object(bytes: &[u8]) -> Result<serde_json::Map<String, Value>, serde_json::Error> {
    match serde_json::from_slice(bytes)? {
        Value::Object(object) => Ok(object),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected JSON object",
        ))),
    }
}
