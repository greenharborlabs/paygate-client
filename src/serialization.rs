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

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_standard(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64[(a >> 2) as usize] as char);
        out.push(BASE64[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_url_nopad(bytes: &[u8]) -> String {
    base64_standard(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

pub fn decode_base64_url_nopad(value: &str) -> Option<Vec<u8>> {
    if value.contains('=') {
        return None;
    }
    let mut normalized = value.replace('-', "+").replace('_', "/");
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }
    let mut out = Vec::with_capacity(normalized.len() / 4 * 3);
    for block in normalized.as_bytes().chunks(4) {
        if block.len() != 4 {
            return None;
        }
        let v = |c: u8| -> Option<u8> {
            BASE64
                .iter()
                .position(|candidate| *candidate == c)
                .map(|i| i as u8)
        };
        let a = v(block[0])?;
        let b = v(block[1])?;
        let c = if block[2] == b'=' { 0 } else { v(block[2])? };
        let d = if block[3] == b'=' { 0 } else { v(block[3])? };
        out.push((a << 2) | (b >> 4));
        if block[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if block[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Some(out)
}
