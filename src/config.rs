//! Safe YAML configuration input boundary.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle, Scanner, StrInput, TokenType};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
use thiserror::Error;

/// A deliberately redacted configuration error. Source bytes and parser diagnostics are not
/// retained because configuration can contain credentials.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigInputError {
    #[error("configuration is not valid UTF-8")]
    Utf8,
    #[error("configuration is empty")]
    Empty,
    #[error("configuration contains a disallowed YAML construct: {0}")]
    Unsafe(&'static str),
    #[error("configuration YAML is malformed")]
    Malformed,
    #[error("configuration does not match the required schema")]
    Schema,
}

#[derive(Default)]
struct MappingState {
    keys: BTreeSet<String>,
    expecting_key: bool,
}

enum Frame {
    Map(MappingState),
    Sequence,
}

/// Deserialize one document from Paygate's qualified safe YAML subset.
pub fn from_safe_yaml<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ConfigInputError> {
    let input = std::str::from_utf8(bytes).map_err(|_| ConfigInputError::Utf8)?;
    if input.trim().is_empty() {
        return Err(ConfigInputError::Empty);
    }
    validate_events(input)?;
    let options = serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(input, options).map_err(|_| ConfigInputError::Schema)
}

fn validate_events(input: &str) -> Result<(), ConfigInputError> {
    let mut scanner = Scanner::new(StrInput::new(input));
    while let Some(token) = scanner
        .next_token()
        .map_err(|_| ConfigInputError::Malformed)?
    {
        if matches!(
            token.1,
            TokenType::VersionDirective(..) | TokenType::TagDirective(..)
        ) {
            return Err(ConfigInputError::Unsafe("directives"));
        }
    }
    let mut parser = Parser::new_from_str(input);
    let mut documents = 0usize;
    let mut frames: Vec<Frame> = Vec::new();
    let mut root_nodes = 0usize;

    while let Some(item) = parser.next_event() {
        let (event, _) = item.map_err(|_| ConfigInputError::Malformed)?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            Event::DocumentStart(_, version) => {
                documents += 1;
                root_nodes = 0;
                if documents > 1 {
                    return Err(ConfigInputError::Unsafe("multiple documents"));
                }
                if version.is_some() {
                    return Err(ConfigInputError::Unsafe("directives"));
                }
            }
            Event::Alias(_) => return Err(ConfigInputError::Unsafe("aliases")),
            Event::Scalar(value, style, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if style == ScalarStyle::Plain
                    && matches!(
                        value.to_ascii_lowercase().as_str(),
                        "y" | "yes" | "n" | "no" | "on" | "off"
                    )
                {
                    return Err(ConfigInputError::Unsafe("YAML 1.1 booleans"));
                }
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    let Frame::Map(map) = frames.last_mut().expect("checked above") else {
                        unreachable!()
                    };
                    if value == "<<" {
                        return Err(ConfigInputError::Unsafe("merge keys"));
                    }
                    if !map.keys.insert(value.to_string()) {
                        return Err(ConfigInputError::Unsafe("duplicate keys"));
                    }
                    map.expecting_key = false;
                } else {
                    finish_value(&mut frames, &mut root_nodes)?;
                }
            }
            Event::MappingStart(_, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    return Err(ConfigInputError::Unsafe("composite keys"));
                }
                frames.push(Frame::Map(MappingState {
                    expecting_key: true,
                    ..MappingState::default()
                }));
            }
            Event::MappingEnd => {
                let Frame::Map(map) = frames.pop().ok_or(ConfigInputError::Malformed)? else {
                    return Err(ConfigInputError::Malformed);
                };
                if !map.expecting_key {
                    return Err(ConfigInputError::Malformed);
                }
                finish_value(&mut frames, &mut root_nodes)?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    return Err(ConfigInputError::Unsafe("composite keys"));
                }
                frames.push(Frame::Sequence);
            }
            Event::SequenceEnd => {
                if !matches!(frames.pop(), Some(Frame::Sequence)) {
                    return Err(ConfigInputError::Malformed);
                }
                finish_value(&mut frames, &mut root_nodes)?;
            }
            Event::Nothing => return Err(ConfigInputError::Malformed),
        }
    }
    if documents != 1 || root_nodes != 1 || !frames.is_empty() {
        return Err(ConfigInputError::Malformed);
    }
    Ok(())
}

fn reject_properties(anchor: usize, tagged: bool) -> Result<(), ConfigInputError> {
    if anchor != 0 {
        return Err(ConfigInputError::Unsafe("anchors"));
    }
    if tagged {
        return Err(ConfigInputError::Unsafe("tags"));
    }
    Ok(())
}

fn finish_value(frames: &mut [Frame], root_nodes: &mut usize) -> Result<(), ConfigInputError> {
    match frames.last_mut() {
        Some(Frame::Map(map)) if !map.expecting_key => map.expecting_key = true,
        Some(Frame::Map(_)) | Some(Frame::Sequence) => {}
        None => {
            *root_nodes += 1;
            if *root_nodes > 1 {
                return Err(ConfigInputError::Unsafe("trailing document content"));
            }
        }
    }
    Ok(())
}
