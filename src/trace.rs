//! Secret-safe request trace rendering. Callers choose stderr for verbose and
//! stdout for JSON-lines; this module guarantees the same sanitized event data.

use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceEvent {
    pub event: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl TraceEvent {
    pub fn new(event: impl Into<String>, mut fields: Map<String, Value>) -> Self {
        let mut value = Value::Object(fields);
        crate::redaction::redact_json(&mut value);
        fields = value.as_object().cloned().unwrap_or_default();
        Self {
            event: event.into(),
            fields,
        }
    }

    pub fn json_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "{\"event\":\"trace.serialization_failed\"}".into())
    }

    pub fn verbose_line(&self) -> String {
        let details = self
            .fields
            .iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(key, value)| {
                format!(
                    "{key}={}",
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        if details.is_empty() {
            format!("paygate: {}", self.event)
        } else {
            format!("paygate: {} {details}", self.event)
        }
    }
}

#[derive(Default)]
pub struct TraceRecorder {
    events: Vec<TraceEvent>,
}

impl TraceRecorder {
    pub fn emit(&mut self, event: impl Into<String>, fields: Map<String, Value>) {
        self.events.push(TraceEvent::new(event, fields));
    }
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }
}
