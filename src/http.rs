//! Bounded HTTP transport used by the request transaction.

use reqwest::{
    Client, Method, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Map, Value, json};
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub url: reqwest::Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
    pub phase_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HttpError {
    #[error("target request timed out")]
    Timeout,
    #[error("target request failed")]
    Transport,
    #[error("response body exceeds the configured limit")]
    ResponseTooLarge,
    #[error("redirect responses are not followed")]
    Redirect,
    #[error("request input is invalid")]
    InvalidRequest,
}

pub fn client() -> Result<Client, HttpError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| HttpError::Transport)
}

/// Send one attempt. The timeout is an inactivity budget for headers and then
/// independently for every body chunk, rather than a total request deadline.
pub async fn send(client: &Client, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
    let mut builder = client
        .request(request.method.clone(), request.url.clone())
        .headers(request.headers.clone());
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }
    let mut response = tokio::time::timeout(request.phase_timeout, builder.send())
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(|error| {
            if error.is_timeout() {
                HttpError::Timeout
            } else {
                HttpError::Transport
            }
        })?;
    if response.status().is_redirection() {
        return Err(HttpError::Redirect);
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    loop {
        let chunk = tokio::time::timeout(request.phase_timeout, response.chunk())
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|error| {
                if error.is_timeout() {
                    HttpError::Timeout
                } else {
                    HttpError::Transport
                }
            })?;
        let Some(chunk) = chunk else { break };
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
            return Err(HttpError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

pub fn parse_headers(values: &[(String, String)]) -> Result<HeaderMap, HttpError> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpError::InvalidRequest)?;
        let value = HeaderValue::from_str(value).map_err(|_| HttpError::InvalidRequest)?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn same_origin(left: &reqwest::Url, right: &reqwest::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

pub fn www_authenticate_values(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(ToOwned::to_owned))
        .collect()
}

pub fn serialize_body(body: &[u8]) -> Result<Value, HttpError> {
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(HttpError::ResponseTooLarge);
    }
    if let Ok(mut value) = serde_json::from_slice::<Value>(body) {
        crate::redaction::redact_json(&mut value);
        return Ok(json!({"json": value}));
    }
    if let Ok(text) = std::str::from_utf8(body) {
        return Ok(json!({"body": crate::redaction::redact_text(text, &[])}));
    }
    Ok(json!({"bodyBase64": crate::serialization::base64_standard(body)}))
}

pub fn serialize_response(response: &HttpResponse) -> Result<Value, HttpError> {
    let mut headers = Map::new();
    for (name, value) in &response.headers {
        headers.insert(
            name.as_str().to_owned(),
            Value::String(crate::redaction::redact_header(
                name.as_str(),
                value.to_str().unwrap_or(""),
            )),
        );
    }
    let mut out = Map::new();
    out.insert("statusCode".into(), Value::from(response.status.as_u16()));
    out.insert("headers".into(), Value::Object(headers));
    if let Value::Object(body) = serialize_body(&response.body)? {
        out.extend(body);
    }
    Ok(Value::Object(out))
}
