// Loosely derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/methods/web/src/lib.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use reqwest::header;

use super::{did::Did, did_doc::DidDocument};

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    pub(crate) static PROXY: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[derive(Debug, thiserror::Error)]
pub enum DidWebError {
    #[error("error building HTTP client: {0}")]
    Client(reqwest::Error),

    #[error("error sending HTTP request ({0}): {1}")]
    Request(String, reqwest::Error),

    #[error("server error: {0}")]
    Server(String),

    #[error("error reading HTTP response: {0}")]
    Response(reqwest::Error),

    #[error("the document was not found: {0}")]
    NotFound(String),

    #[error("the document was not a valid DID document: {0}")]
    InvalidData(String),

    #[error("invalid web DID: {0}")]
    InvalidWebDid(String),
}

pub(crate) async fn resolve(did: &Did<'_>) -> Result<DidDocument, DidWebError> {
    let method = did.method_name();
    #[allow(clippy::panic)] // TEMPORARY while refactoring
    if method != "web" {
        panic!("Unexpected DID method {method}");
    }

    let method_specific_id = did.method_specific_id();

    dbg!(method_specific_id);

    let url = to_url(method_specific_id)?;
    // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security

    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static(USER_AGENT),
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(DidWebError::Client)?;

    let resp = client
        .get(&url)
        .header(header::ACCEPT, "application/did+json")
        .send()
        .await
        .map_err(|e| DidWebError::Request(url.to_owned(), e))?;

    resp.error_for_status_ref().map_err(|err| {
        if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            DidWebError::NotFound(url.clone())
        } else {
            DidWebError::Server(err.to_string())
        }
    })?;

    let document = resp.bytes().await.map_err(DidWebError::Response)?;

    let json =
        String::from_utf8(document.to_vec()).map_err(|_| DidWebError::InvalidData(url.clone()))?;

    DidDocument::from_json(&json).map_err(|_| DidWebError::InvalidData(url))
}

pub(crate) fn to_url(did: &str) -> Result<String, DidWebError> {
    let mut parts = did.split(':').peekable();
    let domain_name = parts
        .next()
        .ok_or_else(|| DidWebError::InvalidWebDid(did.to_owned()))?;

    // TODO:
    // - Validate domain name: alphanumeric, hyphen, dot. no IP address.
    // - Ensure domain name matches TLS certificate common name
    // - Support punycode?
    // - Support query strings?
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    // Use http for localhost, for testing purposes.
    let proto = if domain_name.starts_with("localhost") {
        "http"
    } else {
        "https"
    };

    #[allow(unused_mut)]
    let mut url = format!(
        "{proto}://{}/{path}/did.json",
        domain_name.replacen("%3A", ":", 1)
    );

    #[cfg(test)]
    PROXY.with(|proxy| {
        if let Some(ref proxy) = *proxy.borrow() {
            url = proxy.clone() + &url;
        }
    });

    Ok(url)
}
