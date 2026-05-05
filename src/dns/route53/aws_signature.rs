use anyhow::Context as _;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, str::FromStr as _};

// Returns the HMAC SHA256 of the data
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// Returns the hex-encodedd SHA256 hashed bytes of data
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute all headers required for an AWS SigV4 request (including
/// `Authorization`).  Returns a `BTreeMap` that must be forwarded verbatim
/// to the HTTP client.
#[allow(clippy::too_many_arguments)]
pub fn aws_sigv4_headers(
    method: &str,
    host: &str,
    path: &str,
    query: &str, // empty string if none
    body: &[u8],
    service: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>, // required for STS / instance-role creds
) -> BTreeMap<String, String> {
    let now = chrono::Utc::now();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    let payload_hash = sha256_hex(body);

    // BTreeMap keeps keys sorted — SigV4 requires canonical headers in
    // lexicographic order.
    let mut hdrs: BTreeMap<String, String> = BTreeMap::new();

    // content-type only makes sense for requests that carry a body.
    if !body.is_empty() {
        hdrs.insert("content-type".into(), "application/xml".into());
    }
    hdrs.insert("host".into(), host.into());
    hdrs.insert("x-amz-content-sha256".into(), payload_hash.clone());
    hdrs.insert("x-amz-date".into(), datetime.clone());
    if let Some(tok) = session_token {
        hdrs.insert("x-amz-security-token".into(), tok.into());
    }

    // Task 1: Canonical Request
    log::debug!("Constructing the cannonical AWS request");

    // Each entry is "lowercase-name:trimmed-value\n".
    let canonical_headers: String = hdrs
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    // Collect headers into a ; separated list with minimal allocations
    let signed_headers: String = hdrs
        .keys()
        .enumerate()
        .fold(String::new(), |mut acc, (i, k)| {
            if i > 0 {
                acc.push(';');
            }
            acc.push_str(k);
            acc
        });

    // `canonical_headers` already ends with '\n'; the .join("\n") below adds
    // one more before `signed_headers`, producing the required blank separator.
    let canonical_request = [
        method,
        path,
        query,
        &canonical_headers,
        &signed_headers,
        &payload_hash,
    ]
    .join("\n");

    // Task 2: String to Sign
    log::debug!("Creating the signing string");

    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        &datetime,
        &credential_scope,
        &sha256_hex(canonical_request.as_bytes()),
    ]
    .join("\n");

    // Task 3: Signing Key
    log::debug!("Constructing the signing key");

    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    // Task 4: Authorization Header
    log::debug!("constructing the authorization header");

    hdrs.insert(
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
             SignedHeaders={signed_headers}, Signature={signature}"
        ),
    );

    hdrs
}

// Convert BTreeMap → reqwest HeaderMap
pub fn to_header_map(map: &BTreeMap<String, String>) -> Result<HeaderMap, anyhow::Error> {
    let mut hm = HeaderMap::new();
    for (k, v) in map {
        let name = HeaderName::from_str(k).with_context(|| format!("invalid header name: {k}"))?;
        let value = HeaderValue::from_str(v)
            .with_context(|| format!("invalid header value for {k}: {v}"))?;
        hm.insert(name, value);
    }
    Ok(hm)
}
