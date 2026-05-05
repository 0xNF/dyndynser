use anyhow::Context as _;
use ed25519_dalek::Signer;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::fmt;

pub const PUBLIC_CERT_EXT: &str = "crt";
pub const OPENSSL_PREFIX_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----";
pub const OPENSSH_PREFIX_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

#[derive(Debug, Clone, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);
impl Signature {
    pub fn new(sig: ed25519_dalek::Signature) -> Self {
        Self(sig)
    }
    pub fn inner(&self) -> &ed25519_dalek::Signature {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_bytes()))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

struct SignatureVisitor;

impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a hex-encoded 64-byte Ed25519 signature")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let bytes = hex::decode(v).map_err(|e| E::custom(format!("invalid hex: {e}")))?;

        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| E::custom("signature must be 64 bytes"))?;

        Ok(Signature(ed25519_dalek::Signature::from_bytes(&array)))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(SignatureVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPayload<T> {
    pub envelope: SignableEnvelope<T>,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignableEnvelope<T> {
    pub payload: T,
    pub signed_at_unix_secs: i64,
}

impl<T> SignableEnvelope<T>
where
    T: Serialize,
{
    pub fn new(payload: T) -> Self {
        Self {
            payload,
            signed_at_unix_secs: 0,
        }
    }

    // Signs anything that be JSON-serialized with the given signing key, producing a new object which contains the signature, and the object that was signed
    pub fn sign(
        mut self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.signed_at_unix_secs = chrono::Utc::now().timestamp();
        let payload_json = serde_json_canonicalizer::to_vec(&self)
            .context("failed to JSON serialize the ddns object")?;

        /* Sign bytes */
        log::info!("Signing result");
        let sig = signing_key
            .try_sign(&payload_json)
            .context("failed to ed25519 sign object")?;

        let signed_payload = SignedPayload {
            envelope: self,
            signature: Signature::new(sig),
        };

        let signed_bytes = serde_json::to_vec_pretty(&signed_payload)
            .context("failed to jsonify the signed ddns json")?;

        Ok(signed_bytes)
    }
}
