use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::fmt;

pub const PUBLIC_KEY_EXT: &str = "pub";
pub const PUBLIC_CERT_EXT: &str = "crt";
pub const OPENSSL_PREFIX_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----";
pub const OPENSSL_PREFIX_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----";
pub const OPENSSH_PREFIX_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
pub const OPENSSH_PREFIX_PUBLIC_KEY: &str = "ssh-";

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

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedJSON<T> {
    pub payload: T,
    pub signature: Signature,
}
