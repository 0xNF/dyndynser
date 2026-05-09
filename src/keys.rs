use std::io::Read;
use std::path::Path;

use anyhow::{Context, Ok};
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePrivateKey};
use x509_cert::der::DecodePem;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::db::rfc4519::COMMON_NAME;
use x509_cert::*;

use crate::signatures;
use crate::unix::MustBeRoot;

#[derive(Debug)]
pub struct CertMatch {
    pub common_name: String,
    pub verifying_key: VerifyingKey,
}

/// Parses the given bytes as an X.509 Certificate PEM file and extracts the CommonName / Public Key from it
pub fn load_ed25519_certificate_pem(cert_bytes: &[u8]) -> Result<CertMatch, anyhow::Error> {
    let cert_bytes = cert_bytes.trim_ascii();
    let cert = Certificate::from_pem(cert_bytes)
        .context("Could not parse into an x509 PEM certificate")?;

    let subject_public_key = &cert.tbs_certificate.subject_public_key_info;
    let subject_public_key_as_bytes = subject_public_key
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("unable to extract Public Key bytes"))?;
    let pub_key_bytes: [u8; 32] = subject_public_key_as_bytes
        .try_into()
        .context("Public Key bytes were retrieved but size was not 32")?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .context("unable to convert bytes into a Verifying Key")?;

    let cn_atv = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == COMMON_NAME)
        .ok_or_else(|| {
            anyhow::anyhow!("unable to find the CommonName oid attribute in this certificate")
        })?;

    let common_name = cn_atv
        .value
        .decode_as::<Utf8StringRef<'_>>()
        .map(|s| s.as_str().to_owned())
        .or_else(|_| {
            cn_atv
                .value
                .decode_as::<PrintableStringRef<'_>>()
                .map(|s| s.as_str().to_owned())
        })
        .context("found the CommonName oid, but was unable to transform it into a string")?;

    let certmatch = CertMatch {
        common_name,
        verifying_key,
    };

    Ok(certmatch)
}

/// Parses the given bytes as an Ed25519 formatted private key
/// Takes an optional Password in case this key is encrypted
pub fn load_ed25519_private_key(
    key_bytes: &[u8],
    key_password: Option<&str>,
) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
    let key_bytes = key_bytes.trim_ascii();
    let signing_key = if key_bytes.starts_with(signatures::OPENSSH_PREFIX_PRIVATE_KEY.as_bytes()) {
        log::info!("Signing key is an OpenSSH Key");
        load_ed25519_openssh_private_key(key_bytes, key_password)?
    } else if key_bytes.starts_with(signatures::OPENSSL_PREFIX_PRIVATE_KEY.as_bytes()) {
        log::info!("Key was non-openssh signing key");
        load_ed25519_openssl_key(key_bytes)?
    } else {
        anyhow::bail!("Supplied signing key was not a valid supported format")
    };

    Ok(signing_key)
}

/// Parses the given bytes as an Ed25519 formatted OpenSSH private key
/// Takes an optional Password in case this key is encrypted
fn load_ed25519_openssh_private_key(
    key_bytes: &[u8],
    key_password: Option<&str>,
) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
    let mut sshkey = ssh_key::PrivateKey::from_openssh(key_bytes)?;
    match (sshkey.is_encrypted(), key_password) {
        (true, None) => {
            log::info!("key is encrypted, and no password was supplied. Trying a blank decryption");
            /* try a blank decryption attempt */
            const ZERO_BYTE: [u8; 0] = [];
            sshkey = sshkey.decrypt(ZERO_BYTE).context("Key is encrypted, and no password was supplied. Tried an empty decryption attempt, but a password is required")?;
        }
        (true, Some(pw_str)) => {
            log::info!("key is encrypted, and a password was supplied. trying decryption");
            let pw_bytes = pw_str.as_bytes();
            sshkey = sshkey
                .decrypt(pw_bytes)
                .context("Key is encrypted, but supplied password did not match")?;
        }
        _ => {
            log::info!("Key is not encrypted");
        }
    }
    let bytes = sshkey
        .key_data()
        .ed25519()
        .ok_or(anyhow::anyhow!(
            "signing key was not ed25519, we only support ed25519 keys"
        ))?
        .private
        .to_bytes();

    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Parses the given bytes as an OpenSSL ED25519 formatted private key
fn load_ed25519_openssl_key(key_bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
    let s: &str = std::str::from_utf8(key_bytes).context("not a valid utf8 string")?;
    ed25519_dalek::SigningKey::from_pkcs8_pem(s)
        .context("failed to decode pkcs8 pem bytes from signing key")
}

/// Reads a maximum of `max_bytes` from the given File Path
pub fn read_file_limited<P: AsRef<Path>>(
    path: P,
    max_bytes: u64,
) -> Result<Vec<u8>, anyhow::Error> {
    let size = std::fs::metadata(&path)
        .or_must_be_root("reading file metadata")?
        .len();

    /* Metadata check. Not fail-safe; a concrete check follows below. Early escape only. */
    if size > max_bytes {
        anyhow::bail!(
            "File too large: {} bytes (limit: {} bytes)",
            size,
            max_bytes
        );
    }

    let file = std::fs::File::open(&path).or_must_be_root("opening file")?;

    let mut buffer = Vec::with_capacity(size as usize);

    /* Actual size-check: read_to_end is capped at max_bytes by take() */
    std::io::BufReader::new(file)
        .take(max_bytes)
        .read_to_end(&mut buffer)
        .or_must_be_root("reading file")?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_file_too_big() {
        let f = super::read_file_limited("test/files/too_big.bin", 50);
        assert!(f.is_err(), "expected file to error out after 1024 bytes");
    }
}
