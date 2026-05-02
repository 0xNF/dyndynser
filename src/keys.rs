use std::io::Read;
use std::path::Path;

use anyhow::{Context, Ok};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePrivateKey};
use x509_cert::der::DecodePem;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::db::rfc4519::COMMON_NAME;
use x509_cert::*;

use crate::signatures;

pub struct CertMatch {
    pub common_name: String,
    pub verifying_key: VerifyingKey,
}

pub fn load_ed25519_certificate_pem(cert_bytes: &[u8]) -> Result<CertMatch, anyhow::Error> {
    let cert_bytes = cert_bytes.trim_ascii();
    let cert = Certificate::from_pem(&cert_bytes)
        .context("Could not parse into an x509 PEM certificate")?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pki = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("unable to extract Public Key bytes"))?;
    let pub_key_bytes: [u8; 32] = pki
        .try_into()
        .context("Public Key bytes were retrieved but size was not 32")?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .context("unable to convert bytes into a Veryfying Key")?;

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

pub fn load_ed25519_public_key(key_bytes: &[u8]) -> Result<VerifyingKey, anyhow::Error> {
    let key_bytes = key_bytes.trim_ascii();
    let verifying_key: VerifyingKey =
        if key_bytes.starts_with(signatures::OPENSSH_PREFIX_PUBLIC_KEY.as_bytes()) {
            log::debug!("key looks like an OpenSSH public key, will try to parse it");
            load_ed25519_openssh_public_key(&key_bytes)?
        } else if key_bytes.starts_with(signatures::OPENSSL_PREFIX_PUBLIC_KEY.as_bytes()) {
            log::info!("Key is non-openssh public key");
            load_ed25519_openssl_public_key(&key_bytes)?
        } else {
            return Err(anyhow::anyhow!(
                "Supplied verifying key was not a valid supported format"
            ));
        };

    Ok(verifying_key)
}

fn load_ed25519_openssh_public_key(key_bytes: &[u8]) -> Result<VerifyingKey, anyhow::Error> {
    let pubkey = ssh_key::PublicKey::from_openssh(&String::from_utf8_lossy(&key_bytes))
        .context("failed to parse key as openssh despite beginnign with `ssh-`")?;

    let ed25519 = pubkey
        .key_data()
        .ed25519()
        .context("this openssh key is not ED25519")?;

    let vk = VerifyingKey::from_bytes(&ed25519.0)
        .context("could not parse openssh key bytes into an ed25519 Verifying Key")?;

    Ok(vk)
}

fn load_ed25519_openssl_public_key(key_bytes: &[u8]) -> Result<VerifyingKey, anyhow::Error> {
    ed25519_dalek::VerifyingKey::from_public_key_pem(&String::from_utf8_lossy(&key_bytes))
        .context("failed to parse bytes as a PEM OpenSSL public key")
}

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
        Err(anyhow::anyhow!(
            "Supplied signing key was not a valid supported format"
        ))?
    };

    Ok(signing_key)
}

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

fn load_ed25519_openssl_key(key_bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
    let s: &str = std::str::from_utf8(key_bytes).context("not a valid utf8 string")?;
    ed25519_dalek::SigningKey::from_pkcs8_pem(s)
        .context("failed to decode pkcs8 pem bytes from signing key")
}

pub fn read_file_limited<P: AsRef<Path>>(
    path: P,
    max_bytes: u64,
) -> Result<Vec<u8>, anyhow::Error> {
    let size = std::fs::metadata(&path)?.len();

    if size > max_bytes {
        return Err(anyhow::anyhow!(format!(
            "File too large: {} bytes (limit: {} bytes)",
            size, max_bytes
        )));
    }

    let file = std::fs::File::open(path)?;
    let mut buffer = Vec::with_capacity(size as usize);

    std::io::BufReader::new(file)
        .take(max_bytes)
        .read_to_end(&mut buffer)
        .context(anyhow::anyhow!(format!(
            "File too large: {} bytes (limit: {} bytes)",
            size, max_bytes
        )))?;

    Ok(buffer)
}
