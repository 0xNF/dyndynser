use anyhow::Context;
use ed25519_dalek::SECRET_KEY_LENGTH;

#[derive(Debug)]
pub struct ConfigClient {
    // S3 Bucket id to push $domain.json files
    pub s3_robocerts_bucket: String,

    // Path on the S3 bucket to place -ddns.json files
    pub s3_robocerts_ddns_json_directory: String,

    // AWS Region, like us-east-1
    pub region: String,

    // Domain that this client is configured to push for
    pub domain: String,

    // private key file to sign .json files with
    pub signing_key: ed25519_dalek::SigningKey,
}

impl ConfigClient {
    pub fn parse(
        robocerts_bucket: &str,
        ddns_json_dir: &str,
        domain: &str,
        key_path: &str,
        region: &str,
    ) -> Result<Self, anyhow::Error> {
        let robocerts_bucket = robocerts_bucket.trim();
        let domain = domain.trim();
        let key_path = key_path.trim();
        let region = region.trim();
        let ddns_json_dir = ddns_json_dir.trim();

        /* Check Empties */
        if robocerts_bucket.is_empty() {
            Err(anyhow::anyhow!("Robocerts S3 Bucket cannot be empty"))?;
        } else if domain.is_empty() {
            Err(anyhow::anyhow!("subdomain to update cannot be empty"))?;
        } else if key_path.is_empty() {
            Err(anyhow::anyhow!("keypath to sign with cannot be empty"))?;
        } else if region.is_empty() {
            Err(anyhow::anyhow!("Amazon Region cannot be empty"))?;
        } else if ddns_json_dir.is_empty() {
            Err(anyhow::anyhow!("Robocerts ddns json path cannot be empty"))?;
        }

        /* Find and load the keyfile bytes */
        let key_bytes = std::fs::read(key_path).context("Invalid key_path")?;

        if key_bytes.len() != ed25519_dalek::SECRET_KEY_LENGTH {
            Err(anyhow::anyhow!(
                "ed25519 signing key is invalid length: {}",
                key_bytes.len()
            ))?;
        }
        let arr: &[u8; SECRET_KEY_LENGTH] = key_bytes.as_array().ok_or(anyhow::anyhow!(
            "invalid secret key length after unwrap, this is likely a bug"
        ))?;
        let key = ed25519_dalek::SigningKey::from_bytes(arr);

        Ok(ConfigClient {
            domain: domain.to_lowercase(),
            signing_key: key,
            s3_robocerts_bucket: robocerts_bucket.to_owned(),
            s3_robocerts_ddns_json_directory: ddns_json_dir.to_owned(),
            region: region.to_owned(),
        })
    }
}

#[derive(Debug)]
pub struct ConfigServer {
    // Where to search for authorized public keys on the server
    pub keys_search_path: String,

    // Where to read/write the ddns yaml file
    pub ddns_file_path: String,

    // S3 Bucket id to search for $domain.json files
    pub s3_robocerts_bucket: String,

    // Path on the S3 bucket to search for -ddns.json files
    pub s3_robocerts_ddns_json_directory: String,

    // AWS Region, like us-east-1
    pub region: String,
}

impl ConfigServer {
    pub fn parse(
        robocerts_bucket: &str,
        ddns_json_dir: &str,

        ddns_file_path: &str,
        keys_search_path: &str,
        region: &str,
    ) -> Result<Self, anyhow::Error> {
        let robocerts_bucket = robocerts_bucket.trim();
        let ddns_json_dir = ddns_json_dir.trim();
        let ddns_file_path = ddns_file_path.trim();
        let keys_search_path = keys_search_path.trim();
        let region = region.trim();

        /* Check Empties */
        if robocerts_bucket.is_empty() {
            return Err(anyhow::anyhow!("Robocerts S3 Bucket cannot be empty"));
        } else if ddns_file_path.is_empty() {
            return Err(anyhow::anyhow!("ddns_file_path cannot be empty"));
        } else if keys_search_path.is_empty() {
            return Err(anyhow::anyhow!("keys search path cannot be empty"));
        } else if region.is_empty() {
            Err(anyhow::anyhow!("Amazon Region cannot be empty"))?;
        } else if ddns_json_dir.is_empty() {
            Err(anyhow::anyhow!("Robocerts ddns json path cannot be empty"))?;
        }

        Ok(ConfigServer {
            ddns_file_path: ddns_file_path.to_owned(),
            keys_search_path: keys_search_path.to_owned(),
            s3_robocerts_bucket: robocerts_bucket.to_owned(),
            s3_robocerts_ddns_json_directory: ddns_json_dir.to_owned(),
            region: region.to_owned(),
        })
    }
}

#[derive(Debug)]
pub enum Config {
    Client(ConfigClient),
    Server(ConfigServer),
}
