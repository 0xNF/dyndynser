use anyhow::Context;

use crate::keys;

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

    // whether this run should make mutating changes or not
    pub is_dry_run: bool,
}

impl ConfigClient {
    pub fn parse(
        is_dry_run: bool,
        robocerts_bucket: &str,
        ddns_json_dir: &str,
        domain: &str,
        key_path: &str,
        signing_key_password: Option<&str>,
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
        let key_bytes = keys::read_file_limited(key_path, 10 * 1024).context("invalid key_path")?; // 10kb at most, to maybe account for RSA8192?
        let signing_key = keys::load_ed25519_private_key(&key_bytes, signing_key_password)?;

        Ok(ConfigClient {
            is_dry_run,
            domain: domain.to_lowercase(),
            signing_key,
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
    pub s3_bucket_ddns_json_directory: String,

    // AWS Region, like us-east-1
    pub region: String,

    // whether this run should make mutating changes or not
    pub is_dry_run: bool,

    // if true, s3 ddns.json files used to construct a new route53-ddns.json object will be deleted from the s3 bucket
    //
    // objects that resulted in an will remain in-place
    pub is_s3_delete_after_success: bool,
}

impl ConfigServer {
    pub fn parse(
        is_dry_run: bool,
        is_s3_delete_after_success: bool,

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
            is_dry_run,
            is_s3_delete_after_success,
            ddns_file_path: ddns_file_path.to_owned(),
            keys_search_path: keys_search_path.to_owned(),
            s3_robocerts_bucket: robocerts_bucket.to_owned(),
            s3_bucket_ddns_json_directory: ddns_json_dir.to_owned(),
            region: region.to_owned(),
        })
    }
}

#[cfg(test)]
mod test {
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    use crate::keys;

    #[test]
    fn test_load_private_ed25519_openssl_key() {
        const KEY: &str = "-----BEGIN PRIVATE KEY-----
lol/fixme
-----END PRIVATE KEY-----";
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(KEY);
        assert!(signing_key.is_ok(), "should have gotten a signing key");
        println!("{:?}", signing_key);
    }

    #[test]
    fn t2() {
        const CERT: &str = "-----BEGIN CERTIFICATE-----
MIICozCCAgWgAwIBAgIId7SmsKcLikwwCgYIKoZIzj0EAwMwgcIxCzAJBgNVBAYT
AkpQMQ4wDAYDVQQIEwVUb2t5bzEQMA4GA1UEBxMHU2hpYnV5YTEcMBoGA1UEChMT
QXN0ZXJpYSBDb3Jwb3JhdGlvbjEYMBYGA1UECxMPR3JhdmlvIFJvYm90aWNzMS0w
KwYDVQQDEyRHcmF2aW8gUm9ib3RpY3MgRzEgU3ViLUNBIGdyYXZpby5jb20xKjAo
BgkqhkiG9w0BCQEWG3NlY3VyaXR5QGdyYXZpb3JvYm90aWNzLmNvbTAeFw0yNjA1
MDIwODUxMDBaFw00MTA1MDIwODUxMDBaMIG6MQswCQYDVQQGEwJKUDEOMAwGA1UE
CBMFVG9reW8xEDAOBgNVBAcTB1NoaWJ1eWExGDAWBgNVBAoTD0dyYXZpbyBSb2Jv
dGljczEdMBsGA1UECxMUSW5mb3JtYXRpb24gU2VjdXJpdHkxJDAiBgNVBAMTGzAz
OTY0Njk2LmdyYXZpb3JvYm90aWNzLmNvbTEqMCgGCSqGSIb3DQEJARYbc2VjdXJp
dHlAZ3Jhdmlvcm9ib3RpY3MuY29tMCowBQYDK2VwAyEALh18LjZhLYgHl8I8V8z+
cwcEhvqy/A79LKxC5yFoa6GjGjAYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMAoG
CCqGSM49BAMDA4GLADCBhwJCAXWwBKrHGz+4mmHLPViBe5TcLNmY5JN7FOBJBOjN
zTalVEXAolmjpr45heEWSBnuhhhPahk/59wapIsmUtMbdFhEAkF8PfX3npAz7pmG
ehwiEszuAfzsI5kAn6xnfy67Oqm7Y++F4/Ga+2ZviYFaDlmAR2IUqw4jcU8uyc3b
eMuhW+wTWQ==
-----END CERTIFICATE-----
";

        let certmatch = keys::load_ed25519_certificate_pem(CERT.as_bytes());
        assert!(certmatch.is_ok());
        let certmatch = certmatch.unwrap();
        assert_eq!("03964696.graviorobotics.com", certmatch.common_name);
    }
}
