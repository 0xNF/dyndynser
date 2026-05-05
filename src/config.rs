use std::{ops::Deref, time::Duration};

use anyhow::Context;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use crate::cli::{self, ServerArgs};

/// We are dealing with keys, certificates, and small json files. We wil limit to at most 10kb
pub const FILE_SIZE_MAX_BYTES: u64 = 10 * 1024;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainName {
    inner: String,
}
impl DomainName {
    /// Enforces RFC952 and 1123 to check if the given domain is Valid
    /// If a Some, then it is valid. if not, then it is invalid
    pub fn parse(domain_name: &'_ str) -> Result<DomainName, anyhow::Error> {
        let domain_name = domain_name.trim().to_lowercase();
        // Must not be empty and must fit within 253 characters
        if domain_name.is_empty() || domain_name.len() > 253 {
            anyhow::bail!("domain must be between 1 and 253 ascii chars");
        }

        // Allow optional trailing dot (e.g. "example.com.")
        let domain = domain_name.strip_suffix('.').unwrap_or(&domain_name);

        let labels: Vec<&str> = domain.split('.').collect();

        for label in &labels {
            // Each label must be between 1 and 63 characters
            if label.is_empty() || label.len() > 63 {
                anyhow::bail!("domain sub-labels must be between 1-64 characters");
            }

            // Labels cannot start or end with a hyphen
            if label.starts_with('-') || label.ends_with('-') {
                anyhow::bail!("domain sub-label cannot start or end with a hyphen");
            }

            // Labels may only contain ASCII alphanumeric characters and hyphens
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                anyhow::bail!("domain sub-label mnust only be ascii alphanumeric");
            }
        }

        // The TLD (last label) must not be entirely numeric (e.g. ".123" is invalid)
        if labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
        {
            anyhow::bail!("TLD must not be entirely numeric")
        }

        Ok(DomainName { inner: domain_name })
    }
}

impl Deref for DomainName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        return self.inner.as_ref();
    }
}

#[derive(Debug)]
pub struct ConfigClient {
    /// S3 Bucket id to push $domain.json files
    pub s3_bucket: String,

    /// Path on the S3 bucket to place -ddns.json files
    pub s3_bucket_ddns_json_directory: String,

    /// AWS Region, like us-east-1
    pub region: String,

    /// Domain that this client is configured to push for
    pub domain: DomainName,

    /// URL to query for an IP Address
    pub ip_addr_check_url: String,

    /// TTL to mark the record valid for
    pub ttl: Option<Duration>,

    /// Path on filesystem to search for a private ed25519 key to sign with
    pub key_path: String,

    /// whether this run should make mutating changes or not
    pub is_dry_run: bool,
}

impl ConfigClient {
    const DEFAULT_IP_CHECK_URL: &str = "https://checkip.amazonaws.com";

    pub fn parse(args: &cli::ClientArgs) -> Result<Self, anyhow::Error> {
        let s3_bucket = args.s3_bucket.trim();
        let key_path = args.key_path.trim();
        let region = args.aws_region.trim();
        let ddns_json_dir = args.s3_ddns_json_dir.trim();
        let ttl: Option<Duration> = args.ttl.map(|t| Duration::from_secs(t as u64));
        let ip_addr_check_url = args
            .ip_addr_check_url
            .as_deref()
            .unwrap_or(ConfigClient::DEFAULT_IP_CHECK_URL);

        /* Check Empties */
        if s3_bucket.is_empty() {
            anyhow::bail!("S3 Bucket cannot be empty")
        } else if key_path.is_empty() {
            anyhow::bail!("keypath to sign with cannot be empty")
        } else if region.is_empty() {
            anyhow::bail!("Amazon Region cannot be empty")
        } else if ddns_json_dir.is_empty() {
            anyhow::bail!("s3 bucket ddns json path cannot be empty")
        } else if ip_addr_check_url.is_empty() {
            anyhow::bail!("ip check addr cannot be empty")
        }

        /* Check Domain is valid */
        let domain = DomainName::parse(&args.domain)
            .context("domain is invalid, must conform to RFC 1123")?;

        Ok(ConfigClient {
            is_dry_run: args.is_dry_run,
            domain,
            ttl,
            key_path: key_path.to_owned(),
            s3_bucket: s3_bucket.to_owned(),
            s3_bucket_ddns_json_directory: ddns_json_dir.to_owned(),
            region: region.to_owned(),
            ip_addr_check_url: ip_addr_check_url.to_owned(),
        })
    }
}

#[derive(Debug)]
pub struct ConfigServer {
    /// Where to search for authorized public keys on the server
    pub keys_search_path: String,

    /// S3 Bucket id to search for $domain.json files
    pub s3_bucket: String,

    /// Path on the S3 bucket to search for -ddns.json files
    pub s3_bucket_ddns_json_directory: String,

    /// AWS DNS Hosted Zone Id
    pub hosted_dns_zone_id: String,

    /// AWS Region, like us-east-1
    pub region: String,

    /// whether this run should make mutating changes or not
    pub is_dry_run: bool,

    /// How many seconds a Signed object is valid for, to lower the bounds on potential Replay Attacks
    pub max_time_ago_signed_at: TimeDelta,
}

impl ConfigServer {
    pub fn parse(args: &ServerArgs) -> Result<Self, anyhow::Error> {
        let s3_bucket = args.s3_bucket.trim();
        let ddns_json_dir = args.s3_ddns_json_dir.trim();
        let hosted_dns_zone_id = args.hosted_dns_zone_id.trim();
        let keys_search_path = args.keys_search_path.trim();
        let region = args.aws_region.trim();
        let max_time_ago_signed_at = args
            .max_time_ago_signed_at_secs
            .map_or(chrono::TimeDelta::hours(1), |secs| {
                chrono::TimeDelta::seconds(secs as i64)
            });

        /* Check Empties */
        if s3_bucket.is_empty() {
            anyhow::bail!("S3 Bucket cannot be empty")
        } else if hosted_dns_zone_id.is_empty() {
            anyhow::bail!("hosted_dns_zone_id cannot be empty")
        } else if keys_search_path.is_empty() {
            anyhow::bail!("keys search path cannot be empty")
        } else if region.is_empty() {
            anyhow::bail!("Amazon Region cannot be empty")
        } else if ddns_json_dir.is_empty() {
            anyhow::bail!("bucket ddns json path cannot be empty")
        }

        Ok(ConfigServer {
            is_dry_run: args.is_dry_run,
            hosted_dns_zone_id: hosted_dns_zone_id.to_owned(),
            keys_search_path: keys_search_path.to_owned(),
            s3_bucket: s3_bucket.to_owned(),
            s3_bucket_ddns_json_directory: ddns_json_dir.to_owned(),
            region: region.to_owned(),
            max_time_ago_signed_at,
        })
    }
}
