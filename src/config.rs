use std::time::Duration;

use crate::cli::{self, ServerArgs};

#[derive(Debug)]
pub struct ConfigClient {
    // S3 Bucket id to push $domain.json files
    pub s3_bucket: String,

    // Path on the S3 bucket to place -ddns.json files
    pub s3_bucket_ddns_json_directory: String,

    // AWS Region, like us-east-1
    pub region: String,

    // Domain that this client is configured to push for
    pub domain: String,

    // URL to query for an IP Address
    pub ip_addr_check_url: String,

    // TTL to mark the record valid for
    pub ttl: Option<Duration>,

    pub key_path: String,

    // whether this run should make mutating changes or not
    pub is_dry_run: bool,
}

impl ConfigClient {
    const DEFAULT_IP_CHECK_URL: &str = "https://checkip.amazonaws.com";

    pub fn parse(args: &cli::ClientArgs) -> Result<Self, anyhow::Error> {
        let s3_bucket = args.s3_bucket.trim();
        let domain = args.domain.trim();
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
            Err(anyhow::anyhow!("S3 Bucket cannot be empty"))?;
        } else if domain.is_empty() {
            Err(anyhow::anyhow!("subdomain to update cannot be empty"))?;
        } else if key_path.is_empty() {
            Err(anyhow::anyhow!("keypath to sign with cannot be empty"))?;
        } else if region.is_empty() {
            Err(anyhow::anyhow!("Amazon Region cannot be empty"))?;
        } else if ddns_json_dir.is_empty() {
            Err(anyhow::anyhow!("s3 bucket ddns json path cannot be empty"))?;
        } else if ip_addr_check_url.is_empty() {
            Err(anyhow::anyhow!("ip check addr cannot be empty"))?;
        }

        Ok(ConfigClient {
            is_dry_run: args.is_dry_run,
            domain: domain.to_lowercase(),
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
    // Where to search for authorized public keys on the server
    pub keys_search_path: String,

    // S3 Bucket id to search for $domain.json files
    pub s3_bucket: String,

    // Path on the S3 bucket to search for -ddns.json files
    pub s3_bucket_ddns_json_directory: String,

    // AWS DNS Hosted Zone Id
    pub hosted_dns_zone_id: String,

    // AWS Region, like us-east-1
    pub region: String,

    // whether this run should make mutating changes or not
    pub is_dry_run: bool,

    pub max_time_ago_signed_at: Duration,
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
            .map_or(Duration::from_hours(1), |secs| {
                Duration::from_secs(secs as u64)
            });

        /* Check Empties */
        if s3_bucket.is_empty() {
            return Err(anyhow::anyhow!("S3 Bucket cannot be empty"));
        } else if hosted_dns_zone_id.is_empty() {
            return Err(anyhow::anyhow!("hosted_dns_zone_id cannot be empty"));
        } else if keys_search_path.is_empty() {
            return Err(anyhow::anyhow!("keys search path cannot be empty"));
        } else if region.is_empty() {
            Err(anyhow::anyhow!("Amazon Region cannot be empty"))?;
        } else if ddns_json_dir.is_empty() {
            Err(anyhow::anyhow!("bucket ddns json path cannot be empty"))?;
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
