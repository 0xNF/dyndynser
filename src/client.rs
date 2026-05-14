use std::str::FromStr;

use anyhow::Context;

use reqwest::{self, StatusCode};

use crate::cli;
use crate::config;
use crate::config::ConfigClient;
use crate::dns;
use crate::keys;
use crate::signatures;
use crate::unix;

pub struct DynDynserClient<'a> {
    conf: &'a ConfigClient,
}

impl<'a> DynDynserClient<'a> {
    /// Constructs a DyndynserClient with the given config
    pub fn with_config(conf: &'a ConfigClient) -> Self {
        Self { conf }
    }

    /// Queries a canonical Amazon AWS url for the IP of the machine running this binary
    pub fn query_for_ip(&self) -> Result<std::net::IpAddr, anyhow::Error> {
        let res = reqwest::blocking::get(&self.conf.ip_addr_check_url)
            .context("failed to check IP address")?;
        if res.status() != StatusCode::OK {
            log::error!("IP Query returned non-200 err code: {}", res.status());
            anyhow::bail!("IP query returned non-200 status");
        }

        let res = res
            .bytes()
            .context("could not read IP request body bytes")?;

        log::debug!("got ip query result");

        let bytes = res.trim_ascii();
        let s = String::from_utf8_lossy(bytes);
        let ip_addr = std::net::IpAddr::from_str(&s)
            .with_context(|| format!("failed to convert IP address, returned {}", s))?;

        log::info!("Got machine IP: {}", &ip_addr);

        Ok(ip_addr)
    }
}

/// In client mode, we query the IP of the running machine, create and sign a DDNS payload object for the domain, then push it to S3
pub fn handle_client(args: cli::ClientArgs) -> Result<(), anyhow::Error> {
    log::info!("parsing Client Config");
    let conf = ConfigClient::parse(args).context("failed to parse Client config")?;

    let dyndynser = DynDynserClient::with_config(&conf);

    if conf.is_dry_run {
        log::info!("Doing a dry run, will not make any mutating changes or API calls");
    }

    /* Check if the key location is privelidged or not, in which case this is a Sudo-required operation */
    //
    // Three outcomes:
    //   a) We're root          → succeeds, drop after
    //   b) We're not root but  → succeeds (e.g. file is world-readable,
    //      it works anyway
    //                             skip drop
    //   c) We're not root and  → EACCES/EPERM → "must be root" + exit
    //      it fails

    /* Find and load the keyfile bytes */
    log::info!("Starting priveliged operations, will drop privs after");
    let key_bytes = keys::read_file_limited(&conf.key_path, config::FILE_SIZE_MAX_BYTES)
        .context("invalid key_path")?; // 10kb at most, to maybe account for RSA8192?
    log::info!("Priveliged operations are over, attempting to drop privs now");
    unix::maybe_drop_privileges(&conf.drop_user).context("failed to drop privileges")?;
    let signing_key =
        keys::load_ed25519_private_key(&key_bytes, conf.signing_key_password.as_deref())?;

    /* Get IP */
    log::info!("Querying for machine's IP addr");
    let ip = dyndynser
        .query_for_ip()
        .context("failed to get IP address of this machine")?;

    /* Create and sign the DDNS struct json */
    let dns_obj = &dns::ResourceRecordSet {
        ttl: conf.ttl.map_or(300, |d| d.as_secs() as u32),
        name: (*conf.domain).to_owned(),
        data: match ip {
            std::net::IpAddr::V4(ipv4_addr) => dns::RecordData::A(vec![ipv4_addr]),
            std::net::IpAddr::V6(ipv6_addr) => dns::RecordData::AAAA(vec![ipv6_addr]),
        },
    };

    let signable = signatures::SignableEnvelope::new(dns_obj);
    let signed_json_bytes = signable
        .sign(&signing_key)
        .context("Failed to sign payload object")?;

    /* Send to S3 */
    let ddns_json_path = format!(
        "{}/{}",
        conf.s3_ddns_json_directory,
        dns_obj.make_filename()
    );

    if conf.is_dry_run {
        println!(
            "Will write to: s3://{}{}\nJSON:\n{}",
            conf.s3_queue_bucket,
            ddns_json_path,
            String::from_utf8_lossy(&signed_json_bytes)
        );
    } else {
        log::info!("Invoking S3 for file upload");

        let region = conf
            .aws_config
            .region
            .parse()
            .context("invalid AWS region found during S3 write")?;
        let credentials = conf.aws_config.get_s3_credentials()?;
        let bucket = s3::Bucket::new(&conf.s3_queue_bucket, region, credentials)?;

        let s3_response = bucket
            .put_object_with_content_type(&ddns_json_path, &signed_json_bytes, "application/json")
            .context("failed to put S3 object")?;
        if s3_response.status_code() != 200 {
            anyhow::bail!("s3 returned non-200")
        }
        log::info!("Successfully uploaded S3 ddns json: {}", s3_response);

        println!(
            "Successfully wrote domain request for '{}' to s3 bucket.\nFile key: {}",
            dns_obj.name, ddns_json_path,
        );
    }
    Ok(())
}
