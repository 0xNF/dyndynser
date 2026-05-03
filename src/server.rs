use std::borrow::Cow;

use anyhow::Context;

// We are dealing with keys, certificates, and small json files. We wil limit to at most 10kb
const FILE_SIZE_MAX_BYTES: u64 = 10 * 1024;

use crate::{
    config::*,
    ddns::{self, DDNSRoute53Config, DdnsJSON, DdnsRoute53Record},
    keys::{self, CertMatch},
    signatures::{self, SignedJSON},
};

// Load all the known .crt files into memory at once
fn get_public_key_map<'cert>(
    conf: &ConfigServer,
    results: &mut RunResults,
) -> Result<Vec<CertMatch>, anyhow::Error> {
    let mut v: Vec<CertMatch> = Vec::new();
    /* for each key, accumulate errors. don't fail all just because one key is bad
     * * use the Domain portion to find the corresponding public key
     * * check signature is valid
     * * if valid, put into collected ddns struct
     */

    /* Get list of .crt key files known to this server */
    let list_pub_key_files = std::fs::read_dir(&conf.keys_search_path)
        .context("failed to read known key search path")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let is_file = entry.file_type().map(|ft| ft.is_file()).unwrap_or(false);

            let has_ext = entry
                .path()
                .extension()
                .map(|ext| ext == signatures::PUBLIC_CERT_EXT)
                .unwrap_or(false);

            is_file && has_ext
        });

    /* Parse each byte arr as an X509 Certificate */
    for entry in list_pub_key_files {
        log::debug!("attempting to parse key found at {:?}", &entry.file_name());

        let fbytes = keys::read_file_limited(entry.path(), FILE_SIZE_MAX_BYTES)
            .context("invalid key_path")?;

        let crtmatch = match keys::load_ed25519_certificate_pem(&fbytes)
            .context("failed to load an x509 certifciate from bytes")
        {
            Ok(crt) => crt,
            Err(e) => {
                results
                    .failed_key_parses
                    .push((entry.file_name().to_string_lossy().to_string(), e));
                continue;
            }
        };

        v.push(crtmatch);
    }

    Ok(v)
}

fn check_valid_ddns_request(
    signed_json: &SignedJSON<DdnsJSON>,
    domain_key_map: &Vec<CertMatch>,
) -> Result<(), anyhow::Error> {
    /* Look for Matching Key of domain */
    log::info!(
        "looking for key that matches '{}'",
        &signed_json.payload.domain
    );
    let vk = domain_key_map
        .iter()
        .find(|x| x.common_name == signed_json.payload.domain)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Received ddns request for domain '{}', but no matching key could be found",
                &signed_json.payload.domain,
            )
        })?;

    /* if key is found, try to validate the signature */
    vk.verifying_key
        .verify_strict(
            serde_json::to_string_pretty(&signed_json.payload)
                .context("failed to re-serialize during signature check")?
                .as_bytes(),
            &signed_json.signature.inner(),
        )
        .context("ddns json signature did not match")?;

    Ok(())
}

pub fn handle_server(
    is_dry_run: bool,
    is_s3_delete_after_success: bool,
    s3_bucket: &str,
    s3_ddns_json_dir: &str,
    ddns_file_path: &str,
    keys_search_path: &str,
    region: &str,
) -> Result<(), anyhow::Error> {
    let conf = ConfigServer::parse(
        is_dry_run,
        is_s3_delete_after_success,
        s3_bucket,
        s3_ddns_json_dir,
        ddns_file_path,
        keys_search_path,
        region,
    )
    .context("failed to parse server config")?;

    if conf.is_dry_run {
        println!("Performing a server Dry Run");
        log::info!("Doing a dry run, will not actually update the ddns file");
    }

    /* Retrieve all the ddns requests from the s3 bucket */
    let mut results = fetch_ddns_jsons_from_s3(&conf)
        .context("failed to perform S3 read portion of server operation")?;

    /* Check any ddns files to operate over  */
    if results.unverified_jsons.is_empty() {
        println!("No ddns.json files found, nothing to do.");
        return Ok(());
    }
    println!("Found {} .ddns.json files", results.unverified_jsons.len());
    results.unverified_jsons.iter().for_each(|unverified| {
        println!("\t * {}", &unverified.payload.domain);
    });

    /* Get Keys */
    let domain_certs =
        get_public_key_map(&conf, &mut results).context("failed to get public key map")?;

    log::debug!("known domain keys: {:?}", &domain_certs);

    /* Check Keys exist */
    if domain_certs.is_empty() {
        println!("No public keys found, nothing to validate.");
        return Ok(());
    }

    /* Validate each request by finding a corresponding Public Key */
    for signed_json in results.unverified_jsons.iter() {
        log::info!(
            "Checking signature of '{}' ddns request",
            &signed_json.payload.domain
        );
        match check_valid_ddns_request(&signed_json, &domain_certs)
            .context("failed to check signing key request")
        {
            Ok(_) => {
                log::info!("Validated '{}' domain request", &signed_json.payload.domain);
                results.verified_jsons.push(&signed_json.payload);
            }
            Err(e) => {
                log::error!(
                    "Could not validate '{}' request: {:?}",
                    &signed_json.payload.domain,
                    e,
                );
                results.failed_signature_checks.push((
                    &signed_json.payload.domain,
                    anyhow::Error::from(e).context("signature did not pass validation"),
                ));
            }
        }
    }

    /* read the ddns-route53 config file */
    let contents = std::fs::read_to_string(&conf.ddns_file_path)
        .context("failed to read ddns_route53 ddns config file")?;
    let mut route53_config: DDNSRoute53Config = serde_yaml::from_str(&contents)
        .context("ddns_file_path existed but could not be parsed into a YAML structure")?;

    for valid_request in results.verified_jsons.iter() {
        log::debug!(
            "processing validated request for '{}'",
            &valid_request.domain
        );

        let with_traiing_dot = if valid_request.domain.ends_with('.') {
            Cow::Borrowed(&valid_request.domain)
        } else {
            log::debug!("domain didn't end with '.', adding one ourselves");
            let mut owned = valid_request.domain.to_owned();
            owned.push('.');
            Cow::Owned(owned)
        };

        let new_ddns_record = DdnsRoute53Record {
            name: with_traiing_dot.to_string(),
            record_type: if valid_request.ip.is_ipv4() {
                String::from("A")
            } else if valid_request.ip.is_ipv6() {
                String::from("AAAA")
            } else {
                String::from("?")
            },
            time_to_live: Some(300),
        };

        match route53_config
            .route_53
            .records_set
            .iter()
            .position(|p| p.name == new_ddns_record.name)
        {
            Some(index) => route53_config.route_53.records_set[index] = new_ddns_record,
            None => route53_config.route_53.records_set.push(new_ddns_record),
        }
    }

    let yaml_str = serde_yaml::to_string(&route53_config)
        .context("failed to serialize route53 config back into yaml bytes")?;

    if conf.is_dry_run {
        println!("Will write this yaml:\n```yaml\n{}\n```", yaml_str);
        println!();
        println!(
            "will delete the following s3 bucket items: {:?}",
            results.unverified_jsons
        );
        return Ok(());
    }

    results.print_summary();

    /* Write the valid requests to it, and write file back to disk */

    /* trigger a ddns request automatically via a Process Command */

    // &results.print_summary();

    Ok(())
}

fn fetch_ddns_jsons_from_s3<'unverified>(
    conf: &'unverified ConfigServer,
) -> Result<RunResults<'unverified>, anyhow::Error> {
    log::info!("Fetching s3 bucket items");
    let mut results = RunResults::new();

    /* S3 set up */
    let credentials = s3::creds::Credentials::default()?;
    let region = conf
        .region
        .parse()
        .context("invalid AWS region found during S3 write")?;
    let bucket = s3::Bucket::new(&conf.s3_bucket, region, credentials)
        .context("failed to rerieve s3 credentials")?;

    println!(
        "Querying Bucket: {}/{}",
        &conf.s3_bucket, &conf.s3_bucket_ddns_json_directory
    );

    /* S3 iteration  */
    let mut continuation_token: Option<String> = None;
    let mut iterationcount: usize = 0;
    loop {
        iterationcount += 1;
        log::info!(
            "Fetching s3 page {}, continuation token: {:?}",
            iterationcount,
            continuation_token
        );
        let (list_result, _status_code) = bucket
            .list_page(
                conf.s3_bucket_ddns_json_directory.clone(),
                Some(String::from("/")),
                continuation_token,
                None,
                None,
            )
            .context("failed to list contents of s3 bucket")?;

        log::debug!(
            "Successfully fetched s3 page #{} ({} items)",
            iterationcount,
            &list_result.contents.len()
        );

        for x in &list_result.contents {
            /* Check key is an expected .ddns.json request file */
            if !x.key.ends_with(ddns::DdnsJSON::DDNS_JSON_FILE_EXT) {
                eprintln!(
                    "invalid s3 object key, not a ddns '{}' file: '{}'",
                    ddns::DdnsJSON::DDNS_JSON_FILE_EXT,
                    &x.key
                );
                continue;
            }

            /* Try to deserde into a ddnsjson object */
            match bucket.get_object(&x.key) {
                Ok(response_data) => {
                    match serde_json::from_slice::<SignedJSON<DdnsJSON>>(response_data.as_slice()) {
                        Ok(ddnsjson) => {
                            log::debug!(
                                "successfully deserde'd key '{}' into a {} object",
                                &x.key,
                                ddns::DdnsJSON::DDNS_JSON_FILE_EXT
                            );
                            results.unverified_jsons.push(ddnsjson);
                        }
                        Err(e) => {
                            log::error!(
                                "failed to deserde key '{}' into a {} object: {}",
                                &x.key,
                                ddns::DdnsJSON::DDNS_JSON_FILE_EXT,
                                e,
                            );
                            results.failed_json_deserdes.push((
                                x.key.to_owned(),
                                anyhow::Error::from(e)
                                    .context("failed to derialize into a DdnsJson object"),
                            ));
                        }
                    }
                }
                Err(e) => {
                    results.failed_s3_fetches.push((
                        x.key.to_owned(),
                        anyhow::Error::from(e)
                            .context(format!("failed to Get S3 Object for key {}", x.key)),
                    ));
                }
            }
            // process each object
        }

        // Check if there are more pages
        match list_result.next_continuation_token {
            Some(token) => continuation_token = Some(token),
            None => break,
        }
    }
    log::debug!("Finished iterating pages on s3 bucket");

    Ok(results)
}

// Holds both accumulating non-blocking failures, as well as the Signature-Verified Ddns Json objects
struct RunResults<'unverified> {
    failed_s3_fetches: Vec<(String, anyhow::Error)>,
    failed_json_deserdes: Vec<(String, anyhow::Error)>,
    failed_signature_checks: Vec<(&'unverified str, anyhow::Error)>, // references the unverifid_jsons list
    failed_key_parses: Vec<(String, anyhow::Error)>,
    unverified_jsons: Vec<SignedJSON<DdnsJSON>>,
    verified_jsons: Vec<&'unverified DdnsJSON>, // references the unverified_jsons list
}
impl<'ltself> RunResults<'ltself> {
    fn new() -> Self {
        Self {
            unverified_jsons: Vec::new(),
            verified_jsons: Vec::new(),
            failed_s3_fetches: Vec::new(),
            failed_json_deserdes: Vec::new(),
            failed_signature_checks: Vec::new(),
            failed_key_parses: Vec::new(),
        }
    }

    fn print_summary(&self) {
        println!("Summary\n-------");
        if !self.failed_s3_fetches.is_empty() {
            println!("Failed S3 Fetches:");
            for fail in &self.failed_s3_fetches {
                println!("\t *{}: {:#?}", fail.0, fail.1);
            }
        }
        if !self.failed_json_deserdes.is_empty() {
            println!("Failed JSON Deserializations:");
            for fail in &self.failed_json_deserdes {
                println!("\t *{}: {:#?}", fail.0, fail.1);
            }
        }
        if !self.failed_key_parses.is_empty() {
            println!("Failed Signing Key Parses:");
            for fail in &self.failed_key_parses {
                println!("\t *{}: {:#?}", fail.0, fail.1);
            }
        }
        if !self.failed_signature_checks.is_empty() {
            println!("Failed Signature Checks:");
            for fail in &self.failed_signature_checks {
                println!("\t *{}: {:#?}", fail.0, fail.1);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::{
        ddns::DdnsJSON,
        keys::{load_ed25519_certificate_pem, read_file_limited},
        server::check_valid_ddns_request,
        signatures::SignedJSON,
    };

    #[test]
    fn sign_and_validate_a_record() {
        let record = DdnsJSON {
            domain: "augs.sarif.example".to_owned(),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from_str("192.168.1.1").unwrap()),
            ttl: None,
        };

        /* Load the private key for signing */
        let keybytes = read_file_limited("test/certs/augs.sarif.example.priv", 1400).unwrap();
        let private_key = crate::keys::load_ed25519_private_key(&keybytes, None).unwrap();

        /* Sign the Record */
        let signed_bytes = crate::client::sign_object(&private_key, record).unwrap();
        let reserded_bytes = serde_json::from_slice::<SignedJSON<DdnsJSON>>(&signed_bytes).unwrap();

        /* Load the public key for validating */
        let certbytes = read_file_limited("test/certs/augs.sarif.example.crt", 1400);
        assert!(
            certbytes.is_ok(),
            "expected to read certificate file bytes from file underneath 1024kb limit",
        );
        let certbytes = certbytes.unwrap();
        let cert = load_ed25519_certificate_pem(&certbytes);
        assert!(
            cert.is_ok(),
            "expected augs.sarif.example.crt to be loaded as an x509 cert file"
        );
        let cert = cert.unwrap();
        assert_eq!(
            &cert.common_name, "augs.sarif.example",
            "expected common name of cert to augs.sarif.example"
        );

        assert_eq!(
            &cert.common_name, &reserded_bytes.payload.domain,
            "expected cert.common_name to be same as the reserded_bytes domain request"
        );

        let res = check_valid_ddns_request(&reserded_bytes, &vec![cert]);
        assert!(res.is_ok(), "expected signature to pass validation");
    }
}
