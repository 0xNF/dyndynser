use std::borrow::Cow;

use anyhow::Context;

// We are dealing with keys, certificates, and small json files. We wil limit to at most 10kb
const FILE_SIZE_MAX_BYTES: u64 = 10 * 1024;

use crate::{
    config::*,
    dns::{self, Change, route53},
    keys::{self, CertMatch},
    signatures::{self, SignedJSON},
};

// Load all the known .crt files into memory at once
fn get_public_key_map(
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
    signed_json: &SignedJSON<dns::ResourceRecordSet>,
    domain_key_map: &[CertMatch],
) -> Result<(), anyhow::Error> {
    /* Look for Matching Key of domain */
    log::info!(
        "looking for key that matches '{}'",
        &signed_json.payload.name
    );
    let vk = domain_key_map
        .iter()
        .find(|x| x.common_name == signed_json.payload.name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Received ddns request for domain '{}', but no matching key could be found",
                &signed_json.payload.name,
            )
        })?;

    /* if key is found, try to validate the signature */
    vk.verifying_key
        .verify_strict(
            serde_json::to_string_pretty(&signed_json.payload)
                .context("failed to re-serialize during signature check")?
                .as_bytes(),
            signed_json.signature.inner(),
        )
        .context("ddns json signature did not match")?;

    Ok(())
}

pub fn handle_server(
    is_dry_run: bool,
    s3_bucket: &str,
    s3_ddns_json_dir: &str,
    hosted_dns_zone_id: &str,
    keys_search_path: &str,
    region: &str,
) -> Result<(), anyhow::Error> {
    let conf = ConfigServer::parse(
        is_dry_run,
        s3_bucket,
        s3_ddns_json_dir,
        hosted_dns_zone_id,
        keys_search_path,
        region,
    )
    .context("failed to parse server config")?;

    if conf.is_dry_run {
        println!("Performing a server Dry Run");
        log::info!("Doing a dry run, will not actually update the ddns file");
    }

    /* Retrieve all the ddns requests from the s3 bucket */
    let credentials = s3::creds::Credentials::default()?;
    let mut results = fetch_ddns_jsons_from_s3(&conf, &credentials)
        .context("failed to perform S3 read portion of server operation")?;

    /* Check any ddns files to operate over  */
    if results.unverified_jsons.is_empty() {
        println!("No ddns.json files found, nothing to do.");
        return Ok(());
    }
    println!("Found {} .ddns.json files", results.unverified_jsons.len());
    results.unverified_jsons.iter().for_each(|unverified| {
        println!("\t * {}", &unverified.payload.name);
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
            &signed_json.payload.name
        );
        match check_valid_ddns_request(signed_json, &domain_certs)
            .context("failed to check signing key request")
        {
            Ok(_) => {
                log::info!("Validated '{}' domain request", &signed_json.payload.name);
                results.verified_jsons.push(&signed_json.payload);
            }
            Err(e) => {
                log::error!(
                    "Could not validate '{}' request: {:?}",
                    &signed_json.payload.name,
                    e,
                );
                results.failed_signature_checks.push((
                    &signed_json.payload.name,
                    e.context("signature did not pass validation"),
                ));
            }
        }
    }

    let mut changes: Vec<Change> = Vec::with_capacity(results.verified_jsons.len());
    for verified_request in results.verified_jsons.iter() {
        log::debug!(
            "processing validated request for '{}'",
            &verified_request.name
        );

        /* if we're working on Domains (i.e. CNAME, A, AAAA, etc), add the trialing dot for FQDN */
        let record_type = &verified_request.data.record_type();
        let fixed_name = match record_type {
            dns::RecordType::A | dns::RecordType::AAAA => {
                if verified_request.name.ends_with('.') {
                    Cow::Borrowed(&verified_request.name)
                } else {
                    log::debug!("domain didn't end with '.', adding one ourselves");
                    let mut owned = verified_request.name.to_owned();
                    owned.push('.');
                    Cow::Owned(owned)
                }
            }
        };

        let dns_change = Change {
            action: crate::dns::ChangeAction::Upsert,
            record_set: crate::dns::ResourceRecordSet {
                name: fixed_name.into_owned(),
                data: verified_request.data.clone(),
                ttl: verified_request.ttl,
            },
        };
        changes.push(dns_change);
    }

    if conf.is_dry_run {
        println!(
            "Will write these changes to the DNS records:\n\n```json\n{:?}\n```",
            changes
        );
        return Ok(());
    }

    let route53_client = route53::aws_route53::Route53Client::from_s3_credentials(&credentials)
        .context("failed to construct a Route53 Client")?;
    let change_results = route53_client
        .change_resource_record_sets(
            &conf.hosted_dns_zone_id,
            Some("Updated via dyndynser"),
            &changes,
        )
        .context("failed to issue a Route53 update")?;

    log::info!("Updated Route53 DNS records");
    println!(
        "Updated Route53 DNS records:\nrequest id: {}\nrequest status:{}",
        change_results.id, change_results.status
    );

    /* trigger a ddns request automatically via a Process Command */

    results.print_summary();

    Ok(())
}

fn fetch_ddns_jsons_from_s3<'unverified>(
    conf: &'unverified ConfigServer,
    credentials: &s3::creds::Credentials,
) -> Result<RunResults<'unverified>, anyhow::Error> {
    log::info!("Fetching s3 bucket items");
    let mut results = RunResults::new();

    /* S3 set up */
    let region = conf
        .region
        .parse()
        .context("invalid AWS region found during S3 write")?;
    let bucket = s3::Bucket::new(&conf.s3_bucket, region, credentials.clone())
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
            if !x.key.ends_with(dns::ResourceRecordSet::DDNS_JSON_FILE_EXT) {
                eprintln!(
                    "invalid s3 object key, not a ddns '{}' file: '{}'",
                    dns::ResourceRecordSet::DDNS_JSON_FILE_EXT,
                    &x.key
                );
                continue;
            }

            /* Try to deserde into a ddnsjson object */
            match bucket.get_object(&x.key) {
                Ok(response_data) => {
                    match serde_json::from_slice::<SignedJSON<dns::ResourceRecordSet>>(
                        response_data.as_slice(),
                    ) {
                        Ok(ddnsjson) => {
                            log::debug!(
                                "successfully deserde'd key '{}' into a {} object",
                                &x.key,
                                dns::ResourceRecordSet::DDNS_JSON_FILE_EXT
                            );
                            results.unverified_jsons.push(ddnsjson);
                        }
                        Err(e) => {
                            log::error!(
                                "failed to deserde key '{}' into a {} object: {}",
                                &x.key,
                                dns::ResourceRecordSet::DDNS_JSON_FILE_EXT,
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
    unverified_jsons: Vec<SignedJSON<dns::ResourceRecordSet>>,
    verified_jsons: Vec<&'unverified dns::ResourceRecordSet>, // references the unverified_jsons list
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
        println!("dns records adjusted:");
        for verified in self.verified_jsons.iter() {
            println!("\t * {} -> {}", &verified.name, &verified.data)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::{
        dns::{self, ResourceRecordSet},
        keys::{load_ed25519_certificate_pem, read_file_limited},
        server::check_valid_ddns_request,
        signatures::SignedJSON,
    };

    #[test]
    fn sign_and_validate_a_record() {
        let record = ResourceRecordSet {
            name: "augs.sarif.example".to_owned(),
            data: crate::dns::RecordData::A(vec![
                std::net::Ipv4Addr::from_str("192.168.1.1").unwrap(),
            ]),
            ttl: 300,
        };

        /* Load the private key for signing */
        let keybytes = read_file_limited("test/certs/augs.sarif.example.priv", 1400).unwrap();
        let private_key = crate::keys::load_ed25519_private_key(&keybytes, None).unwrap();

        /* Sign the Record */
        let signed_bytes =
            crate::client::DynDynserClient::sign_object(&private_key, record).unwrap();
        let reserded_bytes =
            serde_json::from_slice::<SignedJSON<dns::ResourceRecordSet>>(&signed_bytes).unwrap();

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
            &cert.common_name, &reserded_bytes.payload.name,
            "expected cert.common_name to be same as the reserded_bytes domain request"
        );

        let res = check_valid_ddns_request(&reserded_bytes, &vec![cert]);
        assert!(res.is_ok(), "expected signature to pass validation");
    }
}
