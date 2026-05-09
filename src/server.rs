use std::{borrow::Cow, fmt::Display};

use anyhow::Context;
use chrono::TimeDelta;
use ed25519_dalek::VerifyingKey;

use crate::{
    cli,
    config::*,
    dns::{self, Change, ChangeInfo, ResourceRecordSet, route53},
    keys::{self, CertMatch},
    signatures::{self, SignedPayload},
};

#[derive(Debug, Clone)]
struct S3Key(String);

impl From<&str> for S3Key {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for S3Key {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Display for S3Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

struct DynDynserServer<'a> {
    conf: &'a ConfigServer,
    credentials: &'a s3::creds::Credentials,
}

/// An unverified ddns request, which is structurally sound, but has not yet passed signature validation
///
/// call the `validate()` method to get a Validated, safe to use struct
#[derive(Debug)]
struct UnverifiedDdnsRequest {
    pub signed_payload: SignedPayload<ResourceRecordSet>,
    pub s3_key: S3Key,
}

impl UnverifiedDdnsRequest {
    pub fn validate(
        &'_ self,
        vk: VerifyingKey,
        max_time_ago: chrono::TimeDelta,
    ) -> Result<VerifiedDdnsRequest<'_>, anyhow::Error> {
        /* if key is found, try to validate the signature */
        vk.verify_strict(
            &serde_json_canonicalizer::to_vec(&self.signed_payload.envelope)
                .context("failed to re-serialize during signature check")?,
            self.signed_payload.signature.inner(),
        )
        .context("ddns json signature did not match")?;

        let signed_at = chrono::DateTime::from_timestamp(
            self.signed_payload.envelope.signed_at_unix_secs,
            0,
        )
        .ok_or_else(|| anyhow::anyhow!("could not construct a timestamp for this envelope"))?;

        let tolerance = chrono::Duration::seconds(15); /* Clock Drift */

        let max_age_permitted = signed_at + max_time_ago + tolerance;
        let now = chrono::Utc::now();
        if max_age_permitted < now {
            anyhow::bail!(
                "Signature is too old (age: {}s, max: {}s)",
                (now - signed_at).num_seconds(),
                max_time_ago.num_seconds(),
            );
        }

        let verified = VerifiedDdnsRequest {
            resource_record: &self.signed_payload.envelope.payload,
            s3_key: &self.s3_key,
        };

        Ok(verified)
    }
}

/// A cryptographically validated Ddns request
///
/// Items of this type are only constructable by the `validate()` method on an Unverified struct with a matching key
/// and can thus be taken as confirmed safe.
struct VerifiedDdnsRequest<'a> {
    pub resource_record: &'a ResourceRecordSet,
    pub s3_key: &'a S3Key,
}

impl<'a> DynDynserServer<'a> {
    /// Instantiates the Server with the given configurtion
    fn with_config(conf: &'a ConfigServer, s3_creds: &'a s3::creds::Credentials) -> Self {
        Self {
            conf,
            credentials: s3_creds,
        }
    }

    /// Returns the configured S3 Bucket as Rust object
    fn get_s3_bucket(&self) -> Result<Box<s3::Bucket>, anyhow::Error> {
        let region = self
            .conf
            .aws_config
            .region
            .parse()
            .context("invalid AWS region found during S3 write")?;
        s3::Bucket::new(&self.conf.s3_bucket, region, self.credentials.clone())
            .context("failed to retrieve s3 credentials")
    }

    /// Loads S3 and retrievs all the .ddns.json files found
    ///
    /// Paginates over S3, so can in theory support very large item counts
    fn fetch_ddns_jsons_from_s3(
        &self,
    ) -> Result<(Vec<UnverifiedDdnsRequest>, ServerErrors), anyhow::Error> {
        log::info!("Fetching s3 bucket items");
        let mut errors = ServerErrors::new();
        let mut unverified_requests: Vec<UnverifiedDdnsRequest> = Vec::new();

        /* S3 set up */
        let bucket = self.get_s3_bucket().context("failed to get S3 bucket")?;

        println!(
            "Querying Bucket: {}/{}",
            &self.conf.s3_bucket, &self.conf.s3_bucket_ddns_json_directory
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
                    self.conf.s3_bucket_ddns_json_directory.clone(),
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
                    log::warn!(
                        "invalid s3 object key, not a ddns '{}' file: '{}'",
                        dns::ResourceRecordSet::DDNS_JSON_FILE_EXT,
                        &x.key,
                    );
                    continue;
                }

                /* Try to deserde into a ddnsjson object */
                match bucket.get_object(&x.key) {
                    Ok(response_data) => {
                        match serde_json::from_slice::<SignedPayload<dns::ResourceRecordSet>>(
                            response_data.as_slice(),
                        ) {
                            Ok(ddnsjson) => {
                                log::debug!(
                                    "successfully deserde'd key '{}' into a {} object",
                                    &x.key,
                                    dns::ResourceRecordSet::DDNS_JSON_FILE_EXT
                                );
                                unverified_requests.push(UnverifiedDdnsRequest {
                                    signed_payload: ddnsjson,
                                    s3_key: S3Key(x.key.clone()),
                                });
                            }
                            Err(e) => {
                                log::error!(
                                    "failed to deserde key '{}' into a {} object: {}",
                                    &x.key,
                                    dns::ResourceRecordSet::DDNS_JSON_FILE_EXT,
                                    e,
                                );
                                errors.failed_json_parses.push((
                                    S3Key(x.key.clone()),
                                    anyhow::Error::from(e)
                                        .context("failed to deserialize into a DdnsJson object"),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        errors.failed_s3_fetches.push((
                            x.key.clone().into(),
                            anyhow::Error::from(e).context("failed to Get S3 Object"),
                        ));
                    }
                }
                /* process each object */
            }

            /* Check if there are more pages */
            match list_result.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }
        log::debug!("Finished iterating pages on s3 bucket");

        Ok((unverified_requests, errors))
    }

    /// Load all the known .crt files into memory at once
    fn get_public_key_map(
        &self,
        errors: &mut ServerErrors,
    ) -> Result<Vec<CertMatch>, anyhow::Error> {
        let mut v: Vec<CertMatch> = Vec::new();

        /* for each key, accumulate errors. don't fail all just because one key is bad
         * * use the Domain portion to find the corresponding public key
         * * check signature is valid
         * * if valid, put into collected ddns struct
         */

        /* Get list of .crt key files known to this server */
        let list_pub_key_files = std::fs::read_dir(&self.conf.keys_search_path)
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
                .context("failed to load an x509 certificate from bytes")
            {
                Ok(crt) => crt,
                Err(e) => {
                    errors
                        .failed_key_parses
                        .push((entry.file_name().to_string_lossy().to_string(), e));
                    continue;
                }
            };

            v.push(crtmatch);
        }

        Ok(v)
    }

    /// Validate each request by finding a corresponding Public Key
    ///
    /// Puts errors into the `errors` struct
    fn validate_unverified_dns_requests(
        &self,
        domain_certs: &[CertMatch],
        unverified_ddns_requests: &'a [UnverifiedDdnsRequest],
        errors: &mut ServerErrors,
    ) -> Vec<VerifiedDdnsRequest<'a>> {
        let mut verified_requests: Vec<VerifiedDdnsRequest<'a>> =
            Vec::with_capacity(unverified_ddns_requests.len());

        /* Validate each request by finding a corresponding Public Key */
        for unverified_request in unverified_ddns_requests.iter() {
            log::info!(
                "Checking signature of '{}' ddns request",
                &unverified_request.signed_payload.envelope.payload.name
            );
            match DynDynserServer::check_valid_ddns_request(
                unverified_request,
                domain_certs,
                self.conf.max_time_ago_signed_at,
            )
            .context("failed to check signing key request")
            {
                Ok(verified) => {
                    log::info!(
                        "Validated '{}' domain request",
                        &unverified_request.signed_payload.envelope.payload.name
                    );
                    verified_requests.push(verified);
                }
                Err(e) => {
                    log::error!(
                        "Could not validate '{}' request: {:?}",
                        &unverified_request.signed_payload.envelope.payload.name,
                        e,
                    );
                    errors.failed_signature_checks.push((
                        unverified_request
                            .signed_payload
                            .envelope
                            .payload
                            .name
                            .to_owned(),
                        e.context("signature did not pass validation"),
                    ));
                }
            }
        }

        verified_requests
    }

    /// Cryptogprahically validates an unverified Ddns request
    fn check_valid_ddns_request(
        unverified_request: &'a UnverifiedDdnsRequest,
        domain_key_map: &[CertMatch],
        max_time_ago: TimeDelta,
    ) -> Result<VerifiedDdnsRequest<'a>, anyhow::Error> {
        /* Look for Matching Key of domain */
        log::info!(
            "looking for key that matches '{}'",
            &unverified_request.signed_payload.envelope.payload.name
        );
        let matching_certificate = domain_key_map
            .iter()
            .find(|x| x.common_name == unverified_request.signed_payload.envelope.payload.name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Received ddns request for domain '{}', but no matching key could be found",
                    &unverified_request.signed_payload.envelope.payload.name,
                )
            })?;

        /* if key is found, try to validate the signature */

        matching_certificate
            .verifying_key
            .verify_strict(
                &serde_json_canonicalizer::to_vec(&unverified_request.signed_payload.envelope)
                    .context("failed to re-serialize during signature check")?,
                unverified_request.signed_payload.signature.inner(),
            )
            .context("ddns json signature did not match")?;

        unverified_request
            .validate(matching_certificate.verifying_key, max_time_ago)
            .context("Did not successfully validate the request")
    }

    /// Constructs a Changeset that can be applied to Route53.
    ///
    /// This method is functionally pure
    fn build_changes(verified_ddns_requests: &[VerifiedDdnsRequest]) -> Vec<Change> {
        let mut changes: Vec<Change> = Vec::with_capacity(verified_ddns_requests.len());
        for verified_request in verified_ddns_requests.iter() {
            log::debug!(
                "processing validated request for '{}'",
                &verified_request.resource_record.name
            );

            /* if we're working on Domains (i.e. CNAME, A, AAAA, etc), add the trialing dot for FQDN */
            let record_type = &verified_request.resource_record.data.record_type();
            let fixed_name = match record_type {
                dns::RecordType::A | dns::RecordType::AAAA => {
                    if verified_request.resource_record.name.ends_with('.') {
                        Cow::Borrowed(&verified_request.resource_record.name)
                    } else {
                        log::debug!("domain didn't end with '.', adding one ourselves");
                        let mut owned = verified_request.resource_record.name.to_owned();
                        owned.push('.');
                        Cow::Owned(owned)
                    }
                }
            };

            let dns_change = Change {
                action: crate::dns::ChangeAction::Upsert,
                record_set: crate::dns::ResourceRecordSet {
                    name: fixed_name.into_owned(),
                    data: verified_request.resource_record.data.clone(),
                    ttl: verified_request.resource_record.ttl,
                },
            };
            changes.push(dns_change);
        }

        changes
    }

    /// Applyes the DNS changseset to Route53
    fn commit_changes(&self, changes: &[Change]) -> Result<ChangeInfo, anyhow::Error> {
        let route53_client =
            route53::aws_route53::Route53Client::from_s3_credentials(self.credentials)
                .context("failed to construct a Route53 Client")?;
        let change_results = route53_client
            .change_resource_record_sets(
                &self.conf.hosted_dns_zone_id,
                Some("Updated via dyndynser"),
                changes,
            )
            .context("failed to issue a Route53 update")?;

        Ok(change_results)
    }

    /// Deletes the given s3_keys from the configured s3 bucket
    fn cleanup(&self, s3_keys: Vec<S3Key>, errors: &mut ServerErrors) -> Result<(), anyhow::Error> {
        let bucket = self.get_s3_bucket().context("failed to get S3 bucket")?;

        for s3_key in s3_keys {
            match bucket
                .delete_object(&s3_key.0)
                .context("failed to delete S3 Key")
            {
                Ok(res) => {
                    if res.status_code() < 200 || res.status_code() >= 300 {
                        println!("Failed to S3 bucket item {}", &s3_key);

                        errors.failed_s3_deletions.push((
                            s3_key,
                            anyhow::anyhow!("got non-200 status code: {}", res.status_code()),
                        ));
                    }
                }
                Err(e) => errors.failed_s3_deletions.push((s3_key, e)),
            }
        }

        Ok(())
    }
}

/// Runs the Server process
pub fn handle_server(server_args: &cli::ServerArgs) -> Result<(), anyhow::Error> {
    let conf = ConfigServer::parse(server_args).context("failed to parse server config")?;

    /* Retrieve all the ddns requests from the s3 bucket */
    let credentials = s3::creds::Credentials::default()?;

    let dyndynser = DynDynserServer::with_config(&conf, &credentials);

    if conf.is_dry_run {
        println!("Performing a server Dry Run");
        log::info!("Doing a dry run, will not actually update the ddns file");
    }

    /* Step 1: Fetch Unverified Requests */

    let (unverified_ddns_requests, mut errors) = dyndynser
        .fetch_ddns_jsons_from_s3()
        .context("failed to query S3 for outstanding ddns requests")?;

    /* Check any ddns files to operate over  */
    if unverified_ddns_requests.is_empty() {
        println!("No ddns.json files found, nothing to do.");
        return Ok(());
    }
    println!("Found {} .ddns.json files", unverified_ddns_requests.len());
    unverified_ddns_requests.iter().for_each(|unverified| {
        println!("\t * {}", &unverified.signed_payload.envelope.payload.name);
    });

    /* Step 2: Validate the requests */

    /* Get Keys */
    let domain_certs = dyndynser
        .get_public_key_map(&mut errors)
        .context("failed to get public key map")?;
    log::debug!("known domain keys: {:?}", &domain_certs);

    /* Check Keys exist */
    if domain_certs.is_empty() {
        println!("No public keys found, nothing to validate.");
        return Ok(());
    }

    let verified_ddns_requests = dyndynser.validate_unverified_dns_requests(
        &domain_certs,
        &unverified_ddns_requests,
        &mut errors,
    );

    if verified_ddns_requests.is_empty() {
        println!("No verified requests found, nothing to do.");
        return Ok(());
    }

    /* Step 3: Build the DNS Changes */
    let changes = DynDynserServer::build_changes(&verified_ddns_requests);

    let delete_keys: Vec<S3Key> = verified_ddns_requests
        .iter()
        .map(|v| v.s3_key.to_owned().clone())
        .chain(
            errors
                .failed_s3_fetches
                .iter()
                .map(|e| e.0.to_owned().clone()),
        )
        .chain(
            errors
                .failed_json_parses
                .iter()
                .map(|e| e.0.to_owned().clone()),
        )
        .collect();

    if conf.is_dry_run {
        println!(
            "Will write these changes to the DNS records:\n\n```json\n{:?}\n```",
            changes
        );
        println!(
            "Will delete the following keys from the s3 bucket:\n{:?}",
            delete_keys,
        );
        return Ok(());
    }

    let change_results = dyndynser
        .commit_changes(&changes)
        .context("failed to commit dns changes")?;

    log::info!("Updated Route53 DNS records");
    println!(
        "Updated Route53 DNS records:\nrequest id: {}\nrequest status:{}",
        change_results.id, change_results.status
    );

    log::info!("Claning up used and invalid ddns request keys");

    dyndynser
        .cleanup(delete_keys, &mut errors)
        .context("failed to cleanup s3 ddns.json items")?;

    /* trigger a ddns request automatically via a Process Command */

    errors.print_summary()
}

/// Holds non-blocking errors encountered during the Server process, so that the process updates what it can update, and doesn't self-DOS in the case of bad or outdated data
struct ServerErrors {
    failed_s3_fetches: Vec<(S3Key, anyhow::Error)>,
    failed_json_parses: Vec<(S3Key, anyhow::Error)>,
    failed_key_parses: Vec<(String, anyhow::Error)>,
    failed_signature_checks: Vec<(String, anyhow::Error)>,
    failed_s3_deletions: Vec<(S3Key, anyhow::Error)>,
}

impl ServerErrors {
    fn new() -> Self {
        Self {
            failed_json_parses: Vec::new(),
            failed_key_parses: Vec::new(),
            failed_s3_fetches: Vec::new(),
            failed_signature_checks: Vec::new(),
            failed_s3_deletions: Vec::new(),
        }
    }

    /// Returns `true` if any of the error vecs is not empty
    fn has_errors(&self) -> bool {
        !self.failed_s3_fetches.is_empty()
            || !self.failed_json_parses.is_empty()
            || !self.failed_key_parses.is_empty()
            || !self.failed_signature_checks.is_empty()
            || !self.failed_s3_deletions.is_empty()
    }

    /// Prints the summary of errors found for the user to remedy, or the Success string if no errors
    fn print_summary(&self) -> Result<(), anyhow::Error> {
        println!("Errors Summary\n-------");
        if self.has_errors() {
            if !self.failed_s3_fetches.is_empty() {
                println!("Failed S3 Fetches:");
                for fail in &self.failed_s3_fetches {
                    println!("\t *{}: {:#?}", fail.0, fail.1);
                }
            }
            if !self.failed_json_parses.is_empty() {
                println!("Failed JSON Deserializations:");
                for fail in &self.failed_json_parses {
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
            if !self.failed_s3_deletions.is_empty() {
                println!("Failed S3 Deletions:");
                for fail in &self.failed_s3_deletions {
                    println!("\t *{}: {:#?}", fail.0, fail.1);
                }
            }
            Err(anyhow::anyhow!(
                "errors occurred while executing this dyndynser run"
            ))
        } else {
            println!("No errors");
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::{
        dns::{self, ResourceRecordSet},
        keys::{load_ed25519_certificate_pem, read_file_limited},
        server::{DynDynserServer, UnverifiedDdnsRequest},
        signatures::{SignableEnvelope, SignedPayload},
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

        let envelope = SignableEnvelope::new(record);

        /* Load the private key for signing */
        let keybytes = read_file_limited("test/certs/augs.sarif.example.priv", 1400).unwrap();
        let private_key = crate::keys::load_ed25519_private_key(&keybytes, None).unwrap();

        /* Sign the Record */
        let signed_bytes = envelope.sign(&private_key).unwrap();
        let reserded_bytes =
            serde_json::from_slice::<SignedPayload<dns::ResourceRecordSet>>(&signed_bytes).unwrap();

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

        /* Check the Common Name is valid for the domain in question */
        let cert = cert.unwrap();
        assert_eq!(
            &cert.common_name, "augs.sarif.example",
            "expected common name of cert to augs.sarif.example"
        );

        assert_eq!(
            &cert.common_name, &reserded_bytes.envelope.payload.name,
            "expected cert.common_name to be same as the reserded_bytes domain request"
        );

        let unverified = UnverifiedDdnsRequest {
            s3_key: "some_key".into(),
            signed_payload: reserded_bytes,
        };

        let res = DynDynserServer::check_valid_ddns_request(
            &unverified,
            &[cert],
            chrono::TimeDelta::seconds(60),
        );
        assert!(res.is_ok(), "expected signature to pass validation");
    }
}
