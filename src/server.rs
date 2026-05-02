use std::{collections::HashMap, str::FromStr};

use anyhow::Context;
use ed25519_dalek::{
    VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};

use crate::{
    config::*,
    ddns::{self, DdnsJSON},
    signatures::{self, SignedJSON},
};

fn get_public_key_map(
    conf: &ConfigServer,
    results: &mut Results,
) -> Result<HashMap<String, ed25519_dalek::VerifyingKey>, anyhow::Error> {
    let mut hm: HashMap<String, ed25519_dalek::VerifyingKey> = HashMap::new();

    /* for each key, accumulate errors. don't fail all just because one key is bad
     * * use the Domain portion to find the corresponding public key
     * * check signature is valid
     * * if valid, put into collected ddns struct
     */

    /* Get list of .pub key files known to this server */
    let list_pub_key_files = std::fs::read_dir(&conf.keys_search_path)
        .context("failed to read known key search path")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let is_file = entry.file_type().map(|ft| ft.is_file()).unwrap_or(false);

            let has_ext = entry
                .path()
                .extension()
                .map(|ext| ext == signatures::PUBLIC_KEY_EXT)
                .unwrap_or(false);

            is_file && has_ext
        });

    for entry in list_pub_key_files {
        let fname = entry.file_name().to_string_lossy().to_string();
        log::debug!("attempting to parse key found at {}", &fname);
        let fbytes = std::fs::read(entry.path())
            .with_context(|| format!("failed to read key file: {}", entry.path().display()));

        if let Err(e) = fbytes {
            results.failed_key_parses.push((
                fname,
                anyhow::Error::from(e).context("failed to read bytes of key file"),
            ));
            continue;
        }
        let fbytes = fbytes.unwrap();

        let vk = if fbytes.starts_with(signatures::OPENSSH_PREFIX_PUBLIC_KEY.as_bytes()) {
            log::info!("key is an OpenSSH public key, will parse as such");
            let pubkey = ssh_key::PublicKey::from_openssh(&String::from_utf8_lossy(&fbytes))
                .context("failed to parse key as openssh despite beginnign with `ssh-`");
            match pubkey {
                Ok(pubkey) => match pubkey.key_data().ed25519() {
                    Some(ed25519) => match VerifyingKey::from_bytes(&ed25519.0) {
                        Ok(vk) => {
                            log::info!("successfully parsed as an OpenSSH Public Key");
                            vk
                        }
                        Err(e) => {
                            let e = anyhow::Error::from(e).context(
                                    "Supplied verifying key was almost a valid ed25519 ssh key but failed to parse out a public key"
                                );
                            results.failed_key_parses.push((fname, e));

                            continue;
                        }
                    },
                    None => {
                        results
                            .failed_key_parses
                            .push((fname, anyhow::anyhow!("key was not an ed25519 public key")));
                        continue;
                    }
                },
                Err(e) => {
                    results.failed_key_parses.push((fname, e));
                    continue;
                }
            }
        } else if fbytes.starts_with(signatures::OPENSSL_PREFIX_PUBLIC_KEY.as_bytes()) {
            log::info!("Key is non-openssh public key");
            match ed25519_dalek::VerifyingKey::from_public_key_pem(&String::from_utf8_lossy(
                &fbytes,
            )) {
                Ok(vk) => {
                    log::info!("successfully parsed as an OpenSSL Public Key");
                    vk
                }
                Err(e) => {
                    results.failed_key_parses.push((
                        fname,
                        anyhow::Error::from(e).context(
                            "tried to create a Public Key but failed to parse as non-ssh format",
                        ),
                    ));

                    continue;
                }
            }
        } else {
            let e = anyhow::anyhow!("Supplied verifying key was not a valid supported format");
            results.failed_key_parses.push((fname, e));

            continue;
        };

        hm.insert(fname, vk);
    }

    Ok(hm)
}

fn check_valid_ddns_request(
    signed_json: &SignedJSON<DdnsJSON>,
    domain_key_map: &HashMap<String, VerifyingKey>,
) -> Result<(), anyhow::Error> {
    /* Look for Matching Key of domain */
    let vk = domain_key_map
        .get(&signed_json.payload.domain)
        .ok_or(Err(anyhow::anyhow!(
            "Receivd ddns request for domain '{}', but no matching key could be found",
            &signed_json.payload.domain,
        ))?)?;

    /* if key is found, try to validate the signature */
    vk.verify_strict(
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
    s3_bucket: &str,
    s3_ddns_json_dir: &str,
    ddns_file_path: &str,
    keys_search_path: &str,
    region: &str,
) -> Result<(), anyhow::Error> {
    let conf = ConfigServer::parse(
        is_dry_run,
        s3_bucket,
        s3_ddns_json_dir,
        ddns_file_path,
        keys_search_path,
        region,
    )
    .context("failed to parse server config")?;

    if conf.is_dry_run {
        log::info!("Doing a dry run, will not actually update the ddns file");
    }

    /* Retrieve all the ddns requests from the s3 bucket */
    let mut results = fetch_ddns_jsons_from_s3(&conf)
        .context("failed to perform S3 read portion of server operation")?;

    if results.signed_jsons.is_empty() {
        println!("No ddns.json files found, nothing to do.");
        return Ok(());
    }

    let domain_key_map =
        get_public_key_map(&conf, &mut results).context("failed to get public key map")?;

    for signed_json in results.signed_jsons.into_iter() {
        match check_valid_ddns_request(&signed_json, &domain_key_map)
            .context("failed to check signing key request")
        {
            Ok(_) => {
                results.valid_json.push(signed_json.payload);
            }
            Err(e) => {
                results.failed_signature_checks.push((
                    signed_json.payload.domain,
                    anyhow::Error::from(e).context("signature did not pass validation"),
                ));
            }
        }
    }

    /* read the ddns-route53 config file */

    /* Write the valid requests to it, and write file back to disk */

    /* trigger a ddns request automatically via a Process Command */

    Ok(())
}

fn fetch_ddns_jsons_from_s3(conf: &ConfigServer) -> Result<Results, anyhow::Error> {
    log::info!("Fetching s3 bucket items");
    let mut results = Results::new();

    /* S3 set up */
    let credentials = s3::creds::Credentials::default()?;
    let region = conf
        .region
        .parse()
        .context("invalid AWS region found during S3 write")?;
    let bucket = s3::Bucket::new(&conf.s3_robocerts_bucket, region, credentials)
        .context("failed to rerieve s3 credentials")?;

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

        log::debug!("Successfully fetched s3 page {}", iterationcount);

        for x in &list_result.contents {
            /* Check key is an expected .ddns.json request file */
            if !x.key.ends_with(ddns::DDNS_JSON_FILE_EXT) {
                eprintln!(
                    "invalid s3 object key, not a ddns '{}' file: {}",
                    ddns::DDNS_JSON_FILE_EXT,
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
                                ddns::DDNS_JSON_FILE_EXT
                            );
                            results.signed_jsons.push(ddnsjson);
                        }
                        Err(e) => {
                            log::error!(
                                "failed to deserde key '{}' into a {} object",
                                &x.key,
                                ddns::DDNS_JSON_FILE_EXT
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

struct Results {
    failed_s3_fetches: Vec<(String, anyhow::Error)>,
    failed_json_deserdes: Vec<(String, anyhow::Error)>,
    failed_signature_checks: Vec<(String, anyhow::Error)>,
    failed_key_parses: Vec<(String, anyhow::Error)>,
    signed_jsons: Vec<SignedJSON<DdnsJSON>>,
    valid_json: Vec<DdnsJSON>,
}
impl Results {
    fn new() -> Self {
        Self {
            signed_jsons: Vec::new(),
            valid_json: Vec::new(),
            failed_s3_fetches: Vec::new(),
            failed_json_deserdes: Vec::new(),
            failed_signature_checks: Vec::new(),
            failed_key_parses: Vec::new(),
        }
    }
}
