mod config;
mod signatures;

use std::fs::OpenOptions;
use std::io::Write;

use std::path::{Path, PathBuf};
use std::{
    process::{ExitCode, Termination},
    str::FromStr,
};

use anyhow::Context;
use clap::{Parser, Subcommand};

use ed25519_dalek::Signer;
use reqwest::{self, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::*;

#[derive(Serialize, Deserialize, Debug)]
struct DdnsJSON {
    pub domain: String,
    pub ip: std::net::IpAddr,
}

impl DdnsJSON {
    pub fn make_filename(&self) -> String {
        format!("{}.ddns.json", &self.domain)
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CLI {
    #[command(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    Server {
        s3_robocerts_bucket: String,
        ddns_file_path: String,
        s3_ddns_json_dir: String,
        keys_search_path: String,
        region: String,
    },
    Client {
        robocerts_bucket: String,
        s3_ddns_json_dir: String,
        domain: String,
        key_path: String,
        region: String,
    },
}

fn main() -> impl Termination {
    log::debug!("loading ddnser");
    let cli = CLI::parse();
    let res = match cli.command {
        SubCommands::Server {
            s3_robocerts_bucket,
            s3_ddns_json_dir,
            ddns_file_path,
            keys_search_path,
            region,
        } => handle_server(
            &s3_robocerts_bucket,
            &s3_ddns_json_dir,
            &ddns_file_path,
            &keys_search_path,
            &region,
        ),
        SubCommands::Client {
            robocerts_bucket,
            s3_ddns_json_dir,
            domain,
            key_path,
            region,
        } => handle_client(
            &robocerts_bucket,
            &s3_ddns_json_dir,
            &domain,
            &key_path,
            &region,
        ),
    };

    let code = match res {
        Ok(_) => todo!(),
        Err(e) => {
            eprintln!("{}", e);
            1
        }
    };

    ExitCode::from(code)
}

fn handle_server(
    s3_robocerts_bucket: &str,
    s3_ddns_json_dir: &str,
    ddns_file_path: &str,
    keys_search_path: &str,
    region: &str,
) -> Result<(), anyhow::Error> {
    let c = ConfigServer::parse(
        s3_robocerts_bucket,
        s3_ddns_json_dir,
        ddns_file_path,
        keys_search_path,
        region,
    );
    match c {
        Ok(conf) => todo!(),
        Err(e) => {
            eprintln!("{}", e);
            Err(e)
        }
    }
}

fn handle_client(
    s3_robocerts_bucket: &str,
    s3_ddns_json_dir: &str,
    domain: &str,
    key_path: &str,
    region: &str,
) -> Result<(), anyhow::Error> {
    log::info!("parsing Client Config");
    let c = ConfigClient::parse(
        s3_robocerts_bucket,
        s3_ddns_json_dir,
        domain,
        key_path,
        region,
    );
    match c {
        Ok(conf) => {
            /* Get IP */
            log::info!("Querying for machine's IP addr");
            let ip = query_for_ip().context("failed to get IP address of this machine")?;

            /* Create DDNS struct json */
            let ddns_obj = DdnsJSON {
                domain: conf.domain,
                ip: ip,
            };

            let file_bytes = sign_object(&conf.signing_key, &ddns_obj)
                .context("Failed to sign payload object")?;

            /* Send to S3 */
            log::info!("Shelling out to invoke into S3");
            let ddns_json_path = format!(
                "{}/{}",
                conf.s3_robocerts_ddns_json_directory,
                ddns_obj.make_filename()
            );

            let region = conf.region.parse()?;
            let credentials = s3::creds::Credentials::default()?;
            let bucket = s3::Bucket::new(&conf.s3_robocerts_bucket, region, credentials)?;
            let content = file_bytes;
            let written_path = bucket
                .put_object_with_content_type(ddns_json_path, &content, "application/json")
                .context("failed to put S3 object")?;
            if written_path.status_code() != 200 {
                Err(anyhow::anyhow!("s3 returned non-200"))?;
            }
            log::info!("Successfully uploaded S3 ddns json");

            /* Clean up */
            Ok(())
        }
        Err(e) => {
            eprintln!("{}", e);
            Err(e)
        }
    }
}

fn query_for_ip() -> Result<std::net::IpAddr, anyhow::Error> {
    const URL: &str = "https://checkip.amazonaws.com";
    let res = reqwest::blocking::get(URL).context("failed to check IP address")?;
    if res.status() != StatusCode::OK {
        log::error!("IP Query returned non-200 err code: {}", res.status());
        return Err(anyhow::anyhow!("IP query returned non-200 status"));
    }

    let res = res
        .bytes()
        .context("could not read IP requets body bytes")?;

    log::debug!("got ip query result");

    let bytes = res.trim_ascii();
    let s = String::from_utf8_lossy(bytes);
    let ip_addr = std::net::IpAddr::from_str(&s)
        .with_context(|| format!("failed to convert IP address, returned {}", s))?;

    log::info!("Got machine IP: {}", &ip_addr);

    Ok(ip_addr)
}

fn sign_object(
    signing_key: &ed25519_dalek::SigningKey,
    serder: impl serde::Serialize,
) -> Result<Vec<u8>, anyhow::Error> {
    let payload_json = serde_json::to_string_pretty(&serder)
        .context("failed to json serialize the ddns object")?;

    /* Sign bytes */
    log::info!("Signing result");
    let sig = signing_key.sign(payload_json.as_bytes());

    let signed_payload = signatures::SignedJSON {
        payload: serder,
        signature: signatures::Signature::new(sig),
    };

    let signed_bytes = serde_json::to_string_pretty(&signed_payload)
        .context("failed to jsonify the signed ddns json")?
        .as_bytes()
        .to_owned();

    Ok(signed_bytes)
}

fn write_ddns_to_disk<P>(file_name: P, file_bytes: &Vec<u8>) -> Result<PathBuf, anyhow::Error>
where
    P: AsRef<Path>,
{
    let mut temp_file = std::env::temp_dir();
    temp_file.push(file_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&temp_file)
        .with_context(|| {
            format!(
                "failed to open ddns file for writing: {}",
                temp_file.to_string_lossy()
            )
        })?;

    file.write_all(&file_bytes)
        .with_context(|| format!("failed to write ddns file: {}", temp_file.to_string_lossy()))?;

    Ok(temp_file)
}
