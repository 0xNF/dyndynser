mod client;
mod config;
mod signatures;

use std::fs::OpenOptions;
use std::io::Write;

use std::path::{Path, PathBuf};
use std::str::FromStr;

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
        #[arg(long)]
        signing_key_password: Option<String>,
        region: String,
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    log::debug!("loading ddnser");
    let cli = CLI::parse();
    match cli.command {
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
            signing_key_password,
            region,
            dry_run,
        } => client::handle_client(
            dry_run,
            &robocerts_bucket,
            &s3_ddns_json_dir,
            &domain,
            &key_path,
            signing_key_password.as_deref(),
            &region,
        ),
    }
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
