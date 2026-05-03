mod client;
mod config;
mod ddns;
mod keys;
mod server;
mod signatures;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CLI {
    #[command(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    Server {
        #[arg(long = "dry-run")]
        is_dry_run: bool,
        #[arg(long = "s3-delete-after-success")]
        is_s3_delete_after_success: bool,

        s3_bucket: String,
        s3_ddns_json_dir: String,

        ddns_file_path: String,
        keys_search_path: String,

        #[arg(name = "region")]
        aws_region: String,
    },
    Client {
        #[arg(long = "dry-run")]
        is_dry_run: bool,

        s3_bucket: String,
        s3_ddns_json_dir: String,
        domain: String,
        ttl: Option<u32>,
        key_path: String,

        #[arg(long)]
        signing_key_password: Option<String>,

        #[arg(name = "region")]
        aws_region: String,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    log::debug!("loading ddnser");
    let cli = CLI::parse();
    match cli.command {
        SubCommands::Server {
            is_dry_run,
            is_s3_delete_after_success,
            s3_bucket: s3_robocerts_bucket,
            s3_ddns_json_dir,
            ddns_file_path,
            keys_search_path,
            aws_region: region,
        } => server::handle_server(
            is_dry_run,
            is_s3_delete_after_success,
            &s3_robocerts_bucket,
            &s3_ddns_json_dir,
            &ddns_file_path,
            &keys_search_path,
            &region,
        ),
        SubCommands::Client {
            is_dry_run,
            s3_bucket,
            s3_ddns_json_dir,
            domain,
            ttl,
            key_path,
            signing_key_password,
            aws_region: region,
        } => client::handle_client(
            is_dry_run,
            &s3_bucket,
            &s3_ddns_json_dir,
            &domain,
            ttl,
            &key_path,
            signing_key_password.as_deref(),
            &region,
        ),
    }
}
