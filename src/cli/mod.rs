use clap::{Parser, Subcommand};

const DEFAULT_DDNS_DIR: &str = "/ddns/requests";

fn trimmed_string(s: &str) -> Result<String, String> {
    let trimmed = s.trim().to_string();
    if trimmed.is_empty() {
        Err(String::from("value cannot be empty or whitespace-only"))
    } else {
        Ok(trimmed)
    }
}
#[derive(Parser)]
#[command(
    version,
    about = "S3-backed dynamic DNS service with cryptographic record signing",
    long_about = None
)]
#[allow(clippy::upper_case_acronyms)]
pub struct CLI {
    #[command(subcommand)]
    pub command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    /// Run in server mode, processing and validating DDNS update requests stored in S3.
    /// The server verifies cryptographic signatures on each request against a set of trusted public keys before applying
    /// any DNS record changes.
    Server(ServerArgs),

    /// Run in client mode, publishing a signed DDNS update request to S3 for the server to process.
    /// The update is cryptographically signed using the provided private key so the server can verify authenticity.
    Client(ClientArgs),

    /// Gets information about the current ip address on this machine
    IP(IPArgs),
}

#[derive(clap::Args)]
pub struct IPArgs {
    #[arg(
        long = "ip-addr-check-url",
        help = "URL of service to use to check IP Address. Must return a bare ip-address in either v4 or v6",
        value_parser = trimmed_string,
        default_value="https://checkip.amazonaws.com"
    )]
    pub ip_addr_check_url: String,

    #[arg(
        long = "public",
        help = "Fetches and displays the Public IP of this machine"
    )]
    pub get_public: bool,

    #[arg(long = "force-ipv4", help = "Fails if the returned address isn't ipv4")]
    pub force_ipv4: bool,

    #[arg(long = "force-ipv6", help = "Fails if the returned address isn't ipv6")]
    pub force_ipv6: bool,
}

#[derive(clap::Args)]
pub struct ServerArgs {
    #[arg(
        long = "dry-run",
        help = "Simulate all operations without writing any DNS changes to Route53. Will print what would otherwise be updated."
    )]
    pub is_dry_run: bool,

    #[arg(long = "bucket", help = "S3 bucket name used as the DDNS backend", value_parser = trimmed_string)]
    pub s3_queue_bucket: String,

    #[arg(
        long = "bucket-ddns-dir",
        help = "S3 key prefix (directory) for pending DDNS update JSON files",
        value_parser = trimmed_string,
        default_value=DEFAULT_DDNS_DIR,

    )]
    pub s3_ddns_json_dir: String,

    #[arg(
        long = "hosted-zone-id",
        help = "Id of the Local Hosted DNS Zone",
        env = "DYNDYNSER_AWS_HOSTED_ZONE_ID",
        value_parser = trimmed_string
    )]
    pub hosted_dns_zone_id: String,

    #[arg(
        long = "keys-search-path",
        help = "Directory to search for trusted public key files used in signature verification",
        value_parser = trimmed_string
    )]
    #[cfg_attr(
        target_os = "linux",
        arg(default_value = "/usr/local/share/ca-certificates")
    )]
    #[cfg_attr(
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ),
        arg(default_value = "/usr/local/etc/ssl/certs/")
    )]
    pub keys_search_path: String,

    #[arg(
        long = "aws-region",
        help = "AWS region of the S3 bucket (e.g. eu-east-1)",
        env = "AWS_REGION",
        value_parser = trimmed_string
    )]
    pub aws_region: String,

    #[arg(
        long = "aws-access-key-id",
        help = "AWS Access Key Id",
        env = "AWS_ACCESS_KEY_ID",
        hide_env_values = true,
        value_parser = trimmed_string
    )]
    pub aws_access_key_id: Option<String>,

    #[arg(
        long = "aws-secret-access-key",
        help = "AWS Secret Access Key",
        env = "AWS_SECRET_ACCESS_KEY",
        hide_env_values = true,
        value_parser = trimmed_string
    )]
    pub aws_secret_access_key: Option<String>,

    #[arg(
        long = "max-signed-at-time-ago",
        help = "Maximum seconds in the past that a ddns request can be signed at before being rejected for being stale",
        default_value_t = 60 * 60
    )]
    pub max_time_ago_signed_at_secs: u32,

    #[arg(
        long = "drop-to-user",
        help = "user to drop down to after priveliged operations are over",
        default_value = "dyndynser",
        value_parser = trimmed_string
    )]
    pub drop_to_user: String,

    #[arg(
        long = "insecure-skip-verify",
        help = "Don't attempt signature validation, accept any request uncritically",
        default_value_t = false
    )]
    pub insecure_skip_verify: bool,
}

#[derive(clap::Args)]
pub struct ClientArgs {
    #[arg(
        long = "dry-run",
        help = "Simulate all operations without writing any DNS changes to S3. Will print what would otherwise be updated."
    )]
    pub is_dry_run: bool,

    #[arg(
        long = "bucket",
        help = "S3 bucket name used as the DDNS backend",
        value_parser = trimmed_string
    )]
    pub s3_queue_bucket: String,

    #[arg(
        long = "bucket-ddns-dir",
        help = "S3 key prefix (directory) for pending DDNS update JSON files",
        value_parser = trimmed_string,
        default_value=DEFAULT_DDNS_DIR,
    )]
    pub s3_ddns_json_dir: String,

    #[arg(
        long = "domain",
        help = "Fully-qualified domain name to update (e.g. somepage.example)",
        value_parser = trimmed_string
    )]
    pub domain_to_update: String,

    #[arg(
        long,
        help = "DNS record TTL in seconds (uses server default if omitted)"
    )]
    pub ttl: Option<u32>,

    #[arg(
        long = "key-path",
        help = "Path to the PEM-encoded Ed25519 private key file for signing",
        value_parser = trimmed_string
    )]
    pub key_path: String,

    #[arg(
        long,
        help = "Passphrase to decrypt the private key (omit if the key is not encrypted)",
        env = "DYNDYNSER_SIGNING_KEY_PASSWORD",
        value_parser = trimmed_string
    )]
    pub signing_key_password: Option<String>,

    #[arg(
        long = "aws-region",
        help = "AWS region of the S3 bucket (e.g. eu-east-1)",
        env = "AWS_REGION",
        value_parser = trimmed_string
    )]
    pub aws_region: String,

    #[arg(
        long = "aws-access-key-id",
        help = "AWS Access Key Id",
        env = "AWS_ACCESS_KEY_ID",
        hide_env_values = true,
        value_parser = trimmed_string
    )]
    pub aws_access_key_id: Option<String>,

    #[arg(
        long = "aws-secret-access-key",
        help = "AWS Secret Access Key",
        env = "AWS_SECRET_ACCESS_KEY",
        hide_env_values = true,
        value_parser = trimmed_string
    )]
    pub aws_secret_access_key: Option<String>,

    #[arg(
        long = "ip-addr-check-url",
        help = "URL of service to use to check IP Address. Must return a bare ip-address in either v4 or v6",
        value_parser = trimmed_string,
            default_value="https://checkip.amazonaws.com"

    )]
    pub ip_addr_check_url: String,

    #[arg(
        long = "drop-to-user",
        help = "user to drop down to after priveliged operations are over",
        default_value = "dyndynser",
        value_parser = trimmed_string
    )]
    pub drop_to_user: String,

    #[arg(
        long = "insecure-skip-verify",
        help = "Don't sign the dns request",
        default_value_t = false
    )]
    pub insecure_skip_verify: bool,
}
