use clap::{Parser, Subcommand};

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
}

#[derive(clap::Args)]
pub struct ServerArgs {
    #[arg(
        long = "dry-run",
        help = "Simulate all operations without writing any DNS changes to Route53. Will print what would otherwise be updated."
    )]
    pub is_dry_run: bool,

    #[arg(long = "bucket", help = "S3 bucket name used as the DDNS backend")]
    pub s3_bucket: String,
    #[arg(
        long = "bucket-ddns-dir",
        help = "S3 key prefix (directory) for pending DDNS update JSON files"
    )]
    pub s3_ddns_json_dir: String,

    #[arg(
        long = "hosted-zone-id",
        help = "Id of the Local Hosted DNS Zone",
        env = "DYNDYNSER_AWS_HOSTED_ZONE_ID"
    )]
    pub hosted_dns_zone_id: String,

    #[arg(
        long = "keys-search-path",
        help = "Directory to search for trusted public key files used in signature verification"
    )]
    pub keys_search_path: String,

    #[arg(
        long = "aws-region",
        help = "AWS region of the S3 bucket (e.g. eu-east-1)",
        env = "AWS_REGION"
    )]
    pub aws_region: String,

    #[arg(
        long = "aws-access-key-id",
        help = "AWS Access Key Id",
        env = "AWS_ACCESS_KEY_ID"
    )]
    pub aws_access_key_id: Option<String>,

    #[arg(
        long = "aws-secret-access-key",
        help = "AWS Secret Access Key",
        env = "AWS_SECRET_ACCESS_KEY"
    )]
    pub aws_secret_access_key: Option<String>,

    #[arg(
        long = "max-signed-at-time-ago",
        help = "Maximum seconds in the past that a ddns request can be signed at before being rejected for being stale"
    )]
    pub max_time_ago_signed_at_secs: Option<u32>,
}

#[derive(clap::Args)]
pub struct ClientArgs {
    #[arg(
        long = "dry-run",
        help = "Simulate all operations without writing any DNS changes to S3. Will print what would otherwise be updated."
    )]
    pub is_dry_run: bool,

    #[arg(long = "bucket", help = "S3 bucket name used as the DDNS backend")]
    pub s3_bucket: String,

    #[arg(
        long = "bucket-ddns-dir",
        help = "S3 key prefix (directory) for pending DDNS update JSON files"
    )]
    pub s3_ddns_json_dir: String,

    #[arg(
        long = "domain",
        help = "Fully-qualified domain name to update (e.g. home.example.com)"
    )]
    pub domain: String,

    #[arg(
        long,
        help = "DNS record TTL in seconds (uses server default if omitted)"
    )]
    pub ttl: Option<u32>,

    #[arg(
        long = "key-path",
        help = "Path to the PEM-encoded Ed25519 private key file for signing"
    )]
    pub key_path: String,

    #[arg(
        long,
        help = "Passphrase to decrypt the private key (omit if the key is not encrypted)",
        env = "DYNDYNSER_SIGNING_KEY_PASSWORD"
    )]
    pub signing_key_password: Option<String>,

    #[arg(
        long = "aws-region",
        help = "AWS region of the S3 bucket (e.g. eu-east-1)",
        env = "AWS_REGION"
    )]
    pub aws_region: String,

    #[arg(
        long = "aws-access-key-id",
        help = "AWS Access Key Id",
        env = "AWS_ACCESS_KEY_ID"
    )]
    pub aws_access_key_id: Option<String>,

    #[arg(
        long = "aws-secret-access-key",
        help = "AWS Secret Access Key",
        env = "AWS_SECRET_ACCESS_KEY"
    )]
    pub aws_secret_access_key: Option<String>,

    #[arg(
        long = "ip-addr-check-url",
        help = "URL of service to use to check IP Address. Must return a bare ip-address in either v4 or v6"
    )]
    pub ip_addr_check_url: Option<String>,
}
