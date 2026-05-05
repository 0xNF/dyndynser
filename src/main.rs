mod client;
mod config;
mod ddns;
mod dns;
mod keys;
mod server;
mod signatures;

use std::{collections::BTreeMap, sync::Mutex};

use clap::{Parser, Subcommand};

const APP_NAME: &str = "dyndynser";

#[derive(Parser)]
#[command(
    version,
    about = "S3-backed dynamic DNS service with cryptographic record signing",
    long_about = None
)]
pub struct CLI {
    #[command(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    /// Run in server mode, processing and validating DDNS update equests stored in S3.
    /// The server verifies cryptographic signatures on each request against a set of trusted public keys before applying
    /// any DNS record changes.
    Server {
        #[arg(
            long = "dry-run",
            help = "Simulate all operations without writing any DNS changes to either the local ddns-route53.yaml conf, or pushing anything ti Route53. Will print what would otherwise be updated."
        )]
        is_dry_run: bool,

        #[arg(long = "bucket", help = "S3 bucket name used as the DDNS backend")]
        s3_bucket: String,
        #[arg(
            long = "bucket-ddns-dir",
            help = "S3 key prefix (directory) for pending DDNS update JSON files"
        )]
        s3_ddns_json_dir: String,

        #[arg(
            long = "hosted-zone-id",
            help = "Id of the Local Hosted DNS Zone",
            env = "DYNDYNSER_AWS_HOSTED_ZONE_ID"
        )]
        hosted_dns_zone_id: String,

        #[arg(
            long = "keys-search-path",
            help = "Directory to search for trusted public key files used in signature verification"
        )]
        keys_search_path: String,

        #[arg(
            long = "aws-region",
            help = "AWS region of the S3 bucket (e.g. eu-west-1)",
            env = "DYNDYNSER_AWS_REGION"
        )]
        aws_region: String,
    },

    /// Run in client mode, publishing a signed DDNS update request to S3 for the server to process.
    /// The update is cryptographically signed using the provided private key so the server can verify authenticity.
    Client {
        #[arg(
            long = "dry-run",
            help = "Simulate all operations without writing any DNS changes to S3. Will print what would otherwise be updated."
        )]
        is_dry_run: bool,

        #[arg(long = "bucket", help = "S3 bucket name used as the DDNS backend")]
        s3_bucket: String,

        #[arg(
            long = "bucket-ddns-dir",
            help = "S3 key prefix (directory) for pending DDNS update JSON files"
        )]
        s3_ddns_json_dir: String,

        #[arg(
            long = "domain",
            help = "Fully-qualified domain name to update (e.g. home.example.com)"
        )]
        domain: String,

        #[arg(
            long,
            help = "DNS record TTL in seconds (uses server default if omitted)"
        )]
        ttl: Option<u32>,

        #[arg(
            long = "key-path",
            help = "Path to the PEM-encoded Ed25519 private key file for signing"
        )]
        key_path: String,

        #[arg(
            long,
            help = "Passphrase to decrypt the private key (omit if the key is not encrypted)",
            env = "DYNDYNSER__SIGNING_KEY_PASSWORD"
        )]
        signing_key_password: Option<String>,

        #[arg(
            long = "aws-region",
            help = "AWS region of the S3 bucket (e.g. eu-west-1)",
            env = "DYNDYNSER__AWS_REGION"
        )]
        aws_region: String,
    },
}

fn main() -> anyhow::Result<()> {
    /* Set Loggers */
    init_global_loggers();

    log::debug!("loading dyndynser");
    let cli = CLI::parse();
    match cli.command {
        SubCommands::Server {
            is_dry_run,
            s3_bucket,
            s3_ddns_json_dir,
            hosted_dns_zone_id,
            keys_search_path,
            aws_region: region,
        } => server::handle_server(
            is_dry_run,
            &s3_bucket,
            &s3_ddns_json_dir,
            &hosted_dns_zone_id,
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

/// Fan-out logger — forwards records to all inner loggers
struct MultiLogger {
    loggers: Vec<Box<dyn log::Log>>,
}

impl log::Log for MultiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.loggers.iter().any(|l| l.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        for logger in &self.loggers {
            if logger.enabled(record.metadata()) {
                logger.log(record);
            }
        }
    }

    fn flush(&self) {
        for logger in &self.loggers {
            logger.flush();
        }
    }
}

struct Syslog5424Logger {
    inner: Mutex<syslog::Logger<syslog::LoggerBackend, syslog::Formatter5424>>,
    level: log::LevelFilter,
}

impl Syslog5424Logger {
    fn new(
        app_name: &str,
        facility: syslog::Facility,
        level: log::LevelFilter,
    ) -> Result<Self, syslog::Error> {
        let formatter = syslog::Formatter5424 {
            facility,
            hostname: None,
            process: app_name.to_owned(),
            pid: std::process::id(),
        };

        let logger = syslog::unix(formatter)?;

        Ok(Self {
            inner: Mutex::new(logger),
            level,
        })
    }

    /// Build the RFC5424 structured data payload:
    /// (msgid, BTreeMap<SD-ID, BTreeMap<param-name, param-value>>, message)
    fn make_payload(
        record: &log::Record,
    ) -> (u32, BTreeMap<String, BTreeMap<String, String>>, String) {
        let msg = format!("{}", record.args());
        let sd: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        (0u32, sd, msg)
    }
}

impl log::Log for Syslog5424Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(mut logger) = self.inner.lock() {
            let _ = match record.level() {
                log::Level::Error => logger.err(Self::make_payload(record)),
                log::Level::Warn => logger.warning(Self::make_payload(record)),
                log::Level::Info => logger.info(Self::make_payload(record)),
                log::Level::Debug => logger.debug(Self::make_payload(record)),
                log::Level::Trace => logger.debug(Self::make_payload(record)),
            };
        }
    }

    fn flush(&self) {}
}

fn init_global_loggers() {
    let env_log = env_logger::Builder::from_default_env().build();
    let max_level = env_log.filter();

    let loggers: Vec<Box<dyn log::Log>> = vec![
        Box::new(env_log),
        /* conditionally add syslogging for systems that support it */
        #[cfg(unix)]
        {
            let ss =
                Syslog5424Logger::new(APP_NAME, syslog::Facility::LOG_USER, log::LevelFilter::Info)
                    .expect("Failed to open RFC5424 syslog");

            Box::new(ss)
        },
    ];

    let multi = MultiLogger { loggers };

    log::set_boxed_logger(Box::new(multi)).expect("Failed to set logger");
    log::set_max_level(max_level);
}
