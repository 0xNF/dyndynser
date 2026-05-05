mod cli;
mod client;
mod config;
mod dns;
mod keys;
mod server;
mod signatures;

use std::{collections::BTreeMap, sync::Mutex};

use clap::Parser;

use crate::cli::CLI;

const APP_NAME: &str = "dyndynser";

fn main() -> anyhow::Result<()> {
    /* Set Loggers */
    init_global_loggers()?;

    log::debug!("loading dyndynser");
    let cli_parsed = CLI::parse();
    match cli_parsed.command {
        cli::SubCommands::Server(server_args) => server::handle_server(&server_args),
        cli::SubCommands::Client(client_args) => client::handle_client(&client_args),
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

fn init_global_loggers() -> Result<(), anyhow::Error> {
    let env_log = env_logger::Builder::from_default_env().build();
    let max_level = env_log.filter();

    let loggers: Vec<Box<dyn log::Log>> = vec![
        Box::new(env_log),
        /* conditionally add syslogging for systems that support it */
        #[cfg(unix)]
        {
            match Syslog5424Logger::new(
                APP_NAME,
                syslog::Facility::LOG_USER,
                log::LevelFilter::Info,
            ) {
                Ok(ss) => Box::new(ss),
                Err(_) => {
                    anyhow::bail!("Cannot contact syslog service")
                }
            }
        },
    ];

    let multi = MultiLogger { loggers };

    log::set_boxed_logger(Box::new(multi)).expect("Failed to set logger");
    log::set_max_level(max_level);
    Ok(())
}
