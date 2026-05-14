mod cli;
mod client;
mod config;
mod dns;
mod ip;
mod keys;
mod logging;
mod server;
mod signatures;
mod unix;

use clap::Parser;

use crate::cli::CLI;

const APP_NAME: &str = "dyndynser";

fn main() -> anyhow::Result<()> {
    /* Set Loggers */
    logging::init_global_loggers(APP_NAME)?;

    log::debug!("loading dyndynser");
    let cli_parsed = CLI::parse();
    match cli_parsed.command {
        cli::SubCommands::Server(server_args) => server::handle_server(server_args),
        cli::SubCommands::Client(client_args) => client::handle_client(client_args),
        cli::SubCommands::IP(ip_args) => ip::handle_ip(ip_args),
    }
}
