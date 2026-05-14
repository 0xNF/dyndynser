use crate::{
    cli::{self},
    client::DynDynserClient,
    config::{AWSCliConfig, ConfigClient, DomainName, IPConfig},
};
use anyhow::Context as _;

/// In client mode, we query the IP of the running machine, create and sign a DDNS payload object for the domain, then push it to S3
pub fn handle_ip(args: cli::IPArgs) -> Result<(), anyhow::Error> {
    log::info!("parsing IP Config");
    let conf = IPConfig::parse(args).context("failed to parse IP config")?;

    if conf.is_public {
        let dummy_config = ConfigClient {
            ip_addr_check_url: conf.ip_addr_check_url,
            s3_queue_bucket: String::from(""),
            s3_ddns_json_directory: String::from(""),
            domain: DomainName::parse("sample.arpa").unwrap(),
            ttl: None,
            key_path: String::from(""),
            signing_key_password: None,
            is_dry_run: false,
            aws_config: AWSCliConfig {
                region: String::from(""),
                access_key_id: None,
                secret_access_key: None,
            },
            drop_user: String::from(""),
        };
        let dyndynser = DynDynserClient::with_config(&dummy_config);

        log::info!("will get public IP address");
        match dyndynser
            .query_for_ip()
            .context("failed to get IP address")?
        {
            std::net::IpAddr::V4(ipv4_addr) => {
                if conf.force_ipv6 {
                    anyhow::bail!(
                        "returned IP address was ipv4, but force-ipv6 was set: {}",
                        ipv4_addr
                    )
                } else {
                    println!("{}", ipv4_addr);
                }
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                if conf.force_ipv4 {
                    anyhow::bail!(
                        "returned IP address was ipv4, but force-ipv6 was set: {}",
                        ipv6_addr
                    )
                } else {
                    println!("{}", ipv6_addr);
                }
            }
        }
    }

    Ok(())
}
