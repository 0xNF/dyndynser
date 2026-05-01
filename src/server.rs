use crate::config::*;

pub fn handle_server(
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
