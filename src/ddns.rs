use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DdnsJSON {
    pub domain: String,
    pub ip: std::net::IpAddr,
}

pub const DDNS_JSON_FILE_EXT: &str = ".ddns.json";

impl DdnsJSON {
    pub fn make_filename(&self) -> String {
        format!("{}{}", &self.domain, DDNS_JSON_FILE_EXT)
    }
}
