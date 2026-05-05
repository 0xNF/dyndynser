use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DdnsJSON {
    // FQDN to set DNS records for
    #[serde(rename = "domain")]
    pub domain: String,

    // IP, 4 or 6, to point the record to
    #[serde(rename = "ip")]
    pub ip: std::net::IpAddr,

    // Optional duration to specify
    #[serde(rename = "ttl", skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl DdnsJSON {
    pub const DDNS_JSON_FILE_EXT: &str = ".ddns.json";

    pub fn make_filename(&self) -> String {
        format!("{}{}", &self.domain, DdnsJSON::DDNS_JSON_FILE_EXT)
    }
}
