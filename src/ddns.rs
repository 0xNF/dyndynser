use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DdnsJSON {
    pub domain: String,
    pub ip: std::net::IpAddr,
}

impl DdnsJSON {
    pub fn make_filename(&self) -> String {
        format!("{}.ddns.json", &self.domain)
    }
}
