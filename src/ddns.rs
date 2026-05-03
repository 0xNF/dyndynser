use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct DDNSRoute53Route53 {
    #[serde(rename = "hostedZoneID")]
    pub hosted_zone_id: String,
    #[serde(rename = "recordsSet")]
    pub records_set: Vec<DdnsRoute53Record>,
    #[serde(flatten)]
    extra: HashMap<String, Value>, // absorbs all unknown fields
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DdnsRoute53Record {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(rename = "ttl")]
    pub time_to_live: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DDNSRoute53Config {
    #[serde(rename = "route53")]
    pub route_53: DDNSRoute53Route53,
    #[serde(flatten)]
    extra: HashMap<String, Value>, // absorbs all unknown fields
}
