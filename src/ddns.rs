use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

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
