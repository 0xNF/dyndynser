use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};

pub mod route53;

#[derive(Debug, Serialize, Deserialize)]
pub enum RecordType {
    A,
    AAAA,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChangeAction {
    /// Create-or-replace — idempotent
    Upsert,
}

impl std::fmt::Display for ChangeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Upsert => "UPSERT",
        })
    }
}

/// IP addresses for a record set.
///
/// The variant determines the record type, making it impossible to mix
/// IPv4 and IPv6 values, or to give a record type the wrong kind of address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordData {
    /// `A` record — one or more IPv4 addresses.
    A(Vec<Ipv4Addr>),
    /// `AAAA` record — one or more IPv6 addresses.
    AAAA(Vec<Ipv6Addr>),
}

impl RecordData {
    /// Returns the [`RecordType`] implied by this variant.
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::AAAA(_) => RecordType::AAAA,
        }
    }
}

/// One DNS record set (name + type).
#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceRecordSet {
    /// Fully-qualified DNS name, e.g. `"api.example.com."` (trailing dot optional).
    pub name: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// Addresses for this record set.  The variant encodes the record type,
    /// so `A` records can only hold [`Ipv4Addr`] values and `AAAA` records
    /// can only hold [`Ipv6Addr`] values.
    pub data: RecordData,
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addrs) => {
                write!(f, "A")?;
                for addr in addrs {
                    write!(f, " {addr}")?;
                }
                Ok(())
            }
            Self::AAAA(addrs) => {
                write!(f, "AAAA")?;
                for addr in addrs {
                    write!(f, " {addr}")?;
                }
                Ok(())
            }
        }
    }
}

impl ResourceRecordSet {
    pub const DDNS_JSON_FILE_EXT: &str = ".ddns.json";

    pub fn make_filename(&self) -> String {
        format!("{}{}", &self.name, ResourceRecordSet::DDNS_JSON_FILE_EXT)
    }
}

/// A single change within a batch.
#[derive(Debug)]
pub struct Change {
    pub action: ChangeAction,
    pub record_set: ResourceRecordSet,
}

/// Parsed response from `ChangeResourceRecordSets`.
#[derive(Debug)]
pub struct ChangeInfo {
    /// Change ID without the `/change/` prefix.
    pub id: String,
    /// `"PENDING"` immediately after submission; `"INSYNC"` once propagated.
    pub status: String,
}
