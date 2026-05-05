use std::fmt::Write;
use std::{borrow::Cow, time::Duration};

use anyhow::Context as _;

use crate::dns::{Change, ChangeInfo, route53::aws_signature};

/// Route 53 is a global service, but SigV4 requires a region; it **must** be
/// `us-east-1` regardless of where the calling code runs.
const HOST: &str = "route53.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";

pub struct Route53Client<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    session_token: Option<&'a str>,
    /// Connection pool shared across all requests on this client instance.
    client: reqwest::blocking::Client,
}

impl<'a> Route53Client<'a> {
    pub fn new(
        access_key: &'a str,
        secret_key: &'a str,
        session_token: Option<&'a str>,
    ) -> Result<Self, anyhow::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self {
            access_key,
            secret_key,
            session_token,
            client,
        })
    }

    /// Build from the `rust-s3` credentials already in your project.
    pub fn from_s3_credentials(creds: &'a s3::creds::Credentials) -> Result<Self, anyhow::Error> {
        let access_key = creds
            .access_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("credentials missing access_key"))?;
        let secret_key = creds
            .secret_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("credentials missing secret_key"))?;

        // rust-s3 may use either field depending on credential source / version
        let session_token = creds
            .security_token
            .as_deref()
            .or(creds.session_token.as_deref());

        Self::new(access_key, secret_key, session_token)
    }

    fn signed_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<reqwest::header::HeaderMap, anyhow::Error> {
        let map = aws_signature::aws_sigv4_headers(
            method,
            HOST,
            path,
            "",
            body,
            SERVICE,
            REGION,
            self.access_key,
            self.secret_key,
            self.session_token,
        );
        aws_signature::to_header_map(&map)
    }

    fn check_response(resp: reqwest::blocking::Response) -> Result<String, anyhow::Error> {
        let status = resp.status();
        let body = resp.text().context("reading Route 53 response body")?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(anyhow::anyhow!("Route 53 HTTP {status}: {body}"))
        }
    }

    /// Submit a batch of DNS record-set changes.
    ///
    /// `hosted_zone_id` accepts `"Z1234567890ABC"` or `"/hostedzone/Z1234567890ABC"`.
    pub fn change_resource_record_sets(
        &self,
        hosted_zone_id: &str,
        comment: Option<&str>,
        changes: &[Change],
    ) -> Result<ChangeInfo, anyhow::Error> {
        let zone = hosted_zone_id.trim_start_matches("/hostedzone/").trim();
        let path = format!("/2013-04-01/hostedzone/{zone}/rrset/");
        let body = build_change_xml(comment, changes);
        let url = format!("https://{HOST}{path}");

        log::debug!("signing headers for route53 push");
        let headers = self.signed_headers("POST", &path, body.as_bytes())?;

        log::info!("Sending Route53 request");
        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .context("sending ChangeResourceRecordSets request")?;

        log::debug!("got response from Route53, code {}", &resp.status());
        let raw_xml =
            Self::check_response(resp).context("failed to deserialize route53 response")?;

        Ok(ChangeInfo {
            id: extract_xml_text(&raw_xml, "Id")
                .unwrap_or_default()
                .trim_start_matches("/change/")
                .to_owned(),
            status: extract_xml_text(&raw_xml, "Status")
                .unwrap_or_default()
                .to_owned(),
        })
    }
}

fn build_change_xml(comment: Option<&str>, changes: &[Change]) -> String {
    let mut x = String::new();

    x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    x.push_str(
        "<ChangeResourceRecordSetsRequest \
                xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\">\n",
    );
    x.push_str("  <ChangeBatch>\n");

    if let Some(c) = comment {
        x.push_str(&format!("    <Comment>{}</Comment>\n", xml_escape(c)));
    }

    x.push_str("    <Changes>\n");

    for change in changes {
        let rrs = &change.record_set;

        // Flatten the typed addresses into strings once.  The match also
        // serves as a compile-time guarantee that A ↔ IPv4 and AAAA ↔ IPv6.
        // IP address Display impls never emit XML-special characters, so no
        // escaping is needed.
        let values: Vec<String> = match &rrs.data {
            crate::dns::RecordData::A(addrs) => addrs.iter().map(|a| a.to_string()).collect(),
            crate::dns::RecordData::AAAA(addrs) => addrs.iter().map(|a| a.to_string()).collect(),
        };

        x.push_str("      <Change>\n");
        writeln!(x, "        <Action>{}</Action>", change.action).unwrap();
        x.push_str("        <ResourceRecordSet>\n");
        writeln!(x, "          <Name>{}</Name>", xml_escape(&rrs.name)).unwrap();
        writeln!(x, "          <Type>{}</Type>", rrs.data.record_type()).unwrap();
        writeln!(x, "          <TTL>{}</TTL>", rrs.ttl).unwrap();
        x.push_str("          <ResourceRecords>\n");

        for v in &values {
            x.push_str("            <ResourceRecord>\n");
            writeln!(x, "              <Value>{}</Value>", xml_escape(v)).unwrap();
            x.push_str("            </ResourceRecord>\n");
        }

        x.push_str("          </ResourceRecords>\n");
        x.push_str("        </ResourceRecordSet>\n");
        x.push_str("      </Change>\n");
    }

    x.push_str("    </Changes>\n");
    x.push_str("  </ChangeBatch>\n");
    x.push_str("</ChangeResourceRecordSetsRequest>");
    x
}

fn xml_escape(s: &str) -> Cow<'_, str> {
    if s.contains(&['&', '<', '>', '"', '\''][..]) {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                _ => out.push(c),
            }
        }
        Cow::Owned(out)
    } else {
        Cow::Borrowed(s)
    }
}

/// Returns the trimmed text content of the first `<Tag>…</Tag>` in `xml`.
/// Intentionally minimal — no XML library needed for Route 53's flat responses.
fn extract_xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml[start..end].trim())
}
