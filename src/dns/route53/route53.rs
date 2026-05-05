use std::time::Duration;

use anyhow::Context as _;

use crate::dns::{Change, ChangeInfo, route53::aws_signature};

/// Route 53 is a global service, but SigV4 requires a region; it **must** be
/// `us-east-1` regardless of where the calling code runs.
const HOST: &str = "route53.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";

pub struct Route53Client {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    /// Connection pool shared across all requests on this client instance.
    client: reqwest::blocking::Client,
}

impl Route53Client {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Result<Self, anyhow::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            session_token,
            client,
        })
    }

    /// Build from the `rust-s3` credentials already in your project.
    pub fn from_s3_credentials(creds: &s3::creds::Credentials) -> Result<Self, anyhow::Error> {
        let access_key = creds
            .access_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("credentials missing access_key"))?
            .to_owned();
        let secret_key = creds
            .secret_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("credentials missing secret_key"))?
            .to_owned();

        // rust-s3 may use either field depending on credential source / version
        let session_token = creds
            .security_token
            .clone()
            .or_else(|| creds.session_token.clone());

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
            &self.access_key,
            &self.secret_key,
            self.session_token.as_deref(),
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
            status: extract_xml_text(&raw_xml, "Status").unwrap_or_default(),
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
        x.push_str(&format!("        <Action>{}</Action>\n", change.action));
        x.push_str("        <ResourceRecordSet>\n");
        x.push_str(&format!(
            "          <Name>{}</Name>\n",
            xml_escape(&rrs.name)
        ));
        x.push_str(&format!(
            "          <Type>{}</Type>\n",
            rrs.data.record_type()
        ));
        x.push_str(&format!("          <TTL>{}</TTL>\n", rrs.ttl));
        x.push_str("          <ResourceRecords>\n");

        for v in &values {
            x.push_str("            <ResourceRecord>\n");
            x.push_str(&format!("              <Value>{}</Value>\n", xml_escape(v)));
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

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Returns the trimmed text content of the first `<Tag>…</Tag>` in `xml`.
/// Intentionally minimal — no XML library needed for Route 53's flat responses.
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml[start..end].trim().to_owned())
}
