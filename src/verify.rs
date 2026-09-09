//! End-to-end verification.
//!
//! This is the only check that measures the property a user actually cares
//! about. A running tor process and an open port prove that a daemon is
//! listening; they say nothing about whether traffic from the namespace reaches
//! the internet through it.
//!
//! The request below is made from *inside* the namespace with **no proxy
//! configured**. If it comes back IsTor=true, the transparent redirect works,
//! because nothing else could have carried it.

use anyhow::{Context, Result};
use std::time::Duration;

/// Three outcomes, kept distinct on purpose. "Could not check" is not
/// "confirmed safe", and collapsing the two is how a tool ends up telling
/// someone they are anonymous when it has no idea.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    /// check.torproject.org confirmed the connection exits via Tor.
    ThroughTor,
    /// It confirmed the connection does NOT exit via Tor. This is a leak.
    NotThroughTor,
    /// The check could not be completed. Unknown, not safe.
    Unverified,
}

impl Verdict {
    pub fn is_confirmed_safe(self) -> bool {
        matches!(self, Verdict::ThroughTor)
    }
}

/// Wording for each verdict, kept in one place so the daemon and the local path
/// cannot drift into describing the same result differently.
/// Multi-line description of a full check, including the exit node.
pub fn describe_result(result: &CheckResult) -> String {
    let mut out = describe(result.verdict).to_string();

    let Some(exit) = &result.exit else { return out };

    if let Some(ip) = &exit.ip {
        out.push_str(&format!("\n  exit node : {ip}"));
    }

    let place: Vec<&str> = [&exit.city, &exit.region, &exit.country]
        .into_iter()
        .filter_map(|f| f.as_deref())
        .filter(|f| !f.is_empty())
        .collect();
    if !place.is_empty() {
        out.push_str(&format!("\n  location  : {}", place.join(", ")));
    }

    if let Some(org) = &exit.org {
        let asn = exit.asn.as_deref().unwrap_or_default();
        out.push_str(&format!(
            "\n  operator  : {}{org}",
            if asn.is_empty() { String::new() } else { format!("AS{asn} ") }
        ));
    }

    // is_proxy is deliberately not reported. The assumption when it was added
    // was that a geo provider would flag a Tor exit as a proxy; in practice
    // ip2location returns false for published exits, so the note fired on every
    // successful connection. A warning that always appears carries no
    // information and trains the reader to ignore warnings.

    out
}

/// Render a status report as lines for a terminal.
pub fn describe_status(report: &crate::proto::StatusReport) -> String {
    let yes_no = |b: bool| if b { "present" } else { "absent" };

    let mut out = format!(
        "namespace      : {}\nnftables table : {}\ntor            : {}\n",
        yes_no(report.namespace),
        yes_no(report.rules),
        yes_no(report.tor)
    );

    if report.is_up() {
        out.push_str("\ntort is up.\n");
        match &report.check {
            Some(check) => out.push_str(&describe_result(check)),
            None => out.push_str("could not verify"),
        }
    } else if report.is_down() {
        out.push_str("\ntort is down.");
    } else {
        out.push_str("\ntort is in a PARTIAL state. Run `tort down` to clean up.");
    }
    out
}

pub fn describe(v: Verdict) -> &'static str {
    match v {
        Verdict::ThroughTor => "confirmed: traffic from the namespace exits through Tor",
        Verdict::NotThroughTor => {
            "FAILED: check.torproject.org says this is NOT exiting through Tor"
        }
        Verdict::Unverified => {
            "UNVERIFIED: the check could not be completed - this is not a pass"
        }
    }
}

/// What the exit node looks like from the outside.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ExitNode {
    pub ip: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    /// Whether the geo provider recognises the address as a proxy or exit.
    pub is_proxy: Option<bool>,
}

/// The result of a check: the verdict, and what we learned about the exit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckResult {
    pub verdict: Verdict,
    pub exit: Option<ExitNode>,
}

/// Ask the Tor Project whether this connection exits through Tor, and describe
/// the exit node.
///
/// Must be called with the current thread already inside the namespace, which
/// is what makes both requests leave through Tor.
///
/// That the geo lookup goes through Tor is a requirement, not an optimisation.
/// Performed over the ordinary connection it would tell the provider the user's
/// real address *and* which exit node they are using at a known moment - the
/// two facts an observer needs to link them. Through Tor, the provider sees an
/// exit node asking about itself. The answer is identical either way, since it
/// concerns a third party's address; only the question of who learns something
/// about the user differs.
pub async fn check() -> CheckResult {
    let (verdict, ip) = match query().await {
        Ok((Some(true), ip)) => (Verdict::ThroughTor, ip),
        Ok((Some(false), ip)) => (Verdict::NotThroughTor, ip),
        _ => (Verdict::Unverified, None),
    };

    // Only describe an exit we actually reached through Tor. Looking up the
    // address behind a NotThroughTor verdict would mean asking a third party
    // about the user's own IP, over the very connection that failed to be
    // anonymous.
    let exit = match (&verdict, &ip) {
        (Verdict::ThroughTor, Some(ip)) => Some(exit_node(ip).await),
        _ => None,
    };

    CheckResult { verdict, exit }
}

/// Look up an address with ip2location. Best effort: a failure here degrades the
/// display, it does not change the verdict.
async fn exit_node(ip: &str) -> ExitNode {
    let mut node = ExitNode { ip: Some(ip.to_string()), ..Default::default() };

    let Ok(client) = lookup_client() else { return node };
    let url = format!("https://api.ip2location.io/?ip={ip}");

    let Ok(response) = client.get(&url).send().await else { return node };
    let Ok(body) = response.json::<serde_json::Value>().await else { return node };

    let field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
    node.city = field("city_name");
    node.region = field("region_name");
    node.country = field("country_name");
    node.org = field("as");
    node.asn = field("asn");
    node.is_proxy = body.get("is_proxy").and_then(|v| v.as_bool());
    node
}

fn lookup_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("building the lookup client")
}

/// Returns whether this is Tor, and the address seen from outside.
async fn query() -> Result<(Option<bool>, Option<String>)> {
    let client = reqwest::Client::builder()
        // No proxy of any kind: the transparent redirect is the thing under
        // test. If this request succeeds via some other path, the test has
        // failed to test anything, so redirects are disabled too.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("building the verification client")?;

    let body: serde_json::Value = client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await
        .context("reaching check.torproject.org")?
        .json()
        .await
        .context("parsing the check.torproject.org response")?;

    Ok((
        body.get("IsTor").and_then(|v| v.as_bool()),
        body.get("IP").and_then(|v| v.as_str()).map(str::to_string),
    ))
}

/// The Tor Project's own onion service. Used to test that .onion addresses
/// resolve and route, which exercises a different path from ordinary traffic:
/// tor's DNSPort hands back a virtual address from VirtualAddrNetworkIPv4, and
/// the redirect must carry a connection to that address into TransPort.
pub const TOR_PROJECT_ONION: &str =
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/";

/// Fetch an onion service from inside the namespace.
///
/// Must be called with the current thread already in the namespace. Returns the
/// HTTP status on success. A failure here with ordinary traffic working means
/// the automap/virtual-address path is broken rather than the tunnel.
pub async fn check_onion() -> Result<u16> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // Onion services are slower to reach than ordinary sites: the circuit is
        // longer and there is a rendezvous to negotiate.
        .timeout(Duration::from_secs(60))
        .build()
        .context("building the onion client")?;

    let response = client
        .get(TOR_PROJECT_ONION)
        .send()
        .await
        .context("reaching the Tor Project onion service")?;

    Ok(response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_is_never_treated_as_safe() {
        assert!(!Verdict::Unverified.is_confirmed_safe());
        assert!(!Verdict::NotThroughTor.is_confirmed_safe());
        assert!(Verdict::ThroughTor.is_confirmed_safe());
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;

    fn node() -> ExitNode {
        ExitNode {
            ip: Some("46.102.153.133".into()),
            city: Some("Sydney".into()),
            region: Some("New South Wales".into()),
            country: Some("Australia".into()),
            asn: Some("9009".into()),
            org: Some("M247 Europe SRL".into()),
            is_proxy: Some(true),
        }
    }

    #[test]
    fn describes_the_exit_node_when_confirmed() {
        let text = describe_result(&CheckResult {
            verdict: Verdict::ThroughTor,
            exit: Some(node()),
        });
        assert!(text.contains("46.102.153.133"));
        assert!(text.contains("Sydney, New South Wales, Australia"));
        assert!(text.contains("AS9009 M247 Europe SRL"));
        // is_proxy is collected but never displayed: it reads false for real
        // published exits, so showing it would warn on every good connection.
        assert!(!text.contains("proxy"));
    }

    /// The exit node is never described for a failed verdict.
    ///
    /// If traffic is not going through Tor, the address in question is the
    /// user's own - and looking it up would mean telling a third party about it
    /// over the connection that just failed to be anonymous.
    #[test]
    fn says_nothing_about_an_address_when_not_through_tor() {
        for verdict in [Verdict::NotThroughTor, Verdict::Unverified] {
            let text = describe_result(&CheckResult { verdict, exit: None });
            assert!(!text.contains("exit node"));
            assert!(!text.contains("location"));
        }
    }

    #[test]
    fn missing_geo_fields_are_omitted_not_blank() {
        let text = describe_result(&CheckResult {
            verdict: Verdict::ThroughTor,
            exit: Some(ExitNode { ip: Some("1.2.3.4".into()), ..Default::default() }),
        });
        assert!(text.contains("1.2.3.4"));
        assert!(!text.contains("location"));
        assert!(!text.contains("operator"));
    }
}
