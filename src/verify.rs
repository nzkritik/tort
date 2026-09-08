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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Ask the Tor Project whether this connection exits through Tor.
///
/// Must be called with the current thread already inside the namespace.
pub async fn check() -> Verdict {
    match query().await {
        Ok(Some(true)) => Verdict::ThroughTor,
        Ok(Some(false)) => Verdict::NotThroughTor,
        _ => Verdict::Unverified,
    }
}

async fn query() -> Result<Option<bool>> {
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

    Ok(body.get("IsTor").and_then(|v| v.as_bool()))
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
