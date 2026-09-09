//! A minimal client for tor's control protocol.
//!
//! Used only to read circuit information. tort never issues a command that
//! changes tor's behaviour through this connection - it asks questions.
//!
//! The control port is bound to host loopback and authenticated with tor's
//! cookie file, which lives in a directory only root and the tor account can
//! read. Nothing inside the namespace can reach it: that is deliberate, because
//! an authenticated control connection can reconfigure tor entirely, which
//! would let a contained program uncontain itself.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config::{CONTROL_COOKIE, CONTROL_PORT};

/// One hop in a circuit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub nickname: String,
    pub fingerprint: String,
    pub address: Option<String>,
    pub country: Option<String>,
}

/// A circuit tor has built.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Circuit {
    pub id: String,
    pub state: String,
    pub purpose: String,
    pub hops: Vec<Hop>,
}

/// Does this line begin with a three-digit reply code?
///
/// Payload lines can look like protocol lines otherwise, which is how a circuit
/// numbered 100 came to be mistaken for the end of a reply.
fn is_status_line(line: &str) -> bool {
    line.len() >= 4 && line.as_bytes()[..3].iter().all(u8::is_ascii_digit)
}

struct Control {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Control {
    fn connect() -> Result<Self> {
        let addr = format!("127.0.0.1:{CONTROL_PORT}");
        let stream = TcpStream::connect(&addr)
            .with_context(|| format!("connecting to tor's control port at {addr}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let reader = BufReader::new(stream.try_clone()?);
        let mut c = Control { stream, reader };
        c.authenticate()?;
        Ok(c)
    }

    /// Authenticate with the cookie tor wrote at startup.
    ///
    /// Cookie authentication rather than a password: there is no secret to
    /// choose, store or leak, and the file's permissions already express who
    /// may talk to tor.
    fn authenticate(&mut self) -> Result<()> {
        let cookie = std::fs::read(CONTROL_COOKIE).with_context(|| {
            format!("reading {CONTROL_COOKIE} - tort must run as root to read tor's cookie")
        })?;

        let hex: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
        let reply = self.command(&format!("AUTHENTICATE {hex}"))?;
        if !reply.starts_with("250") {
            bail!("tor rejected the control authentication: {reply}");
        }
        Ok(())
    }

    /// Send a command and collect the reply.
    ///
    /// Replies are either a single "250 ..." line or a "250+key=" block ended by
    /// a line containing only ".". Anything not beginning with 250 is an error
    /// and is returned for the caller to report.
    fn command(&mut self, cmd: &str) -> Result<String> {
        writeln!(self.stream, "{cmd}\r")?;
        self.stream.flush()?;

        let mut out = String::new();
        let mut in_data_block = false;

        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                bail!("tor closed the control connection");
            }
            let line = line.trim_end_matches(['\r', '\n']);

            // Inside a data block every line is payload until a lone ".".
            // Tracking the block explicitly is what makes this correct: the
            // previous version decided a line was the final one whenever its
            // fourth byte was a space, which is true of "250 OK" but also of a
            // circuit line with a three-digit id - "100 BUILT ..." - so the
            // circuit list was silently truncated at the hundredth circuit.
            if in_data_block {
                if line == "." {
                    in_data_block = false;
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
                continue;
            }

            if !is_status_line(line) {
                out.push_str(line);
                out.push('\n');
                continue;
            }

            match line.as_bytes().get(3) {
                // "250+key=" opens a data block.
                Some(b'+') => in_data_block = true,
                // "250 ..." is the final line of the reply.
                Some(b' ') => {
                    out.push_str(line);
                    out.push('\n');
                    break;
                }
                // "250-key=value" is a mid-reply line.
                _ => {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        Ok(out)
    }
}

/// Read the circuits tor has currently built.
pub fn circuits() -> Result<Vec<Circuit>> {
    let mut control = Control::connect()?;
    let raw = control.command("GETINFO circuit-status")?;

    let mut circuits = Vec::new();
    for line in raw.lines() {
        // Skip the protocol scaffolding; circuit lines start with an id.
        let line = line.trim();
        if line.starts_with("250") || line.is_empty() || line == "OK" {
            continue;
        }
        if let Some(circuit) = parse_circuit(line) {
            circuits.push(circuit);
        }
    }

    // Fill in each hop's address and country. Best effort: a hop tor no longer
    // has a descriptor for is still worth showing by nickname.
    for circuit in &mut circuits {
        for hop in &mut circuit.hops {
            if let Some(addr) = relay_address(&mut control, &hop.fingerprint) {
                hop.country = relay_country(&mut control, &addr);
                hop.address = Some(addr);
            }
        }
    }

    let _ = control.command("QUIT");
    Ok(circuits)
}

/// Parse one circuit-status line.
///
/// Format: `<id> <state> <path> [key=value ...]`, where path is a comma
/// separated list of `$FINGERPRINT~nickname`. A circuit that is still building
/// may have no path at all, which is why the path is read positionally rather
/// than assumed present.
fn parse_circuit(line: &str) -> Option<Circuit> {
    let mut parts = line.split_whitespace();
    let id = parts.next()?.to_string();
    let state = parts.next()?.to_string();

    let mut hops = Vec::new();
    let mut purpose = String::from("UNKNOWN");

    for part in parts {
        if let Some(value) = part.strip_prefix("PURPOSE=") {
            purpose = value.to_string();
        } else if part.contains('$') {
            for entry in part.split(',') {
                let entry = entry.trim_start_matches('$');
                let (fingerprint, nickname) = match entry.split_once('~') {
                    Some((f, n)) => (f.to_string(), n.to_string()),
                    None => (entry.to_string(), String::from("(unnamed)")),
                };
                hops.push(Hop { nickname, fingerprint, address: None, country: None });
            }
        }
    }

    Some(Circuit { id, state, purpose, hops })
}

/// The advertised address of a relay, from its network-status entry.
fn relay_address(control: &mut Control, fingerprint: &str) -> Option<String> {
    let reply = control.command(&format!("GETINFO ns/id/${fingerprint}")).ok()?;
    // The "r" line is: r nickname identity digest date time ADDRESS ORPort DirPort
    reply
        .lines()
        .find(|l| l.starts_with("r "))
        .and_then(|l| l.split_whitespace().nth(6))
        .map(str::to_string)
}

/// The country tor's own GeoIP database assigns to an address.
///
/// Asking tor rather than a web service keeps this local: no third party learns
/// which relays are in the circuit.
fn relay_country(control: &mut Control, address: &str) -> Option<String> {
    let reply = control.command(&format!("GETINFO ip-to-country/{address}")).ok()?;
    reply
        .lines()
        .find_map(|l| l.split_once('=').map(|(_, v)| v.trim().to_string()))
        .filter(|c| !c.is_empty() && c != "??")
        .map(|c| c.to_uppercase())
}

/// Render circuits for display.
pub fn describe(circuits: &[Circuit]) -> String {
    // Only general-purpose circuits carry the user's traffic. Tor also keeps
    // circuits for directory fetches and onion service work, and listing those
    // makes the output confusing rather than informative.
    let general: Vec<&Circuit> = circuits
        .iter()
        .filter(|c| c.purpose == "GENERAL" && c.state == "BUILT")
        .collect();

    let hidden = circuits.len() - general.len();

    if general.is_empty() {
        return format!(
            "No general-purpose circuits are currently built.{}",
            hidden_note(hidden)
        );
    }

    let mut out = String::new();
    for circuit in general {
        out.push_str(&format!("\ncircuit {} ({})\n", circuit.id, circuit.purpose.to_lowercase()));
        let last = circuit.hops.len().saturating_sub(1);
        for (i, hop) in circuit.hops.iter().enumerate() {
            let role = match i {
                0 => "guard ",
                n if n == last => "exit  ",
                _ => "middle",
            };
            let where_ = match (&hop.address, &hop.country) {
                (Some(a), Some(c)) => format!("{a} ({c})"),
                (Some(a), None) => a.clone(),
                _ => String::from("(no descriptor)"),
            };
            out.push_str(&format!("  {role}  {:<20} {where_}\n", hop.nickname));
        }
    }

    out.push_str(&hidden_note(hidden));

    // Say this in the output rather than only in the docs. Seeing an exit in
    // `status` that appears in none of these circuits is otherwise alarming,
    // when it is ordinary: tor spreads streams over several circuits and
    // retires them continuously, so this is a snapshot and not a record of
    // which circuit carried any particular request.
    if !out.is_empty() {
        out.push_str(
            "\nTor assigns each connection to one of several circuits and retires them\n\
             continuously, so the exit reported by `tort status` is a snapshot from its\n\
             own request and need not appear above.\n",
        );
    }
    out
}

fn hidden_note(hidden: usize) -> String {
    if hidden == 0 {
        String::new()
    } else {
        format!(
            "\n({hidden} further circuit{} not shown: still building, or used for directory\n\
             fetches and onion services rather than for your traffic.)\n",
            if hidden == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_built_circuit() {
        let line = "5 BUILT $AAAA~guardnode,$BBBB~middlenode,$CCCC~exitnode \
                    BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-09-09T00:00:00";
        let c = parse_circuit(line).expect("should parse");
        assert_eq!(c.id, "5");
        assert_eq!(c.state, "BUILT");
        assert_eq!(c.purpose, "GENERAL");
        assert_eq!(c.hops.len(), 3);
        assert_eq!(c.hops[0].nickname, "guardnode");
        assert_eq!(c.hops[2].fingerprint, "CCCC");
    }

    /// A circuit still being built has no path yet, and must not be discarded
    /// or panic the parser.
    #[test]
    fn parses_a_circuit_with_no_path_yet() {
        let c = parse_circuit("7 LAUNCHED PURPOSE=GENERAL").expect("should parse");
        assert_eq!(c.state, "LAUNCHED");
        assert!(c.hops.is_empty());
    }

    /// A three-digit circuit id must not be mistaken for a reply code.
    ///
    /// "100 BUILT ..." has a space in its fourth byte, exactly like "250 OK".
    /// The first parser stopped reading there, silently truncating the circuit
    /// list at the hundredth circuit.
    #[test]
    fn a_three_digit_circuit_id_is_not_a_status_line() {
        assert!(is_status_line("250 OK"));
        assert!(is_status_line("250+circuit-status="));
        assert!(is_status_line("515 Bad authentication"));
        assert!(!is_status_line("7 BUILT $AAAA~guard"));
        // The case that broke it.
        assert!(is_status_line("100 BUILT $AAAA~guard"));
    }

    #[test]
    fn hidden_circuits_are_reported_not_silently_dropped() {
        let circuits = vec![
            Circuit { id: "1".into(), state: "BUILT".into(), purpose: "GENERAL".into(),
                      hops: vec![Hop { nickname: "g".into(), fingerprint: "A".into(),
                                       address: None, country: None }] },
            Circuit { id: "2".into(), state: "LAUNCHED".into(), purpose: "GENERAL".into(), hops: vec![] },
            Circuit { id: "3".into(), state: "BUILT".into(), purpose: "HS_CLIENT_INTRO".into(), hops: vec![] },
        ];
        let text = describe(&circuits);
        assert!(text.contains("2 further circuits not shown"));
    }

    #[test]
    fn only_built_general_circuits_are_shown() {
        let circuits = vec![
            Circuit { id: "1".into(), state: "BUILT".into(), purpose: "HS_CLIENT_INTRO".into(), hops: vec![] },
            Circuit { id: "2".into(), state: "LAUNCHED".into(), purpose: "GENERAL".into(), hops: vec![] },
        ];
        assert!(describe(&circuits).contains("No general-purpose circuits"));
    }
}
