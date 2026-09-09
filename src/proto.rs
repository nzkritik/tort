//! The wire protocol between the tort client and the daemon.
//!
//! This *is* the privilege boundary. Everything root does on a caller's behalf
//! has to be expressible here, so keeping the vocabulary small is a security
//! property rather than a matter of taste: an attacker who fully controls the
//! socket can ask for these operations and nothing else. Compare running the
//! whole tool under sudo, where the boundary is "may execute arbitrary
//! commands as root".

use serde::{Deserialize, Serialize};

/// One request, sent as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Create the namespace, start tor, install the rules, verify.
    Up,
    /// Remove everything.
    Down,
    /// Report what is present, read from the kernel.
    Status,
    /// Verify from inside the namespace that traffic exits via Tor.
    Verify,
    /// Fetch a known onion service from inside the namespace.
    Onion,
    /// List the circuits tor has built, hop by hop.
    Route,
    /// Run a command inside the namespace as the calling user.
    ///
    /// The client passes its stdin, stdout and stderr alongside this message as
    /// SCM_RIGHTS file descriptors; the daemon never opens a terminal itself.
    Run {
        argv: Vec<String>,
        /// Session variables from the caller's environment.
        ///
        /// The daemon has no session of its own - no DISPLAY, no D-Bus address -
        /// so a graphical application would not start without these. A curated
        /// list is passed rather than the whole environment: the daemon should
        /// carry across what a session needs, not whatever the caller happens
        /// to have set. The command runs as the calling user, so these
        /// influence only that user's own processes.
        env: Vec<(String, String)>,
    },
}

impl Request {
    /// The polkit action this request must be authorized against.
    ///
    /// Status is deliberately unauthenticated: it only reports what the kernel
    /// already knows and changes nothing, and requiring a password to ask
    /// "am I protected right now?" would discourage people from checking.
    pub fn polkit_action(&self) -> Option<&'static str> {
        match self {
            Request::Up | Request::Down => Some("io.github.nzkritik.tort.manage"),
            // Route is authorized like run, not like status. It names the
            // guard relay, which is long-lived and identifies its user far more
            // than an exit address does; on a machine with other local accounts
            // that is not something to hand out unauthenticated.
            Request::Verify | Request::Onion | Request::Route | Request::Run { .. } => {
                Some("io.github.nzkritik.tort.run")
            }
            Request::Status => None,
        }
    }

    /// Short description used in the audit log line the daemon writes.
    pub fn describe(&self) -> String {
        match self {
            Request::Up => "up".into(),
            Request::Down => "down".into(),
            Request::Status => "status".into(),
            Request::Verify => "verify".into(),
            Request::Onion => "onion".into(),
            Request::Route => "route".into(),
            Request::Run { argv, .. } => format!("run {}", argv.join(" ")),
        }
    }
}

/// One response, sent as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The operation succeeded. `output` is text for the user.
    Ok { output: String },
    /// The operation ran and failed. `message` explains why.
    Failed { message: String },
    /// polkit declined. Not the same as a failure: nothing was attempted.
    Denied { message: String },
    /// A command finished with this exit status.
    Exited { code: i32 },
}
