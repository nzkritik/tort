//! tort - Tor Tunnel.
//!
//! Routes applications through Tor by putting them in a network namespace whose
//! only route leads to a veth pair, where nftables redirects everything to
//! tort's own tor instance.
//!
//! The design property that matters: the namespace has no other path to the
//! network. A missing or broken rule means no connectivity, not a silent leak.
//! Safety is a consequence of the topology rather than of a rule remembering to
//! be there.

use tort::{client, config, control, daemon, netns, nft, privileged, proto, run, tor, verify};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use nix::unistd::Uid;
use std::os::fd::AsRawFd;
use std::path::Path;

use client::report;
use privileged::{DirectRoot, Privileged};
use proto::{Request, Response};

#[derive(Parser)]
#[command(name = "tort", about = "Tor Tunnel - run applications inside a Tor-only network namespace")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create the namespace, start tor, install the redirect rules, and verify.
    Up,
    /// Remove the rules, stop tor, and delete the namespace.
    Down,
    /// Show what is actually running, as read from the kernel.
    Status,
    /// Run a command inside the Tor-only namespace.
    Run {
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Start a shell inside the Tor-only namespace.
    Shell,
    /// Verify from inside the namespace that traffic really exits via Tor.
    Verify,
    /// Fetch a known onion service, testing .onion resolution and routing.
    Onion,
    /// Show the circuits tor has built, hop by hop.
    Route,
    /// Print the nftables ruleset without applying it.
    Ruleset,
    /// Run the privileged daemon. Started by systemd, not by hand.
    #[command(hide = true)]
    Daemon,
    /// Internal: enter the namespace, verify, print JSON. Re-executed by the
    /// daemon so the work happens in a process that was never multi-threaded.
    #[command(name = "__check", hide = true)]
    ProbeCheck,
    /// Internal: enter the namespace and fetch a known onion service.
    #[command(name = "__onion", hide = true)]
    ProbeOnion,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Unprivileged and needs no privilege.
    if let Commands::Ruleset = cli.command {
        print!("{}", nft::ruleset());
        return Ok(());
    }

    if let Commands::Daemon = cli.command {
        return daemon::serve();
    }

    // The probes never return: they print and exit.
    match cli.command {
        Commands::ProbeCheck => run::probe_check(),
        Commands::ProbeOnion => run::probe_onion(),
        _ => {}
    }

    let request = match &cli.command {
        Commands::Up => Request::Up,
        Commands::Down => Request::Down,
        Commands::Status => Request::Status,
        Commands::Verify => Request::Verify,
        Commands::Onion => Request::Onion,
        Commands::Route => Request::Route,
        Commands::Run { argv } => {
            browser_safety_check(argv)?;
            Request::Run { argv: argv.clone(), env: client::session_env() }
        }
        Commands::Shell => Request::Run {
            argv: vec![invoking_user_shell()],
            env: client::session_env(),
        },
        Commands::Ruleset | Commands::Daemon | Commands::ProbeCheck | Commands::ProbeOnion => {
            unreachable!("handled above")
        }
    };

    // Two ways to do the work. Through the daemon, polkit decides whether the
    // caller may proceed and no sudo is involved. Running as root directly is
    // kept for systems without the daemon installed, and for developing it.
    let code = if let Some(stream) = client::connect() {
        via_daemon(&stream, request)?
    } else if Uid::effective().is_root() {
        locally(request)?
    } else {
        bail!(
            "the tort daemon is not running, and this is not root.\n\
             Start it with:  sudo systemctl start tortd\n\
             or run this command under sudo."
        );
    };

    std::process::exit(code);
}

/// Ask the daemon, lending it this process's terminal when running a command.
fn via_daemon(stream: &std::os::unix::net::UnixStream, request: Request) -> Result<i32> {
    let stdio = match request {
        // `up` needs the terminal too: tor's bootstrap takes tens of seconds and
        // the daemon has nowhere else to show progress.
        Request::Up | Request::Run { .. } => Some([
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
            std::io::stderr().as_raw_fd(),
        ]),
        _ => None,
    };

    let is_up = matches!(request, Request::Up);
    // Always interactive: a person typed this command and is waiting, so
    // polkit may stop and ask them for a password.
    let response = client::send(stream, &request, stdio, true)?;

    // The firewall hint is worth showing on a failed `up`, since a host
    // firewall dropping the redirected traffic is the one failure tort cannot
    // fix on the user's behalf.
    if is_up {
        if let Response::Failed { .. } = &response {
            print_firewall_hint();
        }
    }

    Ok(report(response))
}

/// Do the work in this process. Requires root.
fn locally(request: Request) -> Result<i32> {
    match request {
        Request::Up => match DirectRoot.up_and_verify(&mut std::io::stdout()) {
            Ok(output) => {
                println!("{output}");
                Ok(0)
            }
            Err(e) => {
                eprintln!("tort: {e:#}");
                print_firewall_hint();
                Ok(1)
            }
        },
        Request::Down => cmd_down().map(|_| 0),
        Request::Status => {
            println!("{}", verify::describe_status(&local_status()));
            Ok(0)
        }
        Request::Verify => {
            println!("{}", verify::describe_result(&run::verify_in_namespace()?));
            Ok(0)
        }
        Request::Route => {
            if !DirectRoot.is_up() {
                bail!("tort is not up - run `tort up` first");
            }
            println!("{}", control::describe(&control::circuits()?));
            Ok(0)
        }
        Request::Onion => {
            if !DirectRoot.is_up() {
                bail!("tort is not up - run `tort up` first");
            }
            println!("Fetching {} ...", verify::TOR_PROJECT_ONION);
            println!("  {}", run::onion_in_namespace()?);
            Ok(0)
        }
        Request::Run { argv, env } => {
            if !DirectRoot.is_up() {
                bail!("tort is not up - run `tort up` first");
            }
            let (uid, gid) = invoking_user();
            run::spawn_in_namespace(&argv, uid, gid, &[], &env)
        }
    }
}

/// Tear down, reporting only what was actually there.
///
/// The first version printed "the namespace, rules and tor instance are gone"
/// unconditionally - including when nothing had been running, so it claimed to
/// have done work it had not. Teardown now names what it removed and re-reads
/// the kernel afterwards to confirm it really went.
fn cmd_down() -> Result<()> {
    let before = (netns::exists(), nft::is_installed(), tor::is_running());

    if !before.0 && !before.1 && !before.2 {
        println!("tort was not up - nothing to do.");
        return Ok(());
    }

    let result = DirectRoot.down();
    let after = (netns::exists(), nft::is_installed(), tor::is_running());

    for (label, was, still) in [
        ("namespace", before.0, after.0),
        ("nftables table", before.1, after.1),
        ("tor instance", before.2, after.2),
    ] {
        match (was, still) {
            (true, false) => println!("  removed: {label}"),
            (true, true) => println!("  STILL PRESENT: {label}"),
            (false, _) => println!("  (was not present: {label})"),
        }
    }

    result?;
    if after.0 || after.1 || after.2 {
        bail!("teardown did not fully succeed - see above");
    }
    println!("tort is down.");
    Ok(())
}

/// The same report the daemon builds, gathered in this process.
///
/// Both paths produce a StatusReport and both render it with the same
/// function, so the direct and daemon paths cannot describe the same system
/// differently.
fn local_status() -> proto::StatusReport {
    let namespace = netns::exists();
    let rules = nft::is_installed();
    let tor_up = tor::is_running();
    let check = if namespace && rules && tor_up {
        run::verify_in_namespace().ok()
    } else {
        None
    };
    proto::StatusReport { namespace, rules, tor: tor_up, check }
}

fn print_firewall_hint() {
    if !firewall_may_be_interfering() {
        return;
    }
    eprintln!(
        "\nA host firewall is active. tort's rules cannot override it: in netfilter a\n\
         DROP in any table wins, whatever another table accepted. Redirected traffic\n\
         arrives as a NEW inbound connection on {}, which ufw denies by default.\n\
         \n\
         Allow it with:  sudo ufw allow in on {}\n\
         \n\
         That is safe: tort's own input chain still restricts the namespace to tor's\n\
         two ports and drops everything else.",
        config::VETH_HOST, config::VETH_HOST
    );
}

/// Is another firewall active that could be dropping tort's redirected traffic?
///
/// tort deliberately never edits anyone else's rules, so the most it can do is
/// recognise the situation and say exactly what to run.
fn firewall_may_be_interfering() -> bool {
    std::process::Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
        .unwrap_or(false)
}

/// Browsers that hand a new invocation off to an already-running instance.
const HANDOFF_BROWSERS: &[&str] = &[
    "brave", "chrome", "chromium", "firefox", "librewolf", "vivaldi", "opera", "msedge",
];

/// Refuse to launch a browser that would silently open a tab somewhere else.
///
/// Every major browser, started a second time with the same profile, does not
/// start a second browser: it signals the running instance to open a tab and
/// exits. That instance is outside the namespace. The page would load, the user
/// would assume it was tunnelled, and it would not be - traffic leaving through
/// the host's normal route while tort reports success.
///
/// This is the most dangerous thing tort could get wrong, so it fails closed
/// rather than warning.
fn browser_safety_check(argv: &[String]) -> Result<()> {
    let prog = Path::new(&argv[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&argv[0])
        .to_lowercase();

    let Some(browser) = HANDOFF_BROWSERS.iter().find(|b| prog.contains(*b)) else {
        return Ok(());
    };

    let isolated = argv.iter().any(|a| {
        a.starts_with("--user-data-dir") || a.starts_with("--profile") || a == "-P"
    });
    if isolated {
        return Ok(());
    }

    // Is an instance already running outside the namespace?
    let running = std::process::Command::new("pgrep")
        .args(["-x", browser])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if running {
        bail!(
            "{browser} is already running outside the tunnel.\n\
             \n\
             Launching it again would not start a browser inside the namespace: it would\n\
             signal the running instance to open a tab, and that instance is NOT tunnelled.\n\
             The page would load and you would have no indication the traffic went in the\n\
             clear.\n\
             \n\
             Either close {browser} first, or give this instance its own profile:\n\
             \n\
               sudo -E tort run {browser} --user-data-dir=/tmp/tort-{browser}\n"
        );
    }

    eprintln!(
        "tort: note - if {browser} is started outside the tunnel later, it may take over\n\
         this profile. Consider --user-data-dir=/tmp/tort-{browser} for isolation.\n"
    );
    Ok(())
}

/// The uid and gid to run commands as when tort is invoked directly under sudo.
fn invoking_user() -> (u32, u32) {
    let uid = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
    let gid = std::env::var("SUDO_GID").ok().and_then(|g| g.parse().ok());
    match (uid, gid) {
        (Some(u), Some(g)) => (u, g),
        _ => {
            eprintln!("tort: warning - cannot determine the invoking user; running as root");
            (0, 0)
        }
    }
}

fn invoking_user_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string())
}
