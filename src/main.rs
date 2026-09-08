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

mod config;
mod netns;
mod nft;
mod privileged;
mod tor;
mod verify;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Gid, Uid};
use std::ffi::CString;

use config::*;
use privileged::{DirectRoot, Privileged};
use verify::Verdict;

#[derive(Parser)]
#[command(name = "tort", about = "Tor Tunnel - run applications inside a Tor-only network namespace")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create the namespace, start tor, and install the redirect rules.
    Up,
    /// Remove the rules, stop tor, and delete the namespace.
    Down,
    /// Show what is actually running, as read from the kernel.
    Status,
    /// Run a command inside the Tor-only namespace.
    Run {
        /// The command and its arguments.
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Start a shell inside the Tor-only namespace.
    Shell,
    /// Verify from inside the namespace that traffic really exits via Tor.
    Verify,
    /// Print the nftables ruleset without applying it.
    Ruleset,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Unprivileged: just prints generated text.
        Commands::Ruleset => {
            print!("{}", nft::ruleset());
            Ok(())
        }
        Commands::Status => cmd_status(),
        Commands::Up => {
            require_root("up")?;
            cmd_up()
        }
        Commands::Down => {
            require_root("down")?;
            cmd_down()
        }
        Commands::Verify => {
            require_root("verify")?;
            report_verdict(verify_in_namespace()?);
            Ok(())
        }
        Commands::Run { argv } => {
            require_root("run")?;
            cmd_run(&argv)
        }
        Commands::Shell => {
            require_root("shell")?;
            let shell = invoking_user_shell();
            cmd_run(&[shell])
        }
    }
}

/// setns and mount operations need CAP_SYS_ADMIN. Checking the effective uid is
/// the right test here - unlike torc, which checked whether $SUDO_USER was set,
/// an inherited environment variable that says nothing about privilege.
fn require_root(what: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("`tort {what}` needs root: run it with sudo");
    }
    Ok(())
}

fn cmd_up() -> Result<()> {
    if DirectRoot.is_up() {
        println!("tort is already up.");
        return Ok(());
    }

    println!("Creating namespace, starting tor, installing rules...");
    DirectRoot.up()?;

    println!("Verifying that traffic actually exits through Tor...");
    let verdict = verify_in_namespace()?;
    report_verdict(verdict);

    // Fail closed. If we cannot prove the tunnel works, we do not leave it up
    // for the user to trust. torc's equivalent path printed a success banner
    // and carried on.
    if !verdict.is_confirmed_safe() {
        eprintln!("\nRefusing to leave a tunnel up that could not be verified. Tearing down.");
        let _ = DirectRoot.down();
        bail!("tort could not confirm traffic exits through Tor");
    }

    println!("\ntort is up. Run applications with:  sudo tort run <command>");
    Ok(())
}

/// Tear down, reporting only what was actually there.
///
/// The first version printed "the namespace, rules and tor instance are gone"
/// unconditionally - including when nothing had been running, so it claimed to
/// have done work it had not. That is the same unconditional-success reporting
/// this project exists to avoid, so teardown now names what it removed and
/// re-reads the kernel afterwards to confirm it really went.
fn cmd_down() -> Result<()> {
    let before = (netns::exists(), nft::is_installed(), tor::is_running());

    if !before.0 && !before.1 && !before.2 {
        println!("tort was not up - nothing to do.");
        return Ok(());
    }

    let result = DirectRoot.down();

    // Re-read from the kernel rather than trusting that down() succeeded.
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

fn cmd_status() -> Result<()> {
    let ns = netns::exists();
    let rules = nft::is_installed();
    let tor_up = tor::is_running();

    println!("namespace {NETNS:>12}: {}", yes_no(ns));
    println!("nftables table {NFT_TABLE:>7}: {}", yes_no(rules));
    println!("tor TransPort {TRANS_PORT:>8}: {}", yes_no(tor_up));

    if ns && rules && tor_up {
        println!("\ntort is up.");
        if Uid::effective().is_root() {
            report_verdict(verify_in_namespace()?);
        } else {
            println!("Run `sudo tort verify` to confirm traffic exits through Tor.");
        }
    } else if !ns && !rules && !tor_up {
        println!("\ntort is down.");
    } else {
        // Partial state is worth flagging rather than glossing over.
        println!("\ntort is in a PARTIAL state. Run `sudo tort down` to clean up.");
    }
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b { "present" } else { "absent" }
}

fn report_verdict(v: Verdict) {
    match v {
        Verdict::ThroughTor => println!("  confirmed: traffic from the namespace exits through Tor"),
        Verdict::NotThroughTor => {
            println!("  FAILED: check.torproject.org says this is NOT exiting through Tor")
        }
        Verdict::Unverified => {
            println!("  UNVERIFIED: the check could not be completed - this is not a pass")
        }
    }
}

/// Run the verification inside the namespace, in a forked child.
///
/// Forking rather than entering the namespace in this process keeps the parent
/// where it started, so `up` can continue and tear down on failure. The child
/// is single-threaded at the moment it calls setns, and only afterwards builds
/// a current-thread runtime - so every thread that could exist is already in
/// the right namespace.
fn verify_in_namespace() -> Result<Verdict> {
    match unsafe { fork() }.context("fork for verification")? {
        ForkResult::Child => {
            let code = match netns::enter() {
                Err(_) => 2,
                Ok(()) => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match rt {
                        Err(_) => 2,
                        Ok(rt) => match rt.block_on(verify::check()) {
                            Verdict::ThroughTor => 0,
                            Verdict::NotThroughTor => 1,
                            Verdict::Unverified => 2,
                        },
                    }
                }
            };
            std::process::exit(code);
        }
        ForkResult::Parent { child } => match waitpid(child, None).context("waiting for check")? {
            WaitStatus::Exited(_, 0) => Ok(Verdict::ThroughTor),
            WaitStatus::Exited(_, 1) => Ok(Verdict::NotThroughTor),
            _ => Ok(Verdict::Unverified),
        },
    }
}

/// Run a command inside the namespace as the invoking (non-root) user.
fn cmd_run(argv: &[String]) -> Result<()> {
    if !DirectRoot.is_up() {
        bail!("tort is not up - run `sudo tort up` first");
    }

    match unsafe { fork() }.context("fork to run the command")? {
        ForkResult::Child => {
            if let Err(e) = enter_and_exec(argv) {
                eprintln!("tort: {e:#}");
                std::process::exit(127);
            }
            unreachable!("execvp replaces the process");
        }
        ForkResult::Parent { child } => match waitpid(child, None).context("waiting for command")? {
            WaitStatus::Exited(_, code) => std::process::exit(code),
            WaitStatus::Signaled(_, sig, _) => bail!("command killed by signal {sig:?}"),
            _ => Ok(()),
        },
    }
}

fn enter_and_exec(argv: &[String]) -> Result<()> {
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};

    netns::enter()?;

    // setns(CLONE_NEWNET) changes only the network namespace, so the process
    // would still read the host's /etc/resolv.conf. Replicate what
    // `ip netns exec` does: a private mount namespace with the namespace's own
    // resolv.conf bound over it.
    //
    // This is belt and braces - the nftables rule redirects UDP/53 to any
    // destination, so DNS reaches tor even with the wrong resolver configured -
    // but the process should still see the truth.
    unshare(CloneFlags::CLONE_NEWNS).context("unshare mount namespace")?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("making mounts private")?;

    let ns_resolv = format!("{NETNS_ETC}/resolv.conf");
    if std::path::Path::new(&ns_resolv).exists() {
        mount(
            Some(ns_resolv.as_str()),
            "/etc/resolv.conf",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("binding the namespace resolv.conf")?;
    }

    drop_privileges()?;

    let prog = CString::new(argv[0].as_str()).context("command name")?;
    let args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).context("argument"))
        .collect::<Result<_>>()?;

    execvp(&prog, &args).with_context(|| format!("executing {}", argv[0]))?;
    unreachable!()
}

/// Drop back to the user who invoked sudo.
///
/// A browser launched by `sudo tort run firefox` must not run as root. Note
/// this is the *correct* use of $SUDO_UID - identifying who invoked us - as
/// opposed to torc's use of $SUDO_USER as a stand-in for "are we privileged",
/// which it is not.
fn drop_privileges() -> Result<()> {
    let (uid, gid) = match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        (Ok(u), Ok(g)) => (
            u.parse::<u32>().context("SUDO_UID was not a number")?,
            g.parse::<u32>().context("SUDO_GID was not a number")?,
        ),
        _ => {
            eprintln!("tort: warning - cannot determine the invoking user; running as root");
            return Ok(());
        }
    };

    if uid == 0 {
        return Ok(());
    }

    // Order matters: drop supplementary groups and the gid before the uid,
    // because after setuid we no longer have the privilege to do either.
    nix::unistd::setgroups(&[Gid::from_raw(gid)]).context("dropping supplementary groups")?;
    nix::unistd::setgid(Gid::from_raw(gid)).context("dropping gid")?;
    nix::unistd::setuid(Uid::from_raw(uid)).context("dropping uid")?;

    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        bail!("privileges were not actually dropped - refusing to continue");
    }

    std::env::set_var("HOME", home_of(uid));
    std::env::set_var("USER", std::env::var("SUDO_USER").unwrap_or_default());
    Ok(())
}

fn home_of(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|p| {
            p.lines()
                .find(|l| l.split(':').nth(2) == Some(&uid.to_string()))
                .and_then(|l| l.split(':').nth(5).map(str::to_string))
        })
        .unwrap_or_else(|| "/tmp".to_string())
}

fn invoking_user_shell() -> String {
    std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| {
            std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
                p.lines()
                    .find(|l| l.starts_with(&format!("{user}:")))
                    .and_then(|l| l.split(':').nth(6).map(str::to_string))
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string())
}
