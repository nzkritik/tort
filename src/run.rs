//! Operations that execute inside the network namespace.
//!
//! All of these fork first. The child enters the namespace and never comes
//! back, so the parent - which may be a long-lived daemon serving other
//! callers - stays where it is.

use anyhow::{bail, Context, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Gid, Uid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;

use crate::netns;
use crate::verify::{self, CheckResult, Verdict};

/// Run the end-to-end check inside the namespace and bring the result back.
///
/// This re-executes tort rather than forking and doing the work in the child.
/// The distinction matters once the caller may be a thread: a forked child of a
/// multi-threaded process inherits only the forking thread, but inherits every
/// lock, including ones held by threads that no longer exist. Building an async
/// runtime and making TLS connections there is not safe. fork-then-exec is,
/// because exec discards the inherited memory entirely.
///
/// It also means the daemon can refresh its verification on a background thread
/// without the accept loop waiting for Tor.
pub fn verify_in_namespace() -> Result<CheckResult> {
    let output = probe("__check")?;
    serde_json::from_slice(&output).context("the namespace probe returned nothing usable")
}

/// Fetch a known onion service from inside the namespace.
pub fn onion_in_namespace() -> Result<String> {
    let output = probe("__onion")?;
    let text = String::from_utf8_lossy(&output).trim().to_string();
    if text == "ok" {
        Ok("onion service reachable - .onion resolution and routing work".into())
    } else {
        bail!("could not reach the onion service")
    }
}

/// Run one of tort's hidden probe subcommands and collect its output.
fn probe(subcommand: &str) -> Result<Vec<u8>> {
    // /proc/self/exe rather than a name on PATH: the probe must be this exact
    // binary, not whatever a search happens to find.
    let output = Command::new("/proc/self/exe")
        .arg(subcommand)
        .output()
        .with_context(|| format!("running the {subcommand} probe"))?;

    if !output.status.success() {
        bail!(
            "{}",
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("the namespace probe failed")
        );
    }
    Ok(output.stdout)
}

/// The body of `__check`: enter the namespace, verify, print JSON.
///
/// Called in a freshly executed process, so it is single-threaded when it enters
/// the namespace and every thread the runtime later creates inherits it.
pub fn probe_check() -> ! {
    let result = match netns::enter_with_resolver() {
        Err(_) => unverified(),
        Ok(()) => match single_thread_runtime() {
            Err(_) => unverified(),
            Ok(rt) => rt.block_on(verify::check()),
        },
    };

    let json = serde_json::to_string(&result).unwrap_or_default();
    println!("{json}");
    std::process::exit(0);
}

/// The body of `__onion`.
pub fn probe_onion() -> ! {
    let reachable = netns::enter_with_resolver().is_ok()
        && single_thread_runtime()
            .ok()
            .and_then(|rt| rt.block_on(verify::check_onion()).ok())
            .map(|status| (200..400).contains(&status))
            .unwrap_or(false);

    println!("{}", if reachable { "ok" } else { "unreachable" });
    std::process::exit(0);
}

/// The safe answer when anything goes wrong: not a pass.
fn unverified() -> CheckResult {
    CheckResult { verdict: Verdict::Unverified, exit: None }
}

/// A runtime that spawns no worker threads.
///
/// Threads created after setns inherit the namespace, but a multi-threaded
/// runtime built beforehand would not - so the flavour here is part of the
/// correctness argument, not a performance choice.
fn single_thread_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the runtime")
}

/// Run a command inside the namespace as `uid`, returning its exit status.
///
/// `stdio`, when supplied, are the caller's own stdin/stdout/stderr received
/// over the socket. The daemon has no terminal, so without them a command run
/// through it would have nowhere to read from or write to.
pub fn spawn_in_namespace(
    argv: &[String],
    uid: u32,
    gid: u32,
    stdio: &[OwnedFd],
    env: &[(String, String)],
) -> Result<i32> {
    if argv.is_empty() {
        bail!("no command given");
    }

    match unsafe { fork() }.context("fork to run the command")? {
        ForkResult::Child => {
            let result = (|| -> Result<()> {
                if stdio.len() == 3 {
                    for (i, fd) in stdio.iter().enumerate() {
                        nix::unistd::dup2(fd.as_raw_fd(), i as i32)
                            .with_context(|| format!("attaching the caller's fd {i}"))?;
                    }
                }

                netns::enter_with_resolver()?;

                for (k, v) in env {
                    std::env::set_var(k, v);
                }

                // HOME, USER and LOGNAME come from the passwd database rather
                // than from the caller. The caller could say anything, and the
                // daemon is about to run a process as this uid - it should use
                // the system's idea of who that is, not the client's.
                if let Some((home, name)) = passwd_entry(uid) {
                    std::env::set_var("HOME", home);
                    std::env::set_var("USER", &name);
                    std::env::set_var("LOGNAME", &name);
                }

                drop_to_user(uid, gid)?;

                let prog = CString::new(argv[0].as_str())?;
                let args: Vec<CString> = argv
                    .iter()
                    .map(|a| CString::new(a.as_str()).map_err(anyhow::Error::from))
                    .collect::<Result<_>>()?;
                execvp(&prog, &args).with_context(|| format!("executing {}", argv[0]))?;
                Ok(())
            })();

            if let Err(e) = result {
                eprintln!("tort: {e:#}");
            }
            std::process::exit(127);
        }
        ForkResult::Parent { child } => {
            match waitpid(child, None).context("waiting for the command")? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(0),
            }
        }
    }
}

/// The home directory and login name recorded for a uid.
fn passwd_entry(uid: u32) -> Option<(String, String)> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields.get(2) == Some(&uid.to_string().as_str()) {
            Some((fields[5].to_string(), fields[0].to_string()))
        } else {
            None
        }
    })
}

/// Drop to the calling user before exec.
///
/// A browser launched through tort must not run as root. Order matters:
/// supplementary groups and the gid go first, because after setuid the process
/// no longer has the privilege to change either.
fn drop_to_user(uid: u32, gid: u32) -> Result<()> {
    if uid == 0 {
        return Ok(());
    }

    nix::unistd::setgroups(&[Gid::from_raw(gid)]).context("dropping supplementary groups")?;
    nix::unistd::setgid(Gid::from_raw(gid)).context("dropping gid")?;
    nix::unistd::setuid(Uid::from_raw(uid)).context("dropping uid")?;

    // Confirm rather than assume. If privileges were not really dropped, the
    // command would run as root with the user none the wiser.
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        bail!("privileges were not actually dropped - refusing to continue");
    }
    Ok(())
}
