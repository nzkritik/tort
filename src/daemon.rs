//! The privileged daemon.
//!
//! Everything root does on a user's behalf happens here, behind a socket whose
//! vocabulary is the five verbs in `proto::Request`. The point is not
//! convenience - it is that the privilege boundary becomes something you can
//! read in one file, instead of "this program may run any command as root
//! because it was invoked under sudo".
//!
//! Three properties hold for every request:
//!
//!   * The caller is identified by the kernel via SO_PEERCRED, not by anything
//!     the caller says about itself.
//!   * Authorization is polkit's decision, made before any work begins.
//!   * A command run in the namespace runs as the calling user, on the
//!     caller's own terminal, which arrives as passed file descriptors. The
//!     daemon never opens a terminal of its own.

use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::SOCKET_PATH;
use crate::polkit::{self, Decision};
use crate::privileged::{DirectRoot, Privileged};
use crate::proto::{Request, Response};
use crate::{netns, nft, run, tor, verify};

/// Serve until killed.
pub fn serve() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("the tort daemon must run as root");
    }

    std::fs::create_dir_all(crate::config::RUN_DIR)?;
    // Traversable by everyone: unprivileged clients have to reach the socket
    // inside. tor's own files live a level down, in a directory it owns.
    std::fs::set_permissions(
        crate::config::RUN_DIR,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )?;

    // A stale socket from a previous run would make bind() fail.
    let _ = std::fs::remove_file(SOCKET_PATH);

    // tor runs as a child of this daemon, so a restart kills it while the
    // namespace and nftables rules survive. That leaves traffic redirected at a
    // port nothing is listening on - fail-closed, but a confusing state to hand
    // a user. Start from a clean slate instead of inheriting half a tunnel.
    if (netns::exists() || nft::is_installed()) && !DirectRoot.is_up() {
        eprintln!("tortd: found a partial tunnel from a previous daemon; cleaning up");
        if let Err(e) = DirectRoot.down() {
            eprintln!("tortd: could not clean up leftover state: {e:#}");
        }
    }

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("binding {SOCKET_PATH}"))?;

    // World-connectable on purpose. Authorization is polkit's job, and it is
    // performed per request; restricting the socket by mode or group would
    // instead bake a second, cruder policy into the filesystem, and would stop
    // polkit from ever being asked. Nothing is done for a caller before its
    // request is authorized.
    std::fs::set_permissions(
        SOCKET_PATH,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666),
    )?;

    eprintln!("tortd listening on {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle(stream) {
                    eprintln!("tortd: request failed: {e:#}");
                }
            }
            Err(e) => eprintln!("tortd: accept failed: {e}"),
        }
    }
    Ok(())
}

/// Handle one connection. Requests are served one at a time: the operations
/// mutate global system state, so overlapping them would be a race with nothing
/// to gain.
fn handle(stream: UnixStream) -> Result<()> {
    // Who is actually calling? The kernel answers, not the client.
    let creds = getsockopt(&stream.as_fd(), PeerCredentials)
        .context("reading peer credentials")?;
    let (pid, uid, gid) = (creds.pid(), creds.uid(), creds.gid());

    // Read the request line, collecting any file descriptors sent with it.
    let Some((line, fds)) = read_request(&stream)? else {
        // The client connected and said nothing. Not an error worth logging -
        // it happens whenever something is checking whether we are listening.
        return Ok(());
    };
    let envelope: crate::proto::Envelope = serde_json::from_str(&line)
        .context("the client sent a malformed request")?;
    let request = envelope.request;

    eprintln!("tortd: uid={uid} pid={pid} requests: {}", request.describe());

    if let Some(action) = request.polkit_action() {
        match polkit::check(action, pid, uid, envelope.interactive)? {
            Decision::Allowed => {}
            Decision::Denied(reason) => {
                eprintln!("tortd: denied uid={uid}: {reason}");
                return reply(&stream, &Response::Denied { message: reason });
            }
        }
    }

    let response = dispatch(request, uid, gid, fds);
    reply(&stream, &response)
}

fn dispatch(request: Request, uid: u32, gid: u32, fds: Vec<OwnedFd>) -> Response {
    match request {
        Request::Up => {
            // Progress goes to the caller's own terminal when they lent it to
            // us, and to the journal otherwise, so a `tort up` triggered by
            // something without a terminal still leaves a record.
            invalidate_check();
            let mut out = ProgressSink::new(fds.get(1));
            match DirectRoot.up_and_verify(&mut out) {
                Ok(output) => Response::Ok { output },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
        Request::Down => {
            invalidate_check();
            match DirectRoot.down() {
                Ok(()) => Response::Ok { output: "tort is down.".into() },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
        Request::Status => Response::Status(status_report()),
        Request::Verify => {
            // An explicit verify always measures afresh: the user asked, so a
            // minute-old answer is not what they wanted.
            invalidate_check();
            match run::verify_in_namespace() {
                Ok(r) => Response::Ok { output: verify::describe_result(&r) },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
        Request::Route => {
            if !DirectRoot.is_up() {
                return Response::Failed { message: "tort is not up - run `tort up` first".into() };
            }
            match crate::control::circuits() {
                Ok(circuits) => Response::Circuits { circuits },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
        Request::Onion => match run::onion_in_namespace() {
            Ok(msg) => Response::Ok { output: msg },
            Err(e) => Response::Failed { message: format!("{e:#}") },
        },
        Request::Run { argv, env } => {
            if !DirectRoot.is_up() {
                return Response::Failed {
                    message: "tort is not up - run `tort up` first".into(),
                };
            }
            if fds.len() != 3 {
                return Response::Failed {
                    message: format!("expected 3 file descriptors from the client, got {}", fds.len()),
                };
            }
            match run::spawn_in_namespace(&argv, uid, gid, &fds, &env) {
                Ok(code) => Response::Exited { code },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
    }
}

/// Writes progress to the caller's terminal and to the journal at once.
///
/// The journal copy matters for a request with no terminal attached; the
/// terminal copy matters because the person waiting is looking at it.
struct ProgressSink {
    client: Option<std::fs::File>,
}

impl ProgressSink {
    fn new(fd: Option<&OwnedFd>) -> Self {
        let client = fd.and_then(|fd| fd.try_clone().ok()).map(std::fs::File::from);
        Self { client }
    }
}

impl std::io::Write for ProgressSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(f) = self.client.as_mut() {
            let _ = f.write_all(buf);
        }
        // Also to stderr, which systemd routes to the journal.
        let _ = std::io::stderr().write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(f) = self.client.as_mut() {
            let _ = f.flush();
        }
        std::io::stderr().flush()
    }
}

/// The most recent verification, and when it was made.
///
/// Verifying costs two HTTP round trips through Tor - several seconds - and the
/// daemon serves one request at a time. Without this, a status poll every ten
/// seconds keeps the daemon busy for a large fraction of its life, and anything
/// the user does meanwhile waits behind it: clicking Disconnect appeared to do
/// nothing for several seconds because its authentication prompt could not be
/// raised until a poll finished talking to check.torproject.org.
///
/// It is also what keeps the exit-node lookups inside a free API's daily quota.
static LAST_CHECK: Mutex<Option<(Instant, crate::verify::CheckResult)>> = Mutex::new(None);

/// How long a verification stays good for. Circuits persist for minutes, so a
/// result from a minute ago still describes the current exit.
const CHECK_TTL: Duration = Duration::from_secs(60);

/// Set to true while a background refresh is in flight, so a burst of polls
/// starts one refresh rather than one each.
static REFRESHING: AtomicBool = AtomicBool::new(false);

/// The most recent verification, refreshing in the background when stale.
///
/// A status request never waits for Tor. If the cached answer has expired the
/// stale one is returned and a refresh is started behind it, so the next poll
/// gets the new value. Blocking instead is what made Disconnect appear to hang:
/// the daemon serves one request at a time, so a poll that stopped to talk to
/// check.torproject.org held everything the user did meanwhile - including the
/// authentication prompt that had not been raised yet.
///
/// A slightly stale exit address is a much smaller problem than an interface
/// that stops responding for several seconds at unpredictable moments.
fn cached_check() -> Option<crate::verify::CheckResult> {
    let cached = LAST_CHECK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    match cached {
        Some((made, result)) if made.elapsed() < CHECK_TTL => Some(result),
        Some((_, stale)) => {
            start_refresh();
            Some(stale)
        }
        // Nothing to show yet, so this one has to wait.
        None => {
            let fresh = crate::run::verify_in_namespace().ok();
            if let Some(result) = &fresh {
                remember_check(result.clone());
            }
            fresh
        }
    }
}

/// Store a verification as the current answer.
pub fn remember_check(result: crate::verify::CheckResult) {
    *LAST_CHECK.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), result));
}

/// Re-verify off the accept loop.
///
/// Safe to do on a thread because the probe re-executes rather than forking: a
/// forked child of a multi-threaded process would inherit locks held by threads
/// that do not exist in it.
fn start_refresh() {
    if REFRESHING.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        if let Ok(result) = crate::run::verify_in_namespace() {
            remember_check(result);
        }
        REFRESHING.store(false, Ordering::SeqCst);
    });
}

/// Drop the cached verification, so the next status re-measures.
///
/// Called whenever the tunnel changes: a result from before a reconnection
/// describes a tunnel that no longer exists.
fn invalidate_check() {
    *LAST_CHECK.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Gather status from the kernel, and verify if there is anything to verify.
fn status_report() -> crate::proto::StatusReport {
    let namespace = netns::exists();
    let rules = nft::is_installed();
    let tor_up = tor::is_running();

    // Measure rather than assert. All three pieces being present says nothing
    // about whether traffic actually reaches Tor through them.
    let check = if namespace && rules && tor_up {
        cached_check()
    } else {
        None
    };

    crate::proto::StatusReport { namespace, rules, tor: tor_up, check }
}

fn reply(mut stream: &UnixStream, response: &Response) -> Result<()> {
    let mut line = serde_json::to_string(response)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Read one request line, together with any descriptors the client attached.
///
/// The descriptors arrive as SCM_RIGHTS ancillary data on the same message, so
/// they must be collected during the recvmsg that reads the request - a plain
/// BufReader would discard them.
fn read_request(stream: &UnixStream) -> Result<Option<(String, Vec<OwnedFd>)>> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::IoSliceMut;

    let mut buf = [0u8; 8192];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 3]);
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )
    .context("receiving the request")?;

    let mut fds = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(received) = cmsg {
            for fd in received {
                // SAFETY: the kernel just created these descriptors for us and
                // no one else owns them.
                fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }

    let len = msg.bytes;
    let line = String::from_utf8_lossy(&buf[..len]).trim().to_string();

    if line.is_empty() {
        // Either the request spans several messages, or the client hung up.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim().to_string();
        return Ok(if line.is_empty() { None } else { Some((line, fds)) });
    }

    Ok(Some((line, fds)))
}


