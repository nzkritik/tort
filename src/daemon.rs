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
    let request: Request = serde_json::from_str(&line)
        .context("the client sent a malformed request")?;

    eprintln!("tortd: uid={uid} pid={pid} requests: {}", request.describe());

    if let Some(action) = request.polkit_action() {
        match polkit::check(action, pid, uid)? {
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
            let mut out = ProgressSink::new(fds.get(1));
            match DirectRoot.up_and_verify(&mut out) {
                Ok(output) => Response::Ok { output },
                Err(e) => Response::Failed { message: format!("{e:#}") },
            }
        }
        Request::Down => match DirectRoot.down() {
            Ok(()) => Response::Ok { output: "tort is down.".into() },
            Err(e) => Response::Failed { message: format!("{e:#}") },
        },
        Request::Status => Response::Ok { output: status_text() },
        Request::Verify => match run::verify_in_namespace() {
            Ok(v) => Response::Ok { output: verify::describe(v).into() },
            Err(e) => Response::Failed { message: format!("{e:#}") },
        },
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

fn status_text() -> String {
    let ns = netns::exists();
    let rules = nft::is_installed();
    let tor_up = tor::is_running();

    let mut out = String::new();
    out.push_str(&format!("namespace      : {}\n", present(ns)));
    out.push_str(&format!("nftables table : {}\n", present(rules)));
    out.push_str(&format!("tor            : {}\n", present(tor_up)));
    out.push_str(if ns && rules && tor_up {
        "\ntort is up."
    } else if !ns && !rules && !tor_up {
        "\ntort is down."
    } else {
        "\ntort is in a PARTIAL state. Run `tort down` to clean up."
    });
    out
}

fn present(b: bool) -> &'static str {
    if b { "present" } else { "absent" }
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


