//! The unprivileged side: talking to the daemon.
//!
//! This runs as the ordinary user. It holds no privilege, and the only thing it
//! can ask for is one of the verbs in `proto::Request`.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, IoSlice, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::config::SOCKET_PATH;
use crate::proto::{Request, Response};

/// Session variables a graphical application needs.
///
/// A curated list rather than the whole environment: the daemon should carry
/// across what a session requires, not whatever the caller happens to have set.
/// The command runs as the calling user, so nothing here can raise privilege -
/// PATH included, since a hostile PATH would only affect that user's own
/// processes, exactly as it would without tort.
const SESSION_VARS: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "DBUS_SESSION_BUS_ADDRESS",
    "XAUTHORITY",
    "XCURSOR_SIZE",
    "XCURSOR_THEME",
    "LANG",
    "TERM",
    "PATH",
];

pub fn session_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = SESSION_VARS
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();

    // Under sudo, env_reset has already removed most of the above, so fill the
    // gaps by discovery. This is needed on the direct-root path; through the
    // daemon the client is an ordinary process and its environment is intact.
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse::<u32>().ok())
        .unwrap_or_else(|| nix::unistd::Uid::current().as_raw());

    let has = |env: &[(String, String)], k: &str| env.iter().any(|(n, _)| n == k);
    let runtime_dir = format!("/run/user/{uid}");

    if !has(&env, "XDG_RUNTIME_DIR") && Path::new(&runtime_dir).exists() {
        env.push(("XDG_RUNTIME_DIR".into(), runtime_dir.clone()));
    }
    if !has(&env, "DBUS_SESSION_BUS_ADDRESS") {
        let bus = format!("{runtime_dir}/bus");
        if Path::new(&bus).exists() {
            env.push(("DBUS_SESSION_BUS_ADDRESS".into(), format!("unix:path={bus}")));
        }
    }
    if !has(&env, "WAYLAND_DISPLAY") {
        if let Some(d) = find_wayland_socket(&runtime_dir) {
            env.push(("WAYLAND_DISPLAY".into(), d));
        }
    }
    if !has(&env, "DISPLAY") {
        if let Some(d) = find_x11_display() {
            env.push(("DISPLAY".into(), d));
        }
    }

    env
}

/// The first Wayland socket in the runtime directory, sorted so the choice is
/// deterministic when a session has several.
fn find_wayland_socket(runtime_dir: &str) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(runtime_dir)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
        .collect();
    names.sort();
    names.into_iter().next()
}

/// The first X11 display socket. Entries ending in "_" are abstract-socket
/// companions rather than displays in their own right.
fn find_x11_display() -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir("/tmp/.X11-unix")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_prefix('X').map(str::to_string))
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        .collect();
    names.sort();
    names.into_iter().next().map(|n| format!(":{n}"))
}

/// Connect to the daemon, or None if it is not there.
///
/// There is deliberately no separate "is the daemon available?" probe. The
/// obvious one - connect, then drop the connection - makes the daemon accept a
/// client that never speaks, and log a malformed-request error on every single
/// CLI invocation. Connect once and use that connection for the real request.
pub fn connect() -> Option<UnixStream> {
    UnixStream::connect(SOCKET_PATH).ok()
}

/// Send a request on an established connection and return the response.
///
/// `stdio` is passed for `Run`: the daemon has no terminal of its own, so the
/// caller lends it these descriptors over SCM_RIGHTS.
pub fn send(stream: &UnixStream, request: &Request, stdio: Option<[RawFd; 3]>) -> Result<Response> {
    let mut line = serde_json::to_string(request)?;
    line.push('\n');

    match stdio {
        Some(fds) => send_with_fds(stream, line.as_bytes(), &fds)?,
        None => {
            let mut s = stream;
            s.write_all(line.as_bytes())?;
            s.flush()?;
        }
    }

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .context("reading the daemon's response")?;

    if response.trim().is_empty() {
        bail!("the daemon closed the connection without replying");
    }

    serde_json::from_str(response.trim()).context("the daemon sent a malformed response")
}

/// Write the request with the caller's stdio attached as ancillary data.
fn send_with_fds(stream: &UnixStream, payload: &[u8], fds: &[RawFd; 3]) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};

    let iov = [IoSlice::new(payload)];
    let cmsg = [ControlMessage::ScmRights(fds)];

    sendmsg::<()>(
        stream.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::empty(),
        None,
    )
    .context("sending the request with the caller's terminal attached")?;
    Ok(())
}

/// Print a response and turn it into a process exit code.
pub fn report(response: Response) -> i32 {
    match response {
        Response::Ok { output } => {
            if !output.is_empty() {
                println!("{output}");
            }
            0
        }
        Response::Exited { code } => code,
        // Structured responses are rendered by whichever front end asked; the
        // CLI formats them itself so the daemon does not have to guess whether
        // it is talking to a terminal or a widget.
        Response::Status(report) => {
            println!("{}", crate::verify::describe_status(&report));
            0
        }
        Response::Circuits { circuits } => {
            println!("{}", crate::control::describe(&circuits));
            0
        }
        Response::Failed { message } => {
            eprintln!("tort: {message}");
            1
        }
        Response::Denied { message } => {
            eprintln!("tort: not authorized: {message}");
            // Distinguished from a failure on purpose: nothing was attempted,
            // and the fix is a policy or a password, not a bug report.
            77
        }
    }
}
