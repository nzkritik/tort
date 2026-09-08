//! polkit authorization for daemon requests.
//!
//! Authorization is delegated to `pkcheck` rather than spoken over D-Bus
//! directly. That keeps the dependency footprint small, and it is the same
//! choice made for `nft` and `ip`: a narrow, well-defined shell-out to the one
//! tool that owns the job, rather than reimplementing it.

use anyhow::{Context, Result};
use std::process::Command;

/// Why a request was allowed or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Denied(String),
}

/// Ask polkit whether a process may perform an action.
///
/// The subject is identified as `pid,start-time,uid` rather than by pid alone.
/// This matters: a pid can be reused, so a caller that exits immediately after
/// connecting could otherwise have its pid taken by an unrelated - possibly
/// more privileged - process before polkit looks at it. The start time comes
/// from the same /proc entry and pins the identity to one specific process.
pub fn check(action: &str, pid: i32, uid: u32) -> Result<Decision> {
    let start_time = process_start_time(pid)
        .with_context(|| format!("reading the start time of pid {pid}"))?;

    let subject = format!("{pid},{start_time},{uid}");

    let output = Command::new("pkcheck")
        .args([
            "--action-id",
            action,
            "--process",
            &subject,
            // Let polkit prompt the user through their session agent. Without
            // this a policy of auth_admin_keep can only ever be refused.
            "--allow-user-interaction",
        ])
        .output()
        .context("running pkcheck - is polkit installed?")?;

    if output.status.success() {
        Ok(Decision::Allowed)
    } else {
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok(Decision::Denied(if reason.is_empty() {
            format!("polkit refused {action}")
        } else {
            reason
        }))
    }
}

/// Field 22 of /proc/<pid>/stat: the process start time in clock ticks.
///
/// Parsed from the end rather than by splitting on whitespace from the start,
/// because field 2 is the executable name in parentheses and may itself contain
/// spaces or parentheses - a process can choose a name like `foo ) 1 2 3` and
/// shift every subsequent field if the split is naive.
fn process_start_time(pid: i32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;

    let after_comm = stat
        .rfind(')')
        .map(|i| &stat[i + 1..])
        .context("malformed /proc stat: no comm terminator")?;

    // After the closing parenthesis, field 3 is state; start time is field 22
    // overall, so index 19 counting state as index 0.
    let start_time = after_comm
        .split_whitespace()
        .nth(19)
        .context("malformed /proc stat: too few fields")?;

    start_time
        .parse::<u64>()
        .context("start time was not a number")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_our_own_start_time() {
        let pid = std::process::id() as i32;
        let t = process_start_time(pid).expect("should read own start time");
        assert!(t > 0, "start time should be non-zero");
    }

    #[test]
    fn start_time_survives_a_hostile_process_name() {
        // A process whose name contains spaces and parentheses would shift the
        // fields of any parser that splits from the left.
        // state, then 18 filler fields, then the start time at index 19.
        let fillers = vec!["0"; 18].join(" ");
        let stat = format!("123 (evil ) 1 2 3) S {fillers} 987654 rest");
        let after = &stat[stat.rfind(')').unwrap() + 1..];
        let field = after.split_whitespace().nth(19).unwrap();
        assert_eq!(field, "987654");
    }
}
