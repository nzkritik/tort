//! The privileged operations, behind a trait.
//!
//! Today there is one implementation, `DirectRoot`, which runs the operations
//! in-process because tort is invoked under sudo. The trait exists so that a
//! socket-activated root daemon can be added later as a second implementation
//! without touching any of the logic in `up`/`down`: the CLI would hold a
//! client that speaks to the daemon, and the daemon would hold `DirectRoot`.
//!
//! Keeping the privilege boundary this narrow is the point. The surface is
//! these four verbs, not "may run arbitrary commands as root".

use anyhow::{bail, Result};

use crate::{netns, nft, tor};

pub trait Privileged {
    fn up(&self) -> Result<()>;
    fn down(&self) -> Result<()>;
    fn is_up(&self) -> bool;
}

pub struct DirectRoot;

impl Privileged for DirectRoot {
    /// Bring tort up.
    ///
    /// Ordering is deliberate: tor must be serving *before* the redirect rules
    /// go in, otherwise there is a window in which the namespace is redirected
    /// at a port nothing is listening on. Because the namespace has no other
    /// route, that window fails closed (connections are refused) rather than
    /// leaking - but refusing to create it at all is better still.
    fn up(&self) -> Result<()> {
        if !tor::is_installed() {
            bail!("tor is not installed - install it with your package manager");
        }

        netns::create()?;

        // From here on, any failure must not leave a half-built namespace
        // behind, so each step tears down on the way out.
        if let Err(e) = tor::start() {
            // tor daemonises, so a failure here - a bootstrap timeout in
            // particular - can leave a live daemon behind. Stop it, or the next
            // run finds its ports already bound.
            let _ = tor::stop();
            let _ = netns::destroy();
            return Err(e);
        }

        if let Err(e) = nft::apply() {
            let _ = tor::stop();
            let _ = netns::destroy();
            return Err(e);
        }

        Ok(())
    }

    /// Take tort down. Each step is independent and best-effort, so one failure
    /// cannot strand the others - in particular the nftables table is removed
    /// first, since that is the piece whose absence is safe and whose presence
    /// could confuse an unrelated debugging session later.
    fn down(&self) -> Result<()> {
        let mut first_error = None;

        if let Err(e) = nft::remove() {
            first_error.get_or_insert(e);
        }
        if let Err(e) = tor::stop() {
            first_error.get_or_insert(e);
        }
        if let Err(e) = netns::destroy() {
            first_error.get_or_insert(e);
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// tort is up when all three pieces are present. Every one of these is read
    /// from the kernel rather than from a state file, so this cannot disagree
    /// with reality after a crash.
    fn is_up(&self) -> bool {
        netns::exists() && nft::is_installed() && tor::is_running()
    }
}
