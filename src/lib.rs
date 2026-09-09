//! tort — run applications inside a network namespace whose only route out is Tor.
//!
//! The crate is a library so that more than one front end can speak to the
//! daemon: the `tort` CLI and the `tortunnel` GUI share the client, the wire
//! protocol and the types that cross it, rather than each having its own idea
//! of what a circuit or a status report is.

pub mod client;
pub mod config;
pub mod control;
pub mod daemon;
pub mod netns;
pub mod nft;
pub mod polkit;
pub mod privileged;
pub mod proto;
pub mod run;
pub mod tor;
pub mod verify;
