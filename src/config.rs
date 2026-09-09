//! Central configuration: names, ports and paths.
//!
//! Every port here is deliberately non-default. tort runs its *own* tor
//! instance rather than reconfiguring the system one, so it must never collide
//! with a tor the user is already running on 9050/9040/9053.

/// Name of the network namespace tort creates.
pub const NETNS: &str = "tort";

/// Host side of the veth pair. Interface names are limited to 15 characters.
pub const VETH_HOST: &str = "tort0";
/// Namespace side of the veth pair.
pub const VETH_NS: &str = "tort-ns";

/// Point-to-point subnet joining the namespace to the host.
pub const HOST_ADDR: &str = "10.66.0.1";
pub const NS_ADDR: &str = "10.66.0.2";
pub const SUBNET_LEN: u8 = 24;
/// The subnet itself, in network form, for firewall matches.
pub const SUBNET: &str = "10.66.0.0/24";

/// tort's own tor ports, bound to the host side of the veth.
pub const TRANS_PORT: u16 = 9140;
pub const DNS_PORT: u16 = 9153;
pub const SOCKS_PORT: u16 = 9150;

/// Tor's control port.
///
/// Bound to host loopback, never to the veth. Anything that can reach this port
/// and authenticate can reconfigure tor - change its exit policy, ask it to
/// build circuits, read its state. A program inside the namespace is exactly
/// what tort exists to contain, so it must not be able to reach it.
pub const CONTROL_PORT: u16 = 9151;

/// Tor writes its control authentication cookie here.
pub const CONTROL_COOKIE: &str = "/run/tort/tor/control_auth_cookie";

/// nftables table name. Everything tort installs lives in this one table so it
/// can be replaced or removed as a single atomic transaction.
pub const NFT_TABLE: &str = "tort";

/// Runtime state. The kernel is the source of truth for whether tort is up
/// (does the namespace exist? is the nft table present? is tor listening?), so
/// these paths hold only what the kernel cannot: the tor config and pidfile.
/// Runtime directory. Stays root-owned and traversable, because the daemon's
/// socket lives here and unprivileged clients must be able to reach it.
pub const RUN_DIR: &str = "/run/tort";

/// tor's own runtime directory, a level down.
///
/// This is separate from RUN_DIR for a specific reason: tor drops to an
/// unprivileged account and needs to own its runtime files, so this directory
/// becomes 0700 and tor-owned. Keeping the daemon's socket in the parent means
/// tightening this one cannot lock clients out of the socket - which is exactly
/// what happened when both lived in the same place.
pub const TOR_RUN_DIR: &str = "/run/tort/tor";

pub const DATA_DIR: &str = "/var/lib/tort";
pub const TORRC: &str = "/run/tort/tor/torrc";
/// Where the privileged daemon listens.
pub const SOCKET_PATH: &str = "/run/tort/tortd.sock";
pub const TOR_PID: &str = "/run/tort/tor/tor.pid";
/// tor daemonises, so its own log is the only account of why it died.
pub const TOR_LOG: &str = "/run/tort/tor/tor.log";

/// `ip netns exec` bind-mounts /etc/netns/<name> over /etc inside the
/// namespace, which is how the namespace gets its own resolv.conf without the
/// host's ever being touched.
pub const NETNS_ETC: &str = "/etc/netns/tort";

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's socket must not live inside the directory tor owns.
    ///
    /// tor drops privileges and needs its runtime directory to be 0700 and
    /// tor-owned. When the socket shared that directory, bringing the tunnel up
    /// made it untraversable for unprivileged users, and every subsequent CLI
    /// command reported the daemon as missing while it was running perfectly
    /// well. The paths must stay disjoint.
    #[test]
    fn socket_is_outside_the_tor_owned_directory() {
        assert!(
            !SOCKET_PATH.starts_with(&format!("{TOR_RUN_DIR}/")),
            "the socket would become unreachable once tor tightens its directory"
        );
    }

    /// tor's files must live below the runtime directory, not beside the socket.
    #[test]
    fn tor_runtime_files_are_in_tors_own_directory() {
        for path in [TORRC, TOR_PID, TOR_LOG] {
            assert!(
                path.starts_with(&format!("{TOR_RUN_DIR}/")),
                "{path} should be inside {TOR_RUN_DIR}"
            );
        }
    }
}
