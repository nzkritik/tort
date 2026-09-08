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

/// tort's own tor ports, bound to the host side of the veth.
pub const TRANS_PORT: u16 = 9140;
pub const DNS_PORT: u16 = 9153;
pub const SOCKS_PORT: u16 = 9150;

/// nftables table name. Everything tort installs lives in this one table so it
/// can be replaced or removed as a single atomic transaction.
pub const NFT_TABLE: &str = "tort";

/// Runtime state. The kernel is the source of truth for whether tort is up
/// (does the namespace exist? is the nft table present? is tor listening?), so
/// these paths hold only what the kernel cannot: the tor config and pidfile.
pub const RUN_DIR: &str = "/run/tort";
pub const DATA_DIR: &str = "/var/lib/tort";
pub const TORRC: &str = "/run/tort/torrc";
pub const TOR_PID: &str = "/run/tort/tor.pid";

/// `ip netns exec` bind-mounts /etc/netns/<name> over /etc inside the
/// namespace, which is how the namespace gets its own resolv.conf without the
/// host's ever being touched.
pub const NETNS_ETC: &str = "/etc/netns/tort";
