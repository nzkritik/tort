# tort — Tor Tunnel

Run applications inside a network namespace whose only route out is Tor.

> **Prototype.** Verified working on one machine: ordinary traffic exits through
> Tor (confirmed by check.torproject.org), onion services resolve and load, the
> forward-drop counter stays at zero, and the host firewall is byte-identical
> after teardown. That is a great deal less exposure than the tools it borrows
> ideas from have had. Read "What this does not cover" before relying on it.

## At a glance

```console
$ tort up
  tor: 0% (starting): Starting
  tor: 5% (conn): Connecting to a relay
  tor: 14% (handshake): Handshaking with a relay
  tor: 95% (circuit_create): Establishing a Tor circuit
  tor bootstrapped
confirmed: traffic from the namespace exits through Tor
  exit node : 203.0.113.42
  location  : Reykjavik, Capital Region, Iceland
  operator  : AS64500 Example Relay Collective

tort is up. Run applications with:  tort run <command>

$ tort run curl -s https://check.torproject.org/api/ip
{"IsTor":true,"IP":"203.0.113.42"}

$ tort down
tort is down.
```

No `sudo` on any of those. The daemon holds the privilege; polkit decides
whether you may ask.

## The idea

Most "route everything through Tor" tools are **fail-open**: traffic reaches the
internet by default, and firewall rules divert it to Tor. A missing rule, a
crashed tor, or a race at boot means traffic leaves in the clear. You are
maintaining a negative invariant — *nothing escapes* — which can only be
verified by enumerating escape routes. The list never ends.

tort inverts this. Applications run in a network namespace that has:

- exactly one address, on one veth interface,
- exactly one route, pointing at that veth,
- no IPv6 address and no IPv6 route.

The other end of the veth lives on the host, where nftables redirects TCP to
tor's `TransPort` and UDP/53 to tor's `DNSPort`, and drops everything else.

**There is no second path.** A broken rule means no connectivity, not a silent
leak. Safety follows from the topology rather than from a rule remembering to
be in place.

Consequences worth spelling out:

| Problem | How tort avoids it |
|---|---|
| IPv6 leaks | The namespace has no IPv6 address or route. Nothing to leak down. |
| DNS leaks | UDP/53 to *any* destination is redirected to tor's `DNSPort`. |
| QUIC/HTTP3 leaks | UDP is not forwarded, so browsers fall back to TCP, which is redirected. |
| Redirect loops | tor runs outside the namespace, so there is no uid to exclude. |
| Clobbering the host firewall | tort owns one table, `ip tort`, and never flushes a built-in chain. |
| Clobbering the host resolver | The namespace gets its own `/etc/resolv.conf` via `/etc/netns/tort`. |
| Disrupting a system tor | tort runs its own instance, own config, own ports (9140/9150/9153). |
| Stale state after a crash | State is read from the kernel, not from a file. |

## Installing

Requires Rust, `tor`, `nftables`, `iproute2` and `polkit`.

```bash
git clone https://github.com/nzkritik/tort.git
cd tort
sudo ./packaging/install.sh
sudo systemctl enable --now tortd
```

That is all of it. `enable --now` both enables the unit at boot **and** starts
it immediately, so no separate `systemctl start` is needed.

The installer builds the binary, installs it to `/usr/local/bin/tort`, and
installs a polkit policy and a systemd unit. If the daemon is already running it
restarts it, so an install always leaves the running daemon matching the binary
just built.

After this, tort is used **without sudo** — the daemon holds the privilege and
polkit decides whether you may ask for it.

Check it came up:

```console
$ systemctl is-active tortd
active

$ tort status
namespace      : absent
nftables table : absent
tor            : absent

tort is down.
```

### Without installing

You can try it from the build directory. Every command works when run as root
directly, which is how the tool was developed and remains the fallback on
systems without polkit:

```bash
cargo build --release
sudo ./target/release/tort up
```

### Updating

```bash
git pull
sudo ./packaging/install.sh
```

The installer restarts the daemon for you. Note that a restart stops the tor
instance the daemon started, so an active tunnel does not survive an update —
`tort up` again afterwards.

### Uninstalling

```bash
sudo systemctl disable --now tortd
sudo rm /usr/local/bin/tort \
        /etc/systemd/system/tortd.service \
        /usr/share/polkit-1/actions/io.github.nzkritik.tort.policy
sudo systemctl daemon-reload
sudo rm -rf /var/lib/tort
```

`tort down` first if a tunnel is up, so the namespace and firewall rules are
removed while the tool that knows about them is still installed.

## The GUI

```bash
tortunnel
```

A GTK4 front end, built automatically when GTK4 is present. Four areas: a top
bar with connect/disconnect and buttons to run a shell or an application; a
status panel with a coloured Tor indicator; a list of circuits, each with a
colour that will match its path on the map; and the map itself, which is not
drawn yet.

It is **unprivileged**, like the CLI. Every privileged operation goes to the
daemon and is authorized through polkit, so your desktop's own authentication
dialog appears when one is needed. Nothing here runs as root — which matters for
a process that also renders widgets and parses network data.

Three details worth knowing:

- The status indicator has **three** states, not two. "Up but unverified" is
  shown as its own thing rather than as connected, because the whole design
  rests on not claiming what has not been measured.
- **Run shell** launches your terminal emulator running `tort shell`, and
  **Run app** shells out to `tort run`. The GUI does not reimplement either: the
  CLI already lends the daemon its terminal, drops to the calling user and
  performs the browser-handoff check.
- Circuit colours are paired with the circuit number everywhere they appear, so
  nothing depends on colour vision.

Requests run on worker threads. `up` takes tens of seconds to bootstrap tor, and
a GUI that blocks its main loop for that long looks like one that has crashed.

## Usage

| Command | What it does |
|---|---|
| `tort up` | Create the namespace, start tor, install the rules, verify |
| `tort run <cmd>` | Run one command inside the tunnel, as you |
| `tort shell` | Interactive shell inside the tunnel |
| `tort status` | What is actually running, read from the kernel |
| `tort verify` | Confirm traffic exits through Tor |
| `tort route` | Show the circuits tor has built, hop by hop |
| `tort onion` | Fetch a known onion service |
| `tort down` | Remove everything |
| `tort ruleset` | Print the nftables ruleset without applying it |
| `tortunnel` | GTK4 graphical front end (see above) |

Commands that change state or enter the namespace are authorized through polkit.
`status` is not: it reads kernel state and changes nothing, and requiring a
password to ask "am I protected right now?" would discourage checking.

### `tort up`

Verifies before returning, and **tears itself down if it cannot confirm** that
traffic exits through Tor. It will not leave a tunnel up that it could not prove
works:

```console
$ tort up
  tor: 0% (starting): Starting
  tor: 95% (circuit_create): Establishing a Tor circuit
  tor bootstrapped
confirmed: traffic from the namespace exits through Tor
  exit node : 203.0.113.42
  location  : Reykjavik, Capital Region, Iceland
  operator  : AS64500 Example Relay Collective

tort is up. Run applications with:  tort run <command>
```

A failure looks like this, and leaves nothing behind:

```console
$ tort up
  tor bootstrapped
UNVERIFIED: the check could not be completed - this is not a pass

Rule counters at the point of failure:
    iifname "tort0" udp dport 53 counter packets 0 bytes 0 redirect to :9153
    iifname "tort0" meta l4proto tcp counter packets 0 bytes 0 redirect to :9140

Refusing to leave a tunnel up that could not be verified, so it was torn down.
```

Zero on a redirect counter means the packets never reached the rule. A non-zero
counter with no connectivity means something downstream dropped them. Those need
different fixes, which is why the counters are printed rather than a generic
failure message.

### `tort status`

```console
$ tort status
namespace      : present
nftables table : present
tor            : present

tort is up.
confirmed: traffic from the namespace exits through Tor
  exit node : 198.51.100.7
  location  : Bucharest, Bucuresti, Romania
  operator  : AS64501 Example Hosting Ltd
```

Every line is measured, not asserted. Presence is read from the kernel, and the
verdict comes from a request made through the tunnel. Three verdicts are
possible and kept distinct — `confirmed`, `FAILED`, and `UNVERIFIED` — because
"could not check" is not "safe":

```console
$ tort status
namespace      : present
nftables table : present
tor            : absent

tort is in a PARTIAL state. Run `tort down` to clean up.
```

### `tort run`

Runs the command inside the tunnel, as you, on your terminal:

```console
$ tort run curl -s https://ifconfig.me
203.0.113.42

$ tort run firefox --profile /tmp/tort-firefox
```

### `tort route`

```console
$ tort route

circuit 7 (general)
  guard   ExampleGuard         192.0.2.10 (DE)
  middle  ExampleMiddle        198.51.100.22 (NL)
  exit    ExampleExit          203.0.113.42 (IS)

circuit 8 (general)
  guard   ExampleGuard         192.0.2.10 (DE)
  middle  AnotherMiddle        198.51.100.91 (FR)
  exit    AnotherExit          203.0.113.77 (RO)

(2 further circuits not shown: still building, or used for directory
 fetches and onion services rather than for your traffic.)

Tor assigns each connection to one of several circuits and retires them
continuously, so the exit reported by `tort status` is a snapshot from its
own request and need not appear above.
```

The same guard appears in both circuits, which is expected: guards are chosen
rarely and kept for months, because changing them often is what exposes you.

### `tort onion`

```console
$ tort onion
Fetching http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/ ...
  onion service reachable - .onion resolution and routing work
```

### `tort down`

Names what it removed, and re-reads the kernel to confirm it went:

```console
$ tort down
  removed: namespace
  removed: nftables table
  removed: tor instance
tort is down.

$ tort down
tort was not up - nothing to do.
```

### `tort ruleset`

Prints the exact nftables ruleset that `up` would apply, without applying it.
Needs no privilege, so it is the cheapest way to review what tort does to your
firewall before letting it near one.

## Design notes

**nftables, applied atomically.** The whole ruleset is generated as text and
piped to `nft -f` using the `add`/`delete`/`define` idiom, so it applies as one
transaction. There is no window where half the rules are live, and nothing to
roll back — a failed apply changes nothing. `tort ruleset` prints exactly what
would be applied.

**Drops are scoped, never policies.** nftables evaluates the chains of every
table registered on a hook, so `policy drop` in tort's table would drop traffic
belonging to docker, libvirt or any VM on the host. Every drop is scoped to
tort's own interface. There is a test asserting no chain sets a drop policy.

**setns is called on a single-threaded process.** `setns(2)` moves only the
calling thread, and threads created afterwards inherit the namespace. tort
enters the namespace *before* building a current-thread tokio runtime. This
ordering is why the project is in Rust: a runtime that spawns threads implicitly
makes it very hard to reason about, which is why runc implements namespace entry
in C rather than in Go.

**Verification is end-to-end.** The check runs *inside* the namespace with no
proxy configured. If `check.torproject.org` reports `IsTor: true`, the
transparent redirect demonstrably works, because nothing else could have carried
the request. Three outcomes are kept distinct — confirmed, confirmed-not, and
unverified — and unverified is never treated as a pass.

**The privilege boundary is six verbs, not a shell.** A root daemon holds every
privileged operation; the CLI is an ordinary unprivileged process that can ask
for `up`, `down`, `status`, `verify`, `onion` or `run` and nothing else. Compare
running the whole tool under sudo, where the boundary is "may execute arbitrary
commands as root".

Three properties hold for every request:

- The caller is identified by the kernel through `SO_PEERCRED`, never by
  anything the caller says about itself.
- Authorization is polkit's decision, taken before any work begins. The subject
  is passed as `pid,start-time,uid` rather than a bare pid, so a caller that
  exits immediately cannot have its pid reused by a more privileged process
  before polkit looks at it.
- A command runs as the calling user, on the caller's own terminal, which
  arrives as passed file descriptors — the daemon never opens a terminal.

Because the daemon is long-lived it also fixes by construction the bug torc had
structurally: connect and disconnect are no longer separate processes with
separate ideas of the current state.

## Verifying it yourself

`scripts/smoke-test.sh` runs the whole lifecycle as root, snapshots the host
firewall before and after, and prints the rule counters:

```console
$ sudo ./scripts/smoke-test.sh

=== rule counters (which rules actually matched) ===
  iifname "tort0" udp dport 53 counter packets 4 bytes 308 redirect to :9153
  iifname "tort0" meta l4proto tcp counter packets 31 bytes 1860 redirect to :9140
  iifname "tort0" counter packets 0 bytes 0 drop            # forward chain
  iifname "tort0" tcp dport 9140 counter packets 31 bytes 1860 accept

=== SUMMARY ===
tort up      : OK
traffic test : {"IsTor":true,"IP":"203.0.113.42"}
onion test   : reachable
tort down    : exit 0
leftover     : tort is down.
firewall     : unchanged - tort left no structural trace
```

The counters are the useful part when something is wrong. `forward ... drop` at
zero packets means nothing escaped the namespace; a redirect counter at zero
means traffic never reached the rule at all, which is a different problem from a
non-zero counter with no connectivity - that means something downstream dropped
it.

## Running a browser

```bash
tort run brave --user-data-dir=/tmp/tort-brave
```

sudo's `env_reset` strips `DISPLAY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR` and
the D-Bus address, and without them a graphical application exits immediately
with something like "Failed to connect to Wayland display". tort discovers all
of them from the invoking uid — the Wayland display is the name of a socket in
`/run/user/<uid>`, and X11's is the number in `/tmp/.X11-unix/X<n>` — so
`sudo -E` is not required. It stays useful for a remote session where the
sockets are not local.

**`--user-data-dir` is a safety measure, not a preference.** Every major
browser, started a second time against the same profile, does not start a second
browser: it signals the running instance to open a tab and exits. That instance
is outside the namespace. The page loads, and nothing indicates the traffic went
in the clear.

tort refuses to launch a browser it detects already running without an isolated
profile, rather than warning. Getting this wrong looks exactly like success.

Two further notes for Chromium-based browsers:

- **QUIC will fail and fall back to TCP.** tort drops UDP, since tor cannot
  carry it. This is correct - a leak becomes a failure - but the first
  connection to each host may pause. `--disable-quic` avoids the wait.
- **WebRTC cannot leak your address**, because the UDP it needs is dropped. It
  will simply not work.

## How circuit inspection works

`tort route` reads over tor's control port, which is bound to **host loopback only** and
authenticated with tor's cookie file. That restriction is the important part:
an authenticated control connection can reconfigure tor entirely, so a program
inside the namespace reaching it could uncontain itself. The namespace can
reach tor's `TransPort` and `DNSPort` and nothing else, and a test asserts the
control port is never bound to the veth address.

Relay countries come from tor's own GeoIP database rather than a web service, so
inspecting a circuit tells no third party which relays you are using.

`route` requires the same authorization as `run`, not the lighter treatment
`status` gets. It names the **guard** relay, which is long-lived and identifies
its user far more than an exit address does - not something to hand out
unauthenticated on a machine with other local accounts.

Only built, general-purpose circuits are listed in detail — tor also keeps
circuits for directory fetches and onion service work — but the count of those
omitted is reported rather than hidden.

### Why the exit in `status` may not appear in `route`

They are answering different questions, and both answers are correct.

Tor maintains several circuits at once and assigns each new connection to one of
them; it does not pin a process, a destination or a session to a circuit. So
`tort up` and `tort status` are separate processes making separate connections,
and each reports the exit of whichever circuit carried *its* request. Seeing two
different exits seconds apart is normal, and is mildly good for unlinkability.

`tort route` is a snapshot of the circuits that exist at the moment it runs. Tor
builds them ahead of demand and retires them continuously, so a circuit that
carried a request moments ago may already be gone, and circuits that have
carried nothing at all will be listed.

If you want to see which exit a *particular* connection used, ask over that
connection: `tort run curl -s https://check.torproject.org/api/ip`.

### Where the exit node lookup goes

`tort up` and `tort status` report the exit node's address, location and
operator, looked up from ip2location. **That lookup goes through Tor**, from
inside the namespace, like every other request tort makes.

This is a requirement rather than an optimisation. Performed over the ordinary
connection it would tell the provider the user's real address *and* which exit
node they were using at a known moment - precisely the two facts needed to link
them, handed over in a single request. Through Tor, the provider sees an exit
node asking about itself.

The answer is identical either way, since it concerns a third party's address.
Only the question of who learns something about the user differs, which makes
the direct version a cost with no benefit.

For the same reason the exit node is described only when the verdict is
"through Tor". If traffic is *not* going through Tor, the address in question is
the user's own, and looking it up would mean disclosing it over the connection
that just failed to be anonymous.

## How onion routing works

`tort onion` fetches the Tor Project's own onion service from inside the
namespace. This exercises a different path from ordinary traffic: tor's `DNSPort`
returns a virtual address from `VirtualAddrNetworkIPv4` (`10.192.0.0/10`), and
the redirect must carry a connection to that address into `TransPort`.

It is also why the gateway exclusion in the ruleset is a `/24` rather than
`10.0.0.0/8` - the wider range would swallow the virtual network and break onion
routing while leaving ordinary browsing working, which is a bad way to find out.

### Browsers block .onion themselves

A browser inside the tunnel may refuse `.onion` addresses even though the
network path works. Chromium-based browsers do not resolve `.onion` (RFC 7686
reserves it for Tor-aware software), and Brave goes further, intercepting such
navigation to steer you toward its own Tor window:

```
This page has been blocked by Brave
ERR_BLOCKED_BY_CLIENT
```

That is the browser refusing before a packet is sent, not a routing failure.
`tort onion` fetching the same address proves the tunnel carries it.

**Do not use Brave's built-in Tor window to work around this.** It starts
Brave's own bundled tor, whose traffic would then be redirected into tort's tor
as well - Tor over Tor. That is not additional protection; it lengthens the
circuit for no benefit and is explicitly discouraged by the Tor Project.

For `.onion` browsing inside tort, use Firefox with `.onion` resolution allowed:

```bash
tort run firefox --profile /tmp/tort-firefox
```

then set `network.dns.blockDotOnion` to `false` in `about:config`. Firefox
blocks the TLD by default for the same RFC 7686 reason; with a transparent proxy
in front of it, resolution is exactly what you want it to do.

## Coexisting with a host firewall

tort installs its own nftables table and never edits anyone else's rules. That
is deliberate, but it has a consequence worth stating plainly: **tort cannot
override a firewall that drops its traffic.** In netfilter every table
registered on a hook is evaluated, and a DROP in any of them wins regardless of
what another table accepted.

Redirected traffic arrives at the host as a NEW inbound connection on `tort0`.
ufw and most host firewalls deny inbound by default, so on such a system you
must allow it once:

```bash
sudo ufw allow in on tort0
```

This is safe. tort's own input chain still restricts the namespace to tor's two
ports and drops everything else, so opening the interface at the ufw level does
not widen what the namespace can actually reach.

`tort up` detects an active ufw and prints this instruction if verification
fails.

## A note on sandboxing the daemon

`tortd.service` carries almost no systemd hardening, on purpose.

The daemon execs arbitrary user programs - that is what `tort run` is - so any
sandboxing directive it carries is inherited by the browser rather than
confining the daemon. The restriction lands on the wrong process, and shows up
as an error a long way from its cause: `ProtectHome=yes` hides `/run/user` and
a graphical application then fails with "Failed to connect to Wayland display:
Permission denied", which points at Wayland rather than at a unit file.

Nor would those directives confine the daemon meaningfully. It is root, and it
creates network namespaces, rewrites nftables and changes uid. A sandbox
permitting all of that is not restricting much.

The real confinement is elsewhere, and it is the point of the design: the
daemon accepts six verbs over a socket, authorizes each one through polkit
before doing anything, and identifies the caller from the kernel rather than
from anything the caller claims.

## Troubleshooting

**"the tort daemon is not running, and this is not root"** — start it with
`sudo systemctl start tortd`, or run the command under `sudo` to use the
direct path.

**`tort up` succeeds but nothing loads.** Check `tort status` first; if the
verdict is `confirmed`, tort is working and the problem is in the application.
If a host firewall is active, see "Coexisting with a host firewall" — tort
cannot override another table's DROP and will say so.

**A graphical application exits immediately.** It needs a display; tort finds
`DISPLAY` and `WAYLAND_DISPLAY` from your session automatically, but on a remote
session there may be none to find.

**`tort status` says PARTIAL.** Something is present and something is missing —
usually because `tortd` was restarted, which kills the tor instance it started
while the namespace and rules survive. `tort down` clears it; the daemon also
cleans up at startup.

**Pages load very slowly on first contact with each host.** QUIC is timing out
before falling back to TCP. Expected — tor cannot carry UDP, so tort drops it
rather than letting it leak. `--disable-quic` skips the wait in Chromium-based
browsers.

**Everything looks right but you want proof.** `sudo ./scripts/smoke-test.sh`
verifies end to end and diffs your firewall before and after.

## What this does not cover

- **Scope is opt-in.** Only what you run via `tort run` is tunnelled. This is a
  deliberate trade: a guarantee covering what you explicitly place inside it
  beats a claim to cover everything that quietly does not.
- **Traffic analysis and correlation.** Out of scope entirely.
- **Application-level leaks.** An app that ignores the system resolver, embeds
  its own proxy settings, or phones home over a protocol tor cannot carry will
  fail closed rather than leak — but it will fail.
- **Onion services** need `AutomapHostsOnResolve` and `VirtualAddrNetworkIPv4`,
  both set in the generated torrc. This path is not yet well tested.
- **The prototype runs under sudo.** The daemon and polkit policy described
  above are not implemented yet.

## Requirements

Linux with network namespace support, `nftables`, `iproute2`, and `tor`.

## Prior art

The gateway model — Whonix, and Tails' transparent proxying — is the stronger
version of this idea, where the boundary is enforced by something the client
cannot reconfigure even when fully compromised. tort is the same idea at lower
cost and lower assurance.
