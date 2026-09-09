# tort — Tor Tunnel

Run applications inside a network namespace whose only route out is Tor.

> **Prototype.** Verified working on one machine: ordinary traffic exits through
> Tor (confirmed by check.torproject.org), onion services resolve and load, the
> forward-drop counter stays at zero, and the host firewall is byte-identical
> after teardown. That is a great deal less exposure than the tools it borrows
> ideas from have had. Read "What this does not cover" before relying on it.

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

```bash
sudo ./packaging/install.sh
sudo systemctl enable --now tortd
```

This installs the binary, a polkit policy and a systemd unit. After it, tort is
used **without sudo** — polkit decides whether you may proceed.

Without the daemon every command still works when run as root directly, which is
how the tool was developed and remains the fallback on systems without polkit.

## Usage

```bash
tort up                  # create namespace, start tor, install rules, verify
tort run firefox         # run one app inside the tunnel, as your user
tort shell               # interactive shell inside the tunnel
tort status              # what is actually running, read from the kernel
tort verify              # confirm traffic exits via Tor
tort onion               # fetch a known onion service
tort down                # remove everything
tort ruleset             # print the nftables ruleset without applying it
```

`tort up` verifies before returning, and **tears itself down if it cannot
confirm** traffic exits through Tor. It will not leave a tunnel up that it
could not prove works.

Applications run as the user who invoked sudo, not as root.

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

## Verifying it works

`scripts/smoke-test.sh` runs the whole lifecycle as root, snapshots the host
firewall before and after, and prints the rule counters. A healthy run shows:

```
traffic test : {"IsTor":true,"IP":"..."}
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

## Onion services

```bash
tort onion
```

Fetches the Tor Project's own onion service from inside the namespace. Verified
working. This exercises a different path from ordinary traffic: tor's `DNSPort`
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
