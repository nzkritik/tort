# tort — Tor Tunnel

Run applications inside a network namespace whose only route out is Tor.

> **Prototype.** The end-to-end path is verified working - traffic from the
> namespace exits through Tor, confirmed by check.torproject.org - but this has
> had far less real-world exposure than the tools it borrows ideas from, on one
> machine, once. Read "What this does not cover" before relying on it.

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

## Usage

```bash
sudo tort up                  # create namespace, start tor, install rules, verify
sudo tort run firefox         # run one app inside the tunnel, as your user
sudo tort shell               # interactive shell inside the tunnel
sudo tort status              # what is actually running, read from the kernel
sudo tort verify              # confirm traffic exits via Tor
sudo tort down                # remove everything
tort ruleset                  # print the nftables ruleset without applying it
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

**Privileged operations sit behind a trait.** Today there is one implementation
that runs in-process under sudo. A socket-activated root daemon with a polkit
policy can be added as a second implementation without touching the logic,
turning the privilege boundary into four verbs rather than "may run arbitrary
commands as root".

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
sudo -E tort run brave --user-data-dir=/tmp/tort-brave
```

Both parts of that line matter.

**`sudo -E`** — sudo's `env_reset` strips `DISPLAY` and `WAYLAND_DISPLAY`, and
without them a graphical application cannot start at all. tort reconstructs
`XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` from the invoking uid, but the
display variables cannot be derived - only preserved.

**`--user-data-dir`** — this is a safety measure, not a preference. Every major
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

## Onion services

```bash
sudo tort onion
```

Fetches the Tor Project's own onion service from inside the namespace. This
exercises a different path from ordinary traffic: tor's `DNSPort` returns a
virtual address from `VirtualAddrNetworkIPv4` (`10.192.0.0/10`), and the
redirect must carry a connection to that address into `TransPort`.

It is also why the gateway exclusion in the ruleset is a `/24` rather than
`10.0.0.0/8` - the wider range would swallow the virtual network and break onion
routing while leaving ordinary browsing working, which is a bad way to find out.

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
