#!/usr/bin/env bash
# End-to-end smoke test for tort.
#
# Runs the whole lifecycle, captures diagnostics on failure, and proves the
# host firewall is byte-identical afterwards. Deliberately does NOT use `set -e`:
# a failure part-way through is the interesting case, and aborting would skip
# both the cleanup and the diagnostics that explain it.

TORT="${TORT:-./target/release/tort}"
BEFORE=/tmp/tort-nft-before.txt
AFTER=/tmp/tort-nft-after.txt

if [ "$(id -u)" -ne 0 ]; then
    echo "Run me with sudo: sudo $0" >&2
    exit 1
fi
if [ ! -x "$TORT" ]; then
    echo "Cannot find $TORT - run 'cargo build --release' first." >&2
    exit 1
fi

section() { printf '\n=== %s ===\n' "$1"; }

section "environment"
uname -r
nft --version
tor --version | head -1
echo "ip_forward = $(sysctl -n net.ipv4.ip_forward)"

section "firewall snapshot (before)"
nft list ruleset > "$BEFORE" 2>/dev/null
echo "$(wc -l < "$BEFORE") lines captured"

section "tort up"
"$TORT" up
UP_RC=$?
echo "exit code: $UP_RC"

if [ $UP_RC -eq 0 ]; then
    section "traffic test from inside the namespace"
    # -sS so curl stays quiet on success but still reports errors.
    "$TORT" run curl -sS --max-time 45 https://check.torproject.org/api/ip
    echo
    echo "curl exit code: $?"

    section "DNS resolution inside the namespace"
    "$TORT" run getent hosts example.com || echo "(getent failed)"
else
    section "DIAGNOSTICS (tort up failed)"

    echo "--- namespaces ---"
    ip netns list 2>&1 | head

    echo "--- namespace addressing ---"
    ip -n tort addr 2>&1 | head -20
    ip -n tort route 2>&1 | head

    echo "--- host veth ---"
    ip addr show tort0 2>&1 | head

    echo "--- what is listening on the veth address ---"
    ss -lntup 2>/dev/null | grep -E "10\.66\.0\.1|9140|9153|9150" || echo "(nothing bound on tort ports)"

    echo "--- generated torrc ---"
    cat /run/tort/torrc 2>/dev/null || echo "(no torrc written)"

    echo "--- tor's view of that config ---"
    tor -f /run/tort/torrc --verify-config 2>&1 | tail -20

    echo "--- tort's nft table, if it was installed ---"
    nft list table ip tort 2>&1 | head -30
fi

section "tort down"
"$TORT" down
echo "exit code: $?"

section "firewall snapshot (after)"
nft list ruleset > "$AFTER" 2>/dev/null
if diff -q "$BEFORE" "$AFTER" >/dev/null 2>&1; then
    echo "IDENTICAL - tort left no trace on the host firewall"
else
    echo "DIFFERENT - tort changed something it did not clean up:"
    diff "$BEFORE" "$AFTER"
fi

section "final state"
"$TORT" status
