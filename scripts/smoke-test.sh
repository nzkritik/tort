#!/usr/bin/env bash
# End-to-end smoke test for tort.
#
# Runs the whole lifecycle, captures diagnostics on failure, and proves the host
# firewall is structurally unchanged afterwards. Deliberately does NOT use
# `set -e`: a failure part-way through is the interesting case, and aborting
# would skip both the cleanup and the diagnostics that explain it.
#
# The summary is printed LAST so that `| tail` captures the conclusion rather
# than whichever diagnostic happened to run most recently.

TORT="${TORT:-./target/release/tort}"
LOG=/tmp/tort-smoke.log
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

exec > >(tee "$LOG") 2>&1

section() { printf '\n=== %s ===\n' "$1"; }

# nft prints live packet/byte counters, which change constantly as the machine
# does ordinary work. Comparing them raw reports a difference on every run and
# tells us nothing, so normalise them away and compare structure only.
normalise() { sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets N bytes N/g' "$1"; }

section "environment"
uname -r; nft --version; tor --version | head -1
echo "ip_forward = $(sysctl -n net.ipv4.ip_forward)"
echo "tor account = $(getent passwd tor debian-tor _tor | cut -d: -f1 | head -1 || echo none)"

section "firewall snapshot (before)"
nft list ruleset > "$BEFORE" 2>/dev/null
echo "$(wc -l < "$BEFORE") lines captured"

section "tort up"
UP_OUT=$("$TORT" up 2>&1); UP_RC=$?
echo "$UP_OUT"
echo "exit code: $UP_RC"

TRAFFIC_RESULT="not attempted"
if [ $UP_RC -eq 0 ]; then
    section "traffic test from inside the namespace"
    TRAFFIC_OUT=$("$TORT" run curl -sS --max-time 45 https://check.torproject.org/api/ip 2>&1)
    echo "$TRAFFIC_OUT"
    TRAFFIC_RESULT="$TRAFFIC_OUT"

    section "DNS resolution inside the namespace"
    "$TORT" run getent hosts example.com || echo "(getent failed)"
else
    section "DIAGNOSTICS (tort up failed)"
    echo "--- namespaces ---";        ip netns list 2>&1 | head
    echo "--- namespace addr ---";    ip -n tort addr 2>&1 | head -20
    echo "--- namespace routes ---";  ip -n tort route 2>&1 | head
    echo "--- host veth ---";         ip addr show tort0 2>&1 | head
    echo "--- listening on tort ports ---"
    ss -lntup 2>/dev/null | grep -E "10\.66\.0\.1|9140|9153|9150" || echo "(nothing bound)"
    echo "--- generated torrc ---";   cat /run/tort/torrc 2>/dev/null || echo "(none written)"
    echo "--- tor --verify-config ---"
    tor -f /run/tort/torrc --verify-config 2>&1 | tail -8
    echo "--- tort nft table ---";    nft list table ip tort 2>&1 | head -30
fi

section "tort down"
DOWN_OUT=$("$TORT" down 2>&1); DOWN_RC=$?
echo "$DOWN_OUT"
echo "exit code: $DOWN_RC"

section "firewall comparison (counters normalised)"
nft list ruleset > "$AFTER" 2>/dev/null
if diff <(normalise "$BEFORE") <(normalise "$AFTER") > /tmp/tort-nft.diff 2>&1; then
    FIREWALL="unchanged - tort left no structural trace"
else
    FIREWALL="CHANGED - see /tmp/tort-nft.diff"
    cat /tmp/tort-nft.diff
fi
echo "$FIREWALL"

# ---- summary last, so `tail` catches the conclusion ----
section "SUMMARY"
if [ $UP_RC -eq 0 ]; then
    echo "tort up      : OK"
    echo "traffic test : $TRAFFIC_RESULT"
else
    echo "tort up      : FAILED (exit $UP_RC)"
    echo "reason       : $(echo "$UP_OUT" | grep -iE 'error|failed|refus' | head -3)"
fi
echo "tort down    : exit $DOWN_RC"
echo "leftover     : $("$TORT" status | tail -1)"
echo "firewall     : $FIREWALL"
echo
echo "Full log: $LOG"
