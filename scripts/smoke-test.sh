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

section "orphans from previous runs"
pgrep -x tor -a 2>/dev/null | grep -F "/run/tort/torrc" || echo "(none - clean start)"

section "firewall snapshot (before)"
# Tear down first. An earlier run interrupted between `up` and `down` leaves the
# tort table installed, and snapshotting that as the baseline makes the
# comparison meaningless - it reports the table's *removal* as tort having
# changed the firewall.
"$TORT" down >/dev/null 2>&1
nft list ruleset > "$BEFORE" 2>/dev/null
echo "$(wc -l < "$BEFORE") lines captured (after a defensive teardown)"

section "tort up"
UP_OUT=$("$TORT" up 2>&1); UP_RC=$?
echo "$UP_OUT"
echo "exit code: $UP_RC"

TRAFFIC_RESULT="not attempted"
ONION_RESULT="not attempted"
if [ $UP_RC -eq 0 ]; then
    section "traffic test from inside the namespace"
    TRAFFIC_OUT=$("$TORT" run curl -sS --max-time 45 https://check.torproject.org/api/ip 2>&1)
    echo "$TRAFFIC_OUT"
    TRAFFIC_RESULT="$TRAFFIC_OUT"

    section "DNS resolution inside the namespace"
    "$TORT" run getent hosts example.com || echo "(getent failed)"

    section "onion service"
    ONION_OUT=$("$TORT" onion 2>&1); ONION_RC=$?
    echo "$ONION_OUT"
    if [ $ONION_RC -eq 0 ]; then ONION_RESULT="reachable"; else ONION_RESULT="FAILED"; fi
else
    section "DIAGNOSTICS (tort up failed)"
    echo "--- namespaces ---";        ip netns list 2>&1 | head
    echo "--- namespace addr ---";    ip -n tort addr 2>&1 | head -20
    echo "--- namespace routes ---";  ip -n tort route 2>&1 | head
    echo "--- host veth ---";         ip addr show tort0 2>&1 | head
    echo "--- listening on tort ports ---"
    ss -lntup 2>/dev/null | grep -E "10\.66\.0\.1|9140|9153|9150" || echo "(nothing bound)"
    echo "--- generated torrc ---";   cat /run/tort/torrc 2>/dev/null || echo "(none written)"
    echo "--- can the HOST reach the Tor network at all? ---"
    # If this fails, nothing tort does can help: tor cannot bootstrap without
    # reaching a directory authority. moria1 and tor26, on their DirPorts.
    for da in 128.31.0.39:9131 86.59.21.38:80; do
        timeout 5 bash -c "</dev/tcp/${da%%:*}/${da##*:}" 2>/dev/null \
            && echo "  $da reachable" || echo "  $da NOT reachable"
    done

    echo "--- outbound firewall policy (ufw) ---"
    ufw status verbose 2>/dev/null | head -8 || echo "(ufw not present)"

    echo "--- system tor, for comparison ---"
    systemctl is-active tor 2>/dev/null || echo "(system tor not active)"

    echo "--- tor log: errors, warnings and bootstrap progress ---"
    # Filtered, not tailed. A tor crash prints a long backtrace of raw addresses
    # which pushes the actual error out of view, and those frames are useless
    # without tor's debug symbols.
    grep -aE "\[err\]|\[warn\]|Bootstrapped" /run/tort/tor.log 2>/dev/null | tail -20 \
        || echo "(no tor log)"
    echo "--- full tor log, address frames removed ---"
    # The filtered view above can miss a crash banner, which is not tagged
    # [err] or [warn]. Strip only the raw address frames and show the rest.
    grep -avE "^(tor\(\+0x|/usr/lib/)" /run/tort/tor.log 2>/dev/null | tail -25 \
        || echo "(no tor log)"

    echo "--- did tor crash? ---"
    grep -acE "^tor\(\+0x" /run/tort/tor.log 2>/dev/null | \
        xargs -I{} sh -c '[ {} -gt 0 ] && echo "YES - {} backtrace frames present" || echo "no backtrace"' 
    echo "--- tor --verify-config ---"
    tor -f /run/tort/torrc --verify-config 2>&1 | tail -8
    echo "--- tort nft table ---";    nft list table ip tort 2>&1 | head -30
fi

if [ $UP_RC -ne 0 ] && [ -e /var/run/netns/tort ]; then
    section "namespace connectivity (up failed but the namespace survived)"
    ip netns exec tort ip route 2>&1 | head -3
    echo "--- can the namespace reach tor's TransPort? ---"
    ip netns exec tort timeout 5 bash -c "</dev/tcp/10.66.0.1/9140" 2>&1 \
        && echo "reachable" || echo "NOT reachable"
fi

if [ -n "$(nft list table ip tort 2>/dev/null)" ]; then
    section "rule counters (which rules actually matched)"
    nft list table ip tort 2>/dev/null | grep -E "counter packets" | sed 's/^[[:space:]]*/  /'
fi

section "tort down"
DOWN_OUT=$("$TORT" down 2>&1); DOWN_RC=$?
echo "$DOWN_OUT"
echo "exit code: $DOWN_RC"

section "orphans after teardown"
# Checked after `down`, not before: while the tunnel is up a running tor is
# correct, and calling that an orphan reports a success as a failure.
pgrep -x tor -a 2>/dev/null | grep -F "/run/tort/torrc" && echo "ORPHANED tor survived teardown" || echo "(none - clean)"

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
    echo "onion test   : $ONION_RESULT"
else
    echo "tort up      : FAILED (exit $UP_RC)"
    echo "reason       : $(echo "$UP_OUT" | grep -iE 'error|failed|refus' | head -3)"
fi
echo "tort down    : exit $DOWN_RC"
echo "leftover     : $("$TORT" status | tail -1)"
echo "firewall     : $FIREWALL"
echo
echo "Full log: $LOG"
