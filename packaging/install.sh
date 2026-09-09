#!/usr/bin/env bash
# Install tort, its polkit policy and its systemd unit.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run me with sudo: sudo $0" >&2
    exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The GUI needs GTK4, which a headless machine running only the daemon should
# not have to install. Build it when the toolkit is there, skip it when not.
FEATURES=""
if pkg-config --exists gtk4 2>/dev/null; then
    echo "GTK4 found - the tortunnel GUI will be built."
    FEATURES="--features gui"
else
    echo "GTK4 not found - building the CLI and daemon only."
fi

echo "Building..."
sudo -u "${SUDO_USER:-root}" cargo build --release $FEATURES --manifest-path "$REPO/Cargo.toml"

echo "Installing binary..."
install -Dm755 "$REPO/target/release/tort" /usr/local/bin/tort

if [ -x "$REPO/target/release/tortunnel" ]; then
    echo "Installing GUI..."
    install -Dm755 "$REPO/target/release/tortunnel" /usr/local/bin/tortunnel
    install -Dm644 "$REPO/packaging/tortunnel.desktop" \
        /usr/share/applications/tortunnel.desktop
fi

echo "Installing polkit policy..."
install -Dm644 "$REPO/packaging/io.github.nzkritik.tort.policy" \
    /usr/share/polkit-1/actions/io.github.nzkritik.tort.policy

echo "Installing systemd unit..."
install -Dm644 "$REPO/packaging/tortd.service" /etc/systemd/system/tortd.service
systemctl daemon-reload

# Restart if it is already running, so an install always leaves the running
# daemon matching the binary and unit just installed. Without this the installer
# reports success while the old daemon keeps serving.
if systemctl is-active --quiet tortd; then
    echo "Restarting the running daemon..."
    systemctl restart tortd
fi

echo
if systemctl is-active --quiet tortd; then
    echo "Installed. The daemon has been restarted with the new binary."
else
    echo "Installed. Enable and start the daemon with:"
    # --now both enables at boot and starts immediately; no separate start needed.
    echo "  sudo systemctl enable --now tortd"
fi
echo
echo "Then, as your normal user and with no sudo:"
echo "  tort up"
echo "  tort run brave --user-data-dir=/tmp/tort-brave"
echo "  tort down"
if [ -x /usr/local/bin/tortunnel ]; then
    echo
    echo "Or launch the GUI:  tortunnel"
fi
