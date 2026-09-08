#!/usr/bin/env bash
# Install tort, its polkit policy and its systemd unit.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run me with sudo: sudo $0" >&2
    exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Building..."
sudo -u "${SUDO_USER:-root}" cargo build --release --manifest-path "$REPO/Cargo.toml"

echo "Installing binary..."
install -Dm755 "$REPO/target/release/tort" /usr/local/bin/tort

echo "Installing polkit policy..."
install -Dm644 "$REPO/packaging/io.github.nzkritik.tort.policy" \
    /usr/share/polkit-1/actions/io.github.nzkritik.tort.policy

echo "Installing systemd unit..."
install -Dm644 "$REPO/packaging/tortd.service" /etc/systemd/system/tortd.service
systemctl daemon-reload

echo
echo "Installed. Start the daemon with:"
echo "  sudo systemctl enable --now tortd"
echo
echo "Then, as your normal user and with no sudo:"
echo "  tort up"
echo "  tort run brave --user-data-dir=/tmp/tort-brave"
echo "  tort down"
