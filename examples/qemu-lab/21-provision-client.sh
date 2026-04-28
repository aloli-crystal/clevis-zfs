#!/usr/bin/env bash
# Provision the ZFS client VM: install Crystal + git, clone
# crystal-clevis-zfs (the successor to crystal-clevis-geli), build
# the binary, install the rc.d script.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

echo "[client] waiting for SSH..."
wait_for_ssh client

echo "[client] installing crystal, shards, git"
# `shards` is a separate FreeBSD port (devel/shards), not bundled
# with the `crystal` package.
run_ssh client "sudo pkg install -y -q crystal shards git"

echo "[client] loading zfs kernel module (required for `zfs(8)` operations)"
run_ssh client "sudo kldload zfs 2>/dev/null || true"
run_ssh client "kldstat | grep -i zfs || true"

echo "[client] cloning crystal-clevis-zfs"
run_ssh client "test -d ~/crystal-clevis-zfs || git clone --depth=1 https://github.com/aloli-crystal/crystal-clevis-zfs.git ~/crystal-clevis-zfs"
run_ssh client "cd ~/crystal-clevis-zfs && git pull --ff-only"

echo "[client] installing runtime dependencies only (skip ameba dev_dep)"
# ameba's postinstall builds with -Dpreview_mt and crashes in this VM
# (2 GiB RAM is tight). Ameba is a dev tool; we only need crystal-jose.
run_ssh client "cd ~/crystal-clevis-zfs && shards install --without-development"

echo "[client] running test suite"
run_ssh client "cd ~/crystal-clevis-zfs && crystal spec"

echo "[client] building CLI binary"
run_ssh client "cd ~/crystal-clevis-zfs && crystal build src/cli.cr -o ~/crystal-clevis-zfs-bin --release"
run_ssh client "ls -lh ~/crystal-clevis-zfs-bin"

echo "[client] installing binary + rc.d to /usr/local/{sbin,etc/rc.d}"
run_ssh client "sudo install -m 0755 ~/crystal-clevis-zfs-bin /usr/local/sbin/crystal-clevis-zfs"
run_ssh client "sudo install -m 0755 ~/crystal-clevis-zfs/etc/rc.d/crystal-clevis-zfs /usr/local/etc/rc.d/crystal-clevis-zfs"
run_ssh client "/usr/local/sbin/crystal-clevis-zfs version"

echo "[client] OK"
