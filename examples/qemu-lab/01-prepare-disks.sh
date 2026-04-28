#!/usr/bin/env bash
# Prepare per-VM disks (qcow2 backed by the base image, so we can roll
# back easily) and per-VM cloud-init seed ISOs that inject our SSH
# pubkey and a hostname.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_dirs
ensure_ssh_key

if [[ ! -f "${FREEBSD_IMAGE_QCOW2}" ]]; then
  echo "[prepare] base image not found, run 00-fetch-image.sh first" >&2
  exit 1
fi

# qemu-img create with backing file would be more elegant, but cloud-init
# tends to write into the disk so we just clone (cp) for simplicity.
clone_disk() {
  local dest="$1"
  if [[ -f "${dest}" ]]; then
    echo "[prepare] ${dest} already exists, leaving it alone"
    return 0
  fi
  echo "[prepare] cloning base image -> ${dest}"
  cp "${FREEBSD_IMAGE_QCOW2}" "${dest}"
  # Make the disk a bit larger so we have room to install crystal,
  # build the binary, etc.
  qemu-img resize "${dest}" 8G >/dev/null
}

clone_disk "${TANG_DISK}"
clone_disk "${CLIENT_DISK}"

build_seed() {
  local hostname="$1"
  local out_iso="$2"
  local stage
  stage="$(mktemp -d)"

  cat > "${stage}/meta-data" <<EOF
instance-id: ${hostname}-1
local-hostname: ${hostname}
EOF

  cat > "${stage}/user-data" <<EOF
#cloud-config
hostname: ${hostname}
fqdn: ${hostname}.local

# The cloud images do NOT ship with sudo. Install it before any
# cloud-init step that needs to grant sudo to a user.
package_update: true
packages:
  - sudo

users:
  - name: freebsd
    gecos: FreeBSD test user
    shell: /bin/sh
    groups: wheel
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: freebsd
    ssh_authorized_keys:
      - $(cat "${SSH_KEY}.pub")

ssh_pwauth: true
disable_root: false

datasource_list: [NoCloud]
EOF

  # macOS native ISO authoring.
  echo "[prepare] building seed ISO ${out_iso}"
  hdiutil makehybrid -quiet -o "${out_iso}.tmp" -hfs -joliet -iso \
    -default-volume-name CIDATA \
    "${stage}" >/dev/null
  # hdiutil produces a .iso suffix automatically — normalize.
  if [[ -f "${out_iso}.tmp.iso" ]]; then
    mv "${out_iso}.tmp.iso" "${out_iso}"
  else
    mv "${out_iso}.tmp" "${out_iso}"
  fi
  rm -rf "${stage}"
}

build_seed tang   "${TANG_SEED}"
build_seed client "${CLIENT_SEED}"

echo "[prepare] done."
ls -lh "${TANG_DISK}" "${CLIENT_DISK}" "${TANG_SEED}" "${CLIENT_SEED}"
