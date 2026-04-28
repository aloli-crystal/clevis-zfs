# shellcheck shell=bash
# Common variables and helpers for the crystal-clevis-geli QEMU lab.

set -euo pipefail

QEMU_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_DIR="${QEMU_DIR}/images"
RUN_DIR="${QEMU_DIR}/run"
LOGS_DIR="${QEMU_DIR}/logs"
SSH_DIR="${QEMU_DIR}/ssh"

# FreeBSD 15.0-RELEASE aarch64 cloud image (UFS + cloud-init).
FREEBSD_VERSION="15.0-RELEASE"
FREEBSD_IMAGE_BASENAME="FreeBSD-${FREEBSD_VERSION}-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2"
FREEBSD_IMAGE_URL="https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_VERSION}/aarch64/Latest/${FREEBSD_IMAGE_BASENAME}.xz"
FREEBSD_IMAGE_XZ="${IMAGES_DIR}/${FREEBSD_IMAGE_BASENAME}.xz"
FREEBSD_IMAGE_QCOW2="${IMAGES_DIR}/${FREEBSD_IMAGE_BASENAME}"

# Per-VM disks (cloned/derived from the base image).
TANG_DISK="${RUN_DIR}/tang.qcow2"
CLIENT_DISK="${RUN_DIR}/client.qcow2"
TANG_SEED="${RUN_DIR}/tang-seed.iso"
CLIENT_SEED="${RUN_DIR}/client-seed.iso"

TANG_PIDFILE="${RUN_DIR}/tang.pid"
CLIENT_PIDFILE="${RUN_DIR}/client.pid"
TANG_LOG="${LOGS_DIR}/tang.log"
CLIENT_LOG="${LOGS_DIR}/client.log"

# Host port forwards.
TANG_SSH_PORT="2222"
CLIENT_SSH_PORT="2223"
TANG_HTTP_PORT="8888"  # host:8888 -> tang VM:8888 (8080 occupé par nginx local)
TANG_HTTP_PORT2="8889" # 2nd tangd instance for SSS multi-Tang tests
TANG_HTTP_PORT3="8890" # 3rd tangd instance, used for K=2/N=3 demos

# Tang URL as seen from the client VM. 10.0.2.2 is the QEMU user-mode
# default gateway (= host).
TANG_URL_FROM_CLIENT="http://10.0.2.2:${TANG_HTTP_PORT}"

# Per-VM resources.
VM_CPUS="2"
VM_MEM="2048"

# QEMU and firmware paths.
QEMU_BIN="$(command -v qemu-system-aarch64)"
EDK2_FIRMWARE="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"

# Test SSH keypair (regenerated if missing).
SSH_KEY="${SSH_DIR}/id_ed25519"

ensure_dirs() {
  mkdir -p "${IMAGES_DIR}" "${RUN_DIR}" "${LOGS_DIR}" "${SSH_DIR}"
}

ensure_ssh_key() {
  ensure_dirs
  if [[ ! -f "${SSH_KEY}" ]]; then
    ssh-keygen -t ed25519 -N "" -f "${SSH_KEY}" -C "crystal-clevis-geli-qemu" >/dev/null
    echo "[ssh] generated keypair at ${SSH_KEY}"
  fi
}

# Run a command in a guest via SSH. Usage: run_ssh tang|client "command..."
run_ssh() {
  local target="$1"
  shift
  local port
  case "${target}" in
    tang)   port="${TANG_SSH_PORT}" ;;
    client) port="${CLIENT_SSH_PORT}" ;;
    *) echo "run_ssh: unknown target '${target}'"; return 2 ;;
  esac
  ssh \
    -i "${SSH_KEY}" \
    -p "${port}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    freebsd@127.0.0.1 \
    "$@"
}

# Wait until SSH is reachable on the given target.
wait_for_ssh() {
  local target="$1"
  local timeout="${2:-180}"
  local start=$(date +%s)
  while true; do
    if run_ssh "${target}" "true" 2>/dev/null; then
      return 0
    fi
    local now=$(date +%s)
    if (( now - start > timeout )); then
      echo "[wait_for_ssh] ${target}: timeout after ${timeout}s"
      return 1
    fi
    sleep 3
  done
}

# True if the named VM is alive (pidfile exists and process running).
vm_alive() {
  local pidfile="$1"
  [[ -f "${pidfile}" ]] && kill -0 "$(cat "${pidfile}")" 2>/dev/null
}
