#!/usr/bin/env bash
# Boot the GELI client VM in the background.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_dirs

if vm_alive "${CLIENT_PIDFILE}"; then
  echo "[client] already running (pid $(cat "${CLIENT_PIDFILE}"))"
  exit 0
fi

echo "[client] booting QEMU (host SSH on :${CLIENT_SSH_PORT})"
"${QEMU_BIN}" \
  -name client \
  -machine virt,gic-version=3 \
  -accel hvf \
  -cpu host \
  -smp "${VM_CPUS}" \
  -m "${VM_MEM}" \
  -bios "${EDK2_FIRMWARE}" \
  -drive if=virtio,format=qcow2,file="${CLIENT_DISK}" \
  -drive if=virtio,format=raw,readonly=on,file="${CLIENT_SEED}" \
  -netdev user,id=net0,hostfwd=tcp::"${CLIENT_SSH_PORT}"-:22 \
  -device virtio-net-device,netdev=net0 \
  -display none \
  -serial file:"${CLIENT_LOG}" \
  -pidfile "${CLIENT_PIDFILE}" \
  -daemonize

echo "[client] PID $(cat "${CLIENT_PIDFILE}"), logs in ${CLIENT_LOG}"
echo "[client] tail -f ${CLIENT_LOG} to follow boot"
