#!/usr/bin/env bash
# Boot the Tang VM in the background.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_dirs

if vm_alive "${TANG_PIDFILE}"; then
  echo "[tang] already running (pid $(cat "${TANG_PIDFILE}"))"
  exit 0
fi

echo "[tang] booting QEMU (host SSH on :${TANG_SSH_PORT}, host HTTP on :${TANG_HTTP_PORT})"
"${QEMU_BIN}" \
  -name tang \
  -machine virt,gic-version=3 \
  -accel hvf \
  -cpu host \
  -smp "${VM_CPUS}" \
  -m "${VM_MEM}" \
  -bios "${EDK2_FIRMWARE}" \
  -drive if=virtio,format=qcow2,file="${TANG_DISK}" \
  -drive if=virtio,format=raw,readonly=on,file="${TANG_SEED}" \
  -netdev user,id=net0,hostfwd=tcp::"${TANG_SSH_PORT}"-:22,hostfwd=tcp::"${TANG_HTTP_PORT}"-:"${TANG_HTTP_PORT}",hostfwd=tcp::"${TANG_HTTP_PORT2}"-:"${TANG_HTTP_PORT2}",hostfwd=tcp::"${TANG_HTTP_PORT3}"-:"${TANG_HTTP_PORT3}" \
  -device virtio-net-device,netdev=net0 \
  -display none \
  -serial file:"${TANG_LOG}" \
  -pidfile "${TANG_PIDFILE}" \
  -daemonize

echo "[tang] PID $(cat "${TANG_PIDFILE}"), logs in ${TANG_LOG}"
echo "[tang] tail -f ${TANG_LOG} to follow boot"
