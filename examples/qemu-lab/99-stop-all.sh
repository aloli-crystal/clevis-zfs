#!/usr/bin/env bash
# Cleanly shut down both VMs (and as a fallback, kill the QEMU process).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

stop_vm() {
  local label="$1"
  local pidfile="$2"
  if vm_alive "${pidfile}"; then
    local pid
    pid="$(cat "${pidfile}")"
    echo "[${label}] sending SIGTERM to ${pid}"
    kill "${pid}"
    for i in 1 2 3 4 5 6 7 8 9 10; do
      sleep 1
      if ! kill -0 "${pid}" 2>/dev/null; then
        echo "[${label}] stopped"
        rm -f "${pidfile}"
        return 0
      fi
    done
    echo "[${label}] still alive, sending SIGKILL"
    kill -9 "${pid}" 2>/dev/null || true
    rm -f "${pidfile}"
  else
    echo "[${label}] not running"
    rm -f "${pidfile}" 2>/dev/null || true
  fi
}

stop_vm tang   "${TANG_PIDFILE}"
stop_vm client "${CLIENT_PIDFILE}"
