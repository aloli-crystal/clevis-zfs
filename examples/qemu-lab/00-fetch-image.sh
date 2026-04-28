#!/usr/bin/env bash
# Download and extract the FreeBSD 15.0 aarch64 cloud image.
# Idempotent: skips download if the file already exists.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_dirs

if [[ -f "${FREEBSD_IMAGE_QCOW2}" ]]; then
  echo "[image] already extracted: ${FREEBSD_IMAGE_QCOW2}"
  exit 0
fi

if [[ ! -f "${FREEBSD_IMAGE_XZ}" ]]; then
  echo "[image] downloading ${FREEBSD_IMAGE_URL}"
  curl -L --fail --progress-bar \
    -o "${FREEBSD_IMAGE_XZ}" \
    "${FREEBSD_IMAGE_URL}"
fi

echo "[image] extracting (~600 MB → ~3 GiB qcow2)"
xz -d -k -v "${FREEBSD_IMAGE_XZ}"

echo "[image] ready: ${FREEBSD_IMAGE_QCOW2}"
ls -lh "${FREEBSD_IMAGE_QCOW2}"
