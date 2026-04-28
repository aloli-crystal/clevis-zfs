#!/usr/bin/env bash
# Provision the Tang VM: install the package, generate keys, start
# THREE tangd instances (8888, 8889, 8890) so the client VM can
# exercise multi-Tang K=2/N=3 against three independent Tangs from
# a single host.
#
# Notes on the FreeBSD port `security/tang`:
#  - tangd runs as root (no dedicated user is created).
#  - The rc.conf variable for the keys dir is `tangd_jwkdir`, not
#    `tangd_keys_dir`.
#  - Default port is already 8888 (matches our TANG_HTTP_PORT).
#  - The rc.d script only handles ONE instance; Tang #2 and #3 are
#    launched manually via `/usr/local/libexec/tangd -p PORT -l DIR`.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

echo "[tang] waiting for SSH..."
wait_for_ssh tang

echo "[tang] installing package security/tang + curl"
run_ssh tang "sudo pkg install -y -q tang curl"

echo "[tang] preparing /var/db/tang{,2,3} and generating server keys"
for i in "" 2 3; do
  dir="/var/db/tang${i}"
  run_ssh tang "sudo mkdir -p ${dir} && sudo chmod 700 ${dir}"
  run_ssh tang "[ -z \"\$(ls ${dir}/*.jwk 2>/dev/null)\" ] && sudo /usr/local/libexec/tangd-keygen ${dir} || true"
done
run_ssh tang "sudo ls /var/db/tang/"

echo "[tang] enabling and starting tangd #1 (rc.d, port ${TANG_HTTP_PORT})"
run_ssh tang "sudo sysrc tangd_enable=YES tangd_jwkdir=/var/db/tang tangd_port=${TANG_HTTP_PORT}"
run_ssh tang "sudo touch /var/log/tang && sudo chmod 644 /var/log/tang"
run_ssh tang "sudo service tangd restart || sudo service tangd onestart"

echo "[tang] launching tangd #2 (port ${TANG_HTTP_PORT2}) and tangd #3 (port ${TANG_HTTP_PORT3})"
run_ssh tang "sudo pkill -f 'tangd -p ${TANG_HTTP_PORT2}' 2>/dev/null || true"
run_ssh tang "sudo pkill -f 'tangd -p ${TANG_HTTP_PORT3}' 2>/dev/null || true"
run_ssh tang "sudo sh -c '/usr/local/libexec/tangd -p ${TANG_HTTP_PORT2} -l /var/db/tang2 > /var/log/tang2.log 2>&1 &'"
run_ssh tang "sudo sh -c '/usr/local/libexec/tangd -p ${TANG_HTTP_PORT3} -l /var/db/tang3 > /var/log/tang3.log 2>&1 &'"
run_ssh tang "sleep 1 && sudo sockstat -l4 | grep tangd"

echo "[tang] checking advertisements are reachable from host"
for p in "${TANG_HTTP_PORT}" "${TANG_HTTP_PORT2}" "${TANG_HTTP_PORT3}"; do
  if ! curl -fs --max-time 5 "http://127.0.0.1:${p}/adv" >/dev/null; then
    echo "[tang] FAIL: advertisement not reachable on port ${p}" >&2
    exit 1
  fi
  echo "[tang] OK port ${p}"
done

echo "[tang] all 3 Tangs ready : 8888, 8889, 8890 (host) -> /var/db/tang{,2,3} (guest)"
