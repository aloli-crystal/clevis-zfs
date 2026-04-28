#!/usr/bin/env bash
# End-to-end test for crystal-clevis-zfs.
#
# Flow:
#   1. Reset any previous state (zpool destroy testpool, mdconfig -d, rm jwe).
#   2. Create a fresh test pool on a 1 GiB file-backed vnode.
#   3. SINGLE-TANG bind/unlock + I/O on a child dataset + compression check.
#   4. MULTI-TANG bind K=2/N=3 + unlock + tolerance test (kill 1 Tang).
#   5. Failure test : kill 2 Tangs (more than N-K), unlock must fail cleanly.
#   6. Cleanup : detach pool, remove vnode.
#
# Prerequisite: 20-provision-tang.sh and 21-provision-client.sh have run.
# Tangs at 10.0.2.2:{8888,8889,8890} (reached from the client VM via the
# QEMU NAT gateway).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

URL1="http://10.0.2.2:${TANG_HTTP_PORT}"
URL2="http://10.0.2.2:${TANG_HTTP_PORT2}"
URL3="http://10.0.2.2:${TANG_HTTP_PORT3}"

echo "[test] resetting client state"
run_ssh client "sudo zpool destroy testpool 2>/dev/null || true"
run_ssh client "sudo mdconfig -d -u 1 2>/dev/null || true"
run_ssh client "sudo rm -f /var/db/crystal-clevis-zfs/*.jwe"

echo "[test] creating a 1 GiB file-backed pool 'testpool'"
run_ssh client "sudo truncate -s 1G /var/zpool-test.img"
run_ssh client "sudo mdconfig -a -t vnode -f /var/zpool-test.img -u 1"
run_ssh client "sudo zpool create -f testpool /dev/md1"
run_ssh client "zpool list testpool"

# ============================================================================
echo
echo "============================================================"
echo "TEST 1 — single-Tang bind/unlock on testpool/zsys"
echo "============================================================"
run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs bind --init \
  --dataset testpool/zsys --tang ${URL1}"

echo "[test] verifying ZFS properties"
run_ssh client "zfs get -H -o property,value encryption,keyformat,keystatus,compression,mountpoint testpool/zsys"

echo "[test] unload key and unlock again"
run_ssh client "sudo zfs unload-key testpool/zsys"
run_ssh client "test \"\$(zfs get -H -o value keystatus testpool/zsys)\" = unavailable && echo OK_unavailable"
run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs unlock --dataset testpool/zsys"
run_ssh client "test \"\$(zfs get -H -o value keystatus testpool/zsys)\" = available && echo OK_available"

echo "[test] write/read data through the encrypted dataset"
run_ssh client "sudo zfs create -o mountpoint=/mnt/test1 testpool/zsys/data"
run_ssh client "sudo dd if=/dev/random of=/mnt/test1/random.bin bs=1k count=64 2>/dev/null"
run_ssh client "sudo dd if=/mnt/test1/random.bin of=/dev/null bs=1k count=64 2>&1 | grep transferred"

# ============================================================================
echo
echo "============================================================"
echo "TEST 2 — multi-Tang K=2/N=3 on testpool/zdata"
echo "============================================================"
run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs bind --init \
  --dataset testpool/zdata \
  --tang ${URL1} --tang ${URL2} --tang ${URL3} \
  --threshold 2"

echo "[test] verifying JWE format (clevis.sss in header)"
run_ssh client "sudo head -c 100 /var/db/crystal-clevis-zfs/testpool__zdata.jwe; echo"
run_ssh client "sudo wc -c /var/db/crystal-clevis-zfs/testpool__zdata.jwe"

echo "[test] unlock with all 3 Tangs reachable"
run_ssh client "sudo zfs unload-key testpool/zdata"
run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs unlock --dataset testpool/zdata"
run_ssh client "test \"\$(zfs get -H -o value keystatus testpool/zdata)\" = available && echo OK_3of3"

# ============================================================================
echo
echo "============================================================"
echo "TEST 3 — kill Tang #2 (port ${TANG_HTTP_PORT2}), unlock should still succeed"
echo "============================================================"
run_ssh tang "sudo pkill -f 'tangd -p ${TANG_HTTP_PORT2}' || true"
run_ssh tang "sudo sockstat -l4 | grep tangd || echo '(tangs running)'"

run_ssh client "sudo zfs unload-key testpool/zdata"
run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs unlock --dataset testpool/zdata"
run_ssh client "test \"\$(zfs get -H -o value keystatus testpool/zdata)\" = available && echo OK_2of3_after_1_failure"

# ============================================================================
echo
echo "============================================================"
echo "TEST 4 — kill Tang #3 too, unlock must FAIL cleanly"
echo "============================================================"
run_ssh tang "sudo pkill -f 'tangd -p ${TANG_HTTP_PORT3}' || true"
run_ssh tang "sudo sockstat -l4 | grep tangd || echo '(tangs running)'"

run_ssh client "sudo zfs unload-key testpool/zdata"
if run_ssh client "sudo /usr/local/sbin/crystal-clevis-zfs unlock --dataset testpool/zdata" 2>&1; then
  echo "[test] FAIL: unlock unexpectedly succeeded with only 1 Tang up"
  exit 1
else
  echo "[test] OK: unlock failed cleanly as expected (only 1 of 2 required shares)"
fi

# ============================================================================
echo
echo "[test] cleanup"
run_ssh client "sudo zfs destroy -r testpool/zdata 2>/dev/null || true"
run_ssh client "sudo zfs destroy -r testpool/zsys 2>/dev/null || true"
run_ssh client "sudo zpool destroy testpool 2>/dev/null || true"
run_ssh client "sudo mdconfig -d -u 1 2>/dev/null || true"

# Restart the killed Tangs so the lab is reusable
echo "[test] restarting Tang #2 and #3 for next run"
run_ssh tang "sudo sh -c '/usr/local/libexec/tangd -p ${TANG_HTTP_PORT2} -l /var/db/tang2 > /var/log/tang2.log 2>&1 &'"
run_ssh tang "sudo sh -c '/usr/local/libexec/tangd -p ${TANG_HTTP_PORT3} -l /var/db/tang3 > /var/log/tang3.log 2>&1 &'"
run_ssh tang "sleep 1 && sudo sockstat -l4 | grep tangd"

echo
echo "============================================================"
echo "ALL TESTS PASSED — crystal-clevis-zfs is functional end-to-end"
echo "============================================================"
