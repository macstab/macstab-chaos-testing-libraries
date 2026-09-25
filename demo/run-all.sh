#!/usr/bin/env bash
# Run all 15 chaos demo profiles from source and print a green tally.
#   bash demo/run-all.sh          # from the repo root; needs only Docker
#
# Each profile builds the six .so from source into a shared volume (once) and
# runs a probe under LD_PRELOAD. Exit code is non-zero if any profile fails.
set -u
cd "$(dirname "$0")/.." || exit 1
C="docker compose -f demo/docker-compose.yml"
G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; B=$'\033[1m'; Z=$'\033[0m'

echo "${D}building six .so from source ...${Z}"
$C run --rm -T build >/dev/null 2>&1

# profile | description | pass-pattern (extended regex)
ROWS=(
  "io1|read → EIO|input/output error"
  "io2|read → CORRUPT (bit-flip)|checksum mismatch"
  "io3|write → TORN (short write)|TORN short write"
  "net1|connect → ECONNREFUSED|errno 111"
  "net2|connect → ETIMEDOUT|errno 110"
  "net3|send → ECONNRESET|errno 104"
  "dns1|getaddrinfo → REWRITE|127.0.0.1"
  "dns2|getaddrinfo → EAI_AGAIN|exit=2"
  "dns3|getaddrinfo → OVERRIDE|127.0.0.1"
  "time1|CLOCK_REALTIME +1h|delta=3600s"
  "time2|CLOCK_MONOTONIC backward|backward"
  "mem1|mmap → ENOMEM|cannot allocate"
  "mem2|mmap → +150ms latency|took 1[0-9][0-9]"
  "proc1|pthread_create → EAGAIN|pthread_create FAILED|Resource temporarily"
  "proc2|execve → EACCES|parent still running"
)

pass=0; fail=0
for row in "${ROWS[@]}"; do
  IFS='|' read -r name desc pat <<<"$row"
  out=$($C run --rm --no-deps -T "$name" 2>&1)   # app errno messages (e.g. io1) land on stderr
  if echo "$out" | grep -qiE "$pat"; then
    printf '  %s✓%s %s%-6s%s %s%s%s\n' "$G$B" "$Z" "$B" "$name" "$Z" "$D" "$desc" "$Z"
    pass=$((pass+1))
  else
    printf '  %s✗%s %s%-6s%s %s%s%s\n' "$R$B" "$Z" "$B" "$name" "$Z" "$D" "$desc" "$Z"
    fail=$((fail+1))
  fi
done

echo
if [ "$fail" -eq 0 ]; then
  printf '  %s===== %d PASS / %d FAIL (of 15) =====%s\n' "$G$B" "$pass" "$fail" "$Z"
else
  printf '  %s===== %d PASS / %d FAIL (of 15) =====%s\n' "$R$B" "$pass" "$fail" "$Z"
fi
$C down -v --remove-orphans >/dev/null 2>&1
exit "$fail"
