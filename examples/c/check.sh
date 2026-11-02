#!/bin/sh
# democheck - run two demo processes and prove rows replicate.
# Usage: sh examples/c/check.sh  (from the repo root)
set -u
TD=deps/murmur/testdata
GROUP=07070707070707070707070707070707
HEXA=a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
HEXB=b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
PA=18443
PB=18444
rm -f /tmp/murmur-demo-a.db /tmp/murmur-demo-b.db /tmp/murmur-demo-a.log \
  /tmp/murmur-demo-b.log
./build/demo /tmp/murmur-demo-a.db "127.0.0.1:$PA" "$HEXA" "$TD/node-a.pem" \
  "$TD/node-a-key.pem" "$TD/ca.pem" "$GROUP" "" 5 \
  > /tmp/murmur-demo-a.log 2>&1 &
DA=$!
./build/demo /tmp/murmur-demo-b.db "127.0.0.1:$PB" "$HEXB" "$TD/node-b.pem" \
  "$TD/node-b-key.pem" "$TD/ca.pem" "$GROUP" "127.0.0.1:$PA" 5 \
  > /tmp/murmur-demo-b.log 2>&1 &
DB=$!
wait "$DA"
RA=$?
wait "$DB"
RB=$?
echo "--- A log ---"
cat /tmp/murmur-demo-a.log
echo "--- B log ---"
cat /tmp/murmur-demo-b.log
if [ "$RA" -ne 0 ] || [ "$RB" -ne 0 ]; then
  echo "DEMO-FAIL (exit $RA/$RB)"
  exit 1
fi
# Writer emits ~12 rows in 25s; the follower must converge close.
BROWS=$(grep -o 'rows=[0-9]*' /tmp/murmur-demo-b.log | tail -1 | cut -d= -f2)
if [ "${BROWS:-0}" -ge 8 ]; then
  echo "DEMO-OK (B rows=$BROWS)"
  exit 0
fi
echo "DEMO-FAIL (B rows=${BROWS:-0})"
exit 1
