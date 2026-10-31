#!/bin/sh
# admincheck: exercises all 9 murmur-admin subcommands on scratch stores.
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ADMIN="$ROOT/build/admin"
TMP="$(mktemp -d /tmp/murmur-admincheck-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERM

fail() { echo "ADMINCHECK-FAIL: $1" >&2; exit 1; }
pass() { echo "ADMINCHECK-OK: $1"; }

KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
NEWKEY=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
NODE=a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
GROUP=07070707070707070707070707070707
NEWNODE=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
NEWGROUP=08080808080808080808080808080808

# Fixture store builder.
cc -O1 -g -I"$ROOT" -I"$ROOT/deps" -I"$ROOT/deps/murmur" -I"$ROOT/deps/sqlite" \
  "$ROOT/clients/c/admin/mkstore.c" "$ROOT/libmurmur.a" \
  -lstdc++ -lm -ldl -lpthread -o "$TMP/mkstore" || fail "mkstore build"
"$TMP/mkstore" "$TMP/store" "$KEY" "$NODE" "$GROUP" seal >/dev/null || fail "mkstore run"

A="$ADMIN --key-hex $KEY"

# 1. status (text + json)
$A status "$TMP/store" | grep -q "Murmur Database Status" || fail "status text"
$A status "$TMP/store" | grep -q "$NODE" || fail "status node"
$A --json status "$TMP/store" | grep -q '"table_count"' || fail "status json"
pass "status"

# 2. inspect
$A inspect "$TMP/store" | grep -q "docs" || fail "inspect tables"
$A --json inspect "$TMP/store" | grep -q '"storage_files"' || fail "inspect json"
pass "inspect"

# 3. verify (database mode)
$A verify "$TMP/store" | grep -q "^PASS" || fail "verify db"
$A --json verify "$TMP/store" | grep -q '"valid": true' || fail "verify db json"
pass "verify"

# 4. backup + verify backup mode
$A backup "$TMP/store" "$TMP/backup" | grep -q "^PASS" || fail "backup"
test -f "$TMP/backup/manifest.json" || fail "backup manifest"
$A verify --backup "$TMP/backup" | grep -q "^PASS" || fail "verify backup"
pass "backup"

# 5. restore (plain + fresh identities)
$A restore "$TMP/backup" "$TMP/restored" | grep -q "^PASS" || fail "restore"
$A --json status "$TMP/restored" | grep -q "$NODE" || fail "restore identity kept"
$A restore --fresh-node-id="$NEWNODE" --fresh-db-id="$NEWGROUP" \
  "$TMP/backup" "$TMP/restored2" | grep -q "^PASS" || fail "restore fresh"
$A --json status "$TMP/restored2" | grep -q "$NEWNODE" || fail "restore fresh node"
$A --json status "$TMP/restored2" | grep -q "$NEWGROUP" || fail "restore fresh db"
pass "restore"

# 6. keys
$A keys "$TMP/store" | grep -q "Key Registry" || fail "keys text"
$A --json keys "$TMP/store" | grep -q '"active_data_key_id"' || fail "keys json"
pass "keys"

# 7. rekey (copy first: rekey mutates)
cp -r "$TMP/store" "$TMP/rekeyme"
$ADMIN --key-hex "$KEY" rekey "$TMP/rekeyme" --new-key-hex "$NEWKEY" | grep -q "^PASS" || fail "rekey"
$ADMIN --key-hex "$NEWKEY" verify "$TMP/rekeyme" | grep -q "^PASS" || fail "rekey verify new"
if $A verify "$TMP/rekeyme" 2>/dev/null | grep -q "^PASS"; then
  fail "rekey old key still works"
fi
pass "rekey"

# 8. compact
$A compact "$TMP/store" | grep -q "^PASS" || fail "compact"
$A --json compact "$TMP/store" --max-passes 1 | grep -q '"passes": 1' || fail "compact json"
pass "compact"

# 9. repair
$A repair "$TMP/store" --out "$TMP/salvaged" | grep -q "^PASS" || fail "repair"
$A --json status "$TMP/salvaged" | grep -q "$NODE" || fail "repair identity"
pass "repair"

# 10. credentials: passphrase + key providers
PASSPHRASE_STORE="$TMP/pstore"
"$TMP/mkstore" "$PASSPHRASE_STORE" \
  "$(printf hunter2 | sha256sum | cut -d' ' -f1)" "$NODE" "$GROUP" >/dev/null || fail "pstore"
$ADMIN --passphrase hunter2 verify "$PASSPHRASE_STORE" | grep -q "^PASS" || fail "passphrase"
printf '%s' "$KEY" > "$TMP/keyhex.txt"
$ADMIN --key-provider-uri "file:$TMP/keyhex.txt" verify "$TMP/store" | grep -q "^PASS" || fail "provider file"
MURMUR_TEST_KEY="$KEY" $ADMIN --key-provider-uri env:MURMUR_TEST_KEY verify "$TMP/store" | grep -q "^PASS" || fail "provider env"
printf '#!/bin/sh\necho "%s"\n' "$KEY" > "$TMP/helper.sh"
chmod +x "$TMP/helper.sh"
$ADMIN --key-provider-uri "exec:$TMP/helper.sh" verify "$TMP/store" | grep -q "^PASS" || fail "provider exec"
pass "credentials"

# 11. errors: missing dir, unknown command, bad flags
if $A status "$TMP/nope" 2>/dev/null; then fail "missing dir accepted"; fi
if $A frobnicate "$TMP/store" 2>/dev/null; then fail "unknown command accepted"; fi
if $A --json frobnicate 2>&1 | grep -q '"error": true'; then :; else fail "json error envelope"; fi
if $A --key-hex deadbeef status "$TMP/store" 2>/dev/null; then fail "short key accepted"; fi
pass "errors"

echo "ADMINCHECK-OK (11 groups)"
