# Murmur C demo (N7 gate)

Two processes replicate a Murmur store over QUIC with mutual TLS,
using only the C library. No Go is involved.

Build:

```sh
make demo
```

Run (two terminals, from the repo root):

```sh
TD=deps/murmur/testdata
G=07070707070707070707070707070707
A=a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
B=b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
./build/demo /tmp/a.db 127.0.0.1:18443 $A $TD/node-a.pem \
  $TD/node-a-key.pem $TD/ca.pem $G
./build/demo /tmp/b.db 127.0.0.1:18444 $B $TD/node-b.pem \
  $TD/node-b-key.pem $TD/ca.pem $G 127.0.0.1:18443
```

The seedless side writes a row every 2s; both sides report
`peers=` and `rows=` every 5s. Watch B's `rows=` converge on A's.

Headless check (5 reports each, asserts B replicates):

```sh
make democheck
```

Notes:

- The demo opens file stores through the `sqlite-murmur` VFS and
  provisions a fixed demo key via `murmur_db_key` (insecure by
  design; real clients seal a key per store).
- Node ids must match the certificate URI SANs; the testdata CA
  and node certificates live in `deps/murmur/testdata`.
- `ROUNDS=0` (default) runs until SIGINT/SIGTERM.
