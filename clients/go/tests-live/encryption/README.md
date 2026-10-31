# Encrypted SQL persistence

Insert a confidential marker, flush, stop the node, and scan its durable files for plaintext. Restart on the same key and verify the original row still reads.

The node runs as a child process (`tests-live/node`; build it and point
`MURMUR_NODE_BIN` at it) so the restart leg exercises a real process
reopen with the unlock key. The byte-level audit is inlined in the
test. The reference wrong-key legs are skipped: the harness cannot
restart with an alternate unlock key and native nodes expose no wire
auth surface (`harness: restart/unlock with an alternate key and
wire-level unlock auth`).

Known engine limitation: a SIGKILL (rather than the graceful stop used
here) loses acknowledged flushed writes — `Flush` does not make data
crash-durable. Crash legs must not rely on flushed-write survival until
the engine checkpoints on flush.

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/encryption/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.

The disk scan checks exact plaintext byte sequences. It does not prove general cryptographic security.
