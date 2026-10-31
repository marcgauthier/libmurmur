# snaprejoin

Local regression suite with no reference twin. Fast cycle (~10 s): it
forces the pruned-cursor state directly instead of waiting out the
60 s retention tick.

## What it proves

Two nodes converge a seed row plus 50 bulk rows; node 1 restarts
in-process and remeshes; then node 0's `gc_watermark` is forced past
node 1's pull cursor so its next pull fails with "cursor pruned". The
engine must request a snapshot automatically (trust-gated, sweep-paced)
and node 1 must converge on all 51 rows via the snapshot path.

## History

Written against two real bugs:

- No automatic snapshot fallback: the pull loop retried the pruned
  cursor forever and snapshot only ran via a manual SQL verb.
  Fixed in `deps/murmur/driver.c` (`maybe_request_snapshot`, reference
  `engine_sync.go` missingHistory parity).
- Duplicate QUIC stream ids: `murmur_session_open_stream` peeked
  picoquic's next id without consuming it, so a pull racing a snapshot
  request minted the same id twice, crossed both streams' bytes, and
  starved one reader (flaky `snapshot:running` hang, only after
  restart). Fixed in `deps/murmur/transport.cc` by reserving the id
  with an empty add at open time.
