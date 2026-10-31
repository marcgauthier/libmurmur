# fetch-restart

Local regression suite with no reference twin.

## What it proves

In-process `StopNode`/`StartNode` on a node that completed a file fetch
must reopen the file store. This used to fail with
`driver start: sqlite sqlrc=0: File exists`: after a fetch the `staging/`
dir exists but is empty, `dir_names` returned NULL for the empty dir,
and `reconcile_staging` reported stale `errno` (EEXIST left by `mkdir_all`)
via `io_fail`. Nodes that never fetched restarted fine because the
missing staging dir hit the ENOENT-tolerant path.

## Shape

Two nodes with `Files: true`, a meshgate row to establish seed sessions,
one 256 KiB upload on node 0, wait for node-1 local availability,
byte-exact download, in-process restart of the fetcher, byte-exact
download again.
