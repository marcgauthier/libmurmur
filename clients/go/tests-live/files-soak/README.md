# files-soak

A two-node encrypted mesh soaks 64 KiB file uploads for
`MURMUR_FILES_SOAK_DURATION_SECONDS` (default 5 s), one upload every
`MURMUR_FILES_SOAK_INTERVAL_SECONDS` (default 1 s). Each round uploads
`soak/file-NNNN.bin` (payload `data[i] = (round*31 + i*17) % 251`) to
node 0, waits for replicated metadata on node 1, waits for the
automatic fetch, downloads, verifies the digest, and searches the
replicated names; afterwards the fetch gate shows every file completed
with zero failures and the first file reads existing + available.

Pass criteria: at least one upload round; every uploaded file is
locally available on the peer with its upload digest;
`soak/file-0000.bin` exists and is available; per-round search returns
exactly the files uploaded so far; upload p95 stays under 5 s and
metadata-to-verified-fetch p95 under 120 s.

## Env knobs

- `MURMUR_FILES_SOAK_DURATION_SECONDS` (default 5): soak wall-clock
  budget. Long soak: `MURMUR_FILES_SOAK_DURATION_SECONDS=600
  MURMUR_FILES_SOAK_INTERVAL_SECONDS=60`.
- `MURMUR_FILES_SOAK_INTERVAL_SECONDS` (default 1): sleep between
  rounds (skipped after the last round).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores with staged
  file-object stores, driven in-process through `goharness`
  (`Files: true`; see `../PORTING.md`) instead of `murmur-server`
  children over pgwire.
- File ops use the native store surface (`FileUpload` / `FileList` /
  `FileAvailable` / `FileDownload`) instead of `MURMUR FILE` wire
  commands; uploads flush so metadata replicates. File names, payload
  bytes, and the payload pattern keep the reference values; the object
  key is the harness cluster key and the file cap is the product
  default.
- The harness pins the file-fetch cadence at 30 s (no interval knob on
  the Stage call) while the reference configures 100 ms, so the fetch
  wait is 90 s (metadata wait keeps the reference 20 s) and the
  metadata-to-verified-fetch SLO is scaled 20 s -> 120 s. The upload
  SLO keeps the reference 5 s. Rounds are sequential, so the default
  5 s duration still proves every leg end to end.
- Before round 0 the suite converges one `meshgate` fixture row:
  seed sessions on this stack only establish once user-table writes
  give the sync loop something to ship, and file metadata alone never
  wakes the mesh (an upload-only cluster stays unmeshed past 120 s).
  The gate mirrors the reference harness handing over an
  already-meshed cluster; it does not affect file semantics.
- The fetch gate maps to per-file availability + digest checks over
  every uploaded file (behavioral zero-failures proof); the first-file
  gate maps to a `FileList` hit for `soak/file-0000.bin` plus its
  availability flag; `SEARCH '%file-%'` maps to a client-side
  substring filter over `FileList`.
- The digest gate is digest consistency plus full byte equality: the
  upload digest must match the peer metadata digest and the download
  must be byte-identical.
- The soak summary line keeps rounds and p95s (no fetched-bytes
  counter).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/files-soak/
```
