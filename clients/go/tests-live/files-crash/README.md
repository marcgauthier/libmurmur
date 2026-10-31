# files-crash

File crash consistency: uploads replicate, fetch, and verify, and
every on-disk payload is attributable to a known attempt.

## What it proves

- Positive control: an honest upload replicates, fetches, and
  verifies, with a clean baseline inventory (zero unattributable
  payloads).
- Volume: 2 rounds of 4 honest 1 MiB uploads plus one
  `MURMUR_FILES_CRASH_BIG_MB` (default 3) MiB object (scaled down
  from the reference 3x8: peer fetch completes ~2 objects per 30 s
  tick, so full volume would idle ~7 minutes on tick boundaries).
- Recovery proof: metadata settles identically on both nodes, every
  listed object downloads byte-complete and digest-verified on both
  nodes with no phantoms and no lost acked uploads, and every
  on-disk `.spfo`/`.upload-*`/`.part` payload is attributable to a
  known attempt and bounded in count (no kills run, so every bound
  is strict: zero orphans, zero stage files).

## Skipped legs (harness gaps)

- `TestFileCrashMidUploadKill`: the reference kills the uploader
  between chunked UPLOAD APPENDs. This stack exposes only atomic
  `UploadOne` (a single RPC), and `KillNode` serializes behind the
  in-flight call, so a kill can never land mid-upload.
- `TestFileCrashMidFetchKill`: the reference kills the fetcher while
  a `.part` transfer is on disk and requires the interrupted fetch
  to complete after restart. A child restart drops the files
  staging (`RestartNode` reboots without files), and an in-process
  node that completed a fetch cannot restart at all ("File exists"),
  so both reboot paths are closed.

## Env knobs

- `MURMUR_FILES_CRASH_BIG_MB` (default 3): size in MiB of the big
  fetch payload. Same name and default as the reference.

## Deviations from the reference

- Nodes are native replication drivers over VFS stores with staged
  file-object stores, driven in-process through `goharness` (see
  `../PORTING.md`) instead of `murmur-server` children over pgwire.
  No kill legs remain, so no child mode is needed.
- File ops use the native file-object store (`FileUpload` /
  `FileList` / `FileAvailable` / `FileDownload`) instead of `MURMUR
  FILE` wire commands (`UPLOAD BEGIN` / chunked `UPLOAD APPEND` /
  `UPLOAD FINISH`; `DOWNLOAD` / `DOWNLOAD NEXT`; `LIST` + `NEXT` +
  `CLOSE`). Digests come from the list metadata after each
  acknowledged upload (the `UPLOAD FINISH` shape).
- A one-row mesh gate precedes the control upload (file metadata
  alone never wakes the mesh; the files-soak pattern).
- Peer fetch is automatic on the driver's fetch tick, but the
  harness pins the cadence at 30 s (the reference configures
  100 ms), so each fetch wait is 90 s; metadata waits keep the
  reference 30 s and the final settle keeps 60 s. Each availability
  wait counts one fetch attempt for the inventory bound, as in the
  reference.
- The on-disk inventory walk covers the same taxonomy (`.spfo`
  objects, `.upload-*`/`.rotate-*` stage files, `.part` fetch
  transfers) with the same name parsers and bounds.
