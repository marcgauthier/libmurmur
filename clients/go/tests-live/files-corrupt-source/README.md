# files-corrupt-source

A two-node encrypted mesh proves that fetching from a corrupt source
fails verification. One test
(`TestCorruptSourceFetchFailsVerification`) follows the reference
phases in reference order: a positive control
(upload/replicate/fetch/verify), honest publication of a victim object,
corruption of its stored container bytes on the source node while
stopped (same length, 16 flipped bytes in the middle of the container,
i.e. inside chunk ciphertext), restart and re-mesh, then the failing
fetch legs.

Pass criteria: the peer fetch fails verification with no partial
install: with victim metadata honestly replicated, the fetching node
never reports the victim locally available across a full 75 s window
(at least two 30 s fetch ticks) and refuses its download; it holds
neither an object file for the unverified digest nor any staging
residue (no `*.part`, staging rows back at the post-control baseline);
victim metadata stays intact (original digest/size, still listed) on
both nodes; the corruption is persistent (still unavailable after a
35 s retry window covering at least one more fetch cycle); and honest
objects still fetch afterwards.

## Env knobs

- `MURMUR_FILES_CORRUPT_VICTIM_KB` (default 256): victim payload size
  in KiB (reference: same name and default).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores with staged
  file-object stores, driven in-process through `goharness`
  (`Files: true`; see `../PORTING.md`) instead of `murmur-server`
  children over pgwire.
- File ops use the native store surface (`FileUpload` / `FileList` /
  `FileAvailable` / `FileDownload`) instead of `MURMUR FILE` wire
  commands; uploads flush so metadata replicates. File names, sizes,
  and the payload pattern keep the reference values; the object key is
  the harness cluster key.
- The harness pins the file-fetch cadence at 30 s (no interval knob on
  the Stage call) while the reference configures 100 ms, so the
  never-local window is 75 s (at least two fetch ticks; reference: 30 s
  covering ~300 attempts), the retry-persistence window is 35 s (at
  least one more tick; reference: 500 ms), honest-fetch waits are 90 s
  (the files-soak value), and the staging-quiescence budget is 65 s
  (spanning two ticks). Metadata waits keep the reference 30 s.
- The victim is published on the running source, which stops at once
  (with its replication down, victim metadata cannot escape to the
  fetcher before the corruption lands; the test asserts the fetcher
  holds no victim metadata at that point). The reference stops the
  fetcher instead, but an in-process node that completed a fetch cannot
  restart -- driver start fails with `sqlite sqlrc=0: File exists` (a
  product bug worth a follow-up) -- so the fetcher stays up throughout.
- Verification failure is proven behaviorally (never available while
  metadata is present, downloads fail), as in the reference: the sticky
  fetch-error sentinel is process memory with no native equivalent.
- Staging-residue checks observe a quiescent moment (no `*.part` plus
  `murmur_file_staging` back at its post-control baseline, since
  successful fetches may legitimately leave staging history), then
  require no `.spfo` for the unverified digest, no `*.part`, and no
  staging growth. Object files are `<digest>.g0.spfo` under `files/`.
- Before the control leg the suite converges one fixture row: seed
  sessions on this stack only establish once user-table writes give the
  sync loop something to ship, and file metadata alone never wakes the
  mesh (the files-soak gate).

## Verification

```sh
cd clients/go && go vet ./tests-live/files-corrupt-source/ && \
  MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/files-corrupt-source/
```
