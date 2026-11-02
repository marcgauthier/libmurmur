# files-bridge

Two Low nodes and two High nodes use different database IDs, CAs and object
keys. A 384 KiB file uploaded to a Low peer is fetched by its exporter, sealed
in bounded bridge parts, imported and re-encrypted on High, then fetched by the
second High peer. The second High node does not scan a ferry directory: it
receives and verifies original source parts through the signed High journal.
Its source receipts and drained encrypted chunk staging are checked explicitly.
The test compares content and confirms the encrypted object
containers differ between domains. Full exporter and receiver reopen proves
completed files are not recaptured or reapplied.

Native file-bridge tests additionally cover partial-export resume, empty
files, partial-import cancellation, offset gaps, duplicate/conflicting chunks,
full-content digest verification, and atomic metadata/receipt rollback.

The harness uses a 100 ms native peer-fetch interval and advertises each file
service's actual loopback address. A replicated fixture establishes the mesh
before upload. The runtime performs no plaintext filesystem staging: received
chunks are retained in encrypted SQL until native object publication commits.

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 120s ./tests-live/files-bridge/
```
