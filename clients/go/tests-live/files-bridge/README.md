# files-bridge

The reference meshes a two-node Low cluster and a two-node High cluster
(separate DBIDs, CAs, storage keys, and file object keys: `0x11..` on
Low, `0x22..` on High) and moves one 384 KiB file
(`shared/field-map.bin`, stream `field-files`) across a shared staging
directory: Low upload, Low mesh metadata plus digest-verified peer
fetch, signed export of sealed file chunks, High import with
re-encryption under the High object key, High mesh metadata plus
digest-verified peer fetch, and metadata search returning the one
replicated file.

`TestTwoLowTwoHighFileBridgeLive` is skipped on this stack: the native
bindings and the harness have no file-bridge surface at all -- no
bridge exporter/receiver roles, no bundle capture/process, no staging
directory handling, and no signer/recipient key configuration (the
harness stages one uniform file-object store per cluster). A
single-cluster upload/fetch round-trip would not prove the bridge, so
the suite stays a named skip rather than a weakened pass.

## Verification

```sh
cd clients/go && go vet ./tests-live/files-bridge/ && \
  MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/files-bridge/
```
