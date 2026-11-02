# highlow-peer

Two native High peers exchange signed field claims, subsequent edits, field
release, row-delete claims and row release through the native CRR transport.
The test fully reopens a High store and checks that ownership and journal
progress survive. Bridged user tables do not use raw row CRR replication;
the native signed journal applies semantic ownership joins and projection.

Only the first High node scans the ferry. The second loads source-verification
keys and receives original sealed Low proofs, shadows and receipts through
the signed High journal. It verifies the original Low exporter signature
independently. Capturing original signed Low-peer writes remains a release gate.
A replicated fixture establishes the native mesh before bridge assertions.

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 120s ./tests-live/highlow-peer/
```
