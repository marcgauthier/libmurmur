# write-priority

Concurrent SQL writers on both nodes compete with incoming replication
while reads continue. Each worker uses atomic 25-row statements over a
bounded owned range. The test requires at least one second of
local-plus-remote writer service with replication performing nonzero
apply work, then enforces the policy that replication takes at most 25%
of total writer service. Every acknowledged row must subsequently
converge exactly.

This suite is fully skipped in the native port: the verdict reads
engine scheduler counters (`scheduler.local/remote.service_nanos`)
that do not exist natively — the health snapshot reports
`scheduler.stats` as null — so the fairness policy is unmeasurable
(`harness: scheduler service-time stats (local/remote
service_nanos)`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/write-priority/
```

`MURMUR_LIVE_WRITE_PRIORITY_SECONDS` defaults to 12 seconds;
`MURMUR_LIVE_WRITE_PRIORITY_SYNC_TIMEOUT_SECONDS` defaults to 120 seconds.
