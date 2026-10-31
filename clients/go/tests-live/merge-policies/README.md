# merge-policies

Three disconnected nodes share one typed row with PN_COUNTER / OR_SET
/ MAX / MIN policy columns; policy ops forward across connection and
restart legs with observed-remove semantics (an unobserved remove
erases nothing; a later observed remove propagates).

This suite is fully skipped in the native port: the engine exposes no
`MURMUR POLICY COUNTER_ADD` / `SET_ADD` / `SET_REMOVE` / `MIN` / `MAX`
ops and no OR_SET projection reads, so no leg can run (`harness:
merge-policy ops (PN_COUNTER/OR_SET/MAX/MIN) have no native
equivalent`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/merge-policies/
```
