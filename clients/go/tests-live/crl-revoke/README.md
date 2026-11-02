# crl-revoke

Three meshed native nodes converge on 5 rows; the cluster CA then
revokes node3's leaf and the CRL is installed on both survivors via
the `crl_file` setting plus a replication restart. TLS handshakes
with node3 fail in both directions (sessions drop, writes stop
crossing either way) while the survivor link stays converged.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/crl-revoke/
```
