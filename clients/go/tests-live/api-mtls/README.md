# SQL mutual TLS

Starts a node, writes a control row, then restarts it in production
mode with TLS and a trusted client CA. The client must reject
plaintext, missing client certificates and an untrusted certificate. A
trusted certificate still requires the correct password and encryption
key. Valid writes must remain available after all rejection probes and
after another restart.

The test is skipped: native nodes expose no SQL wire endpoint
(statements run on in-process store handles), so production TLS,
client-certificate verification, and password/unlock auth have no
surface to probe. Replication-peer certificate admission is covered
separately.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/api-mtls/
```
