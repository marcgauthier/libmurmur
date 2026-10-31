# Wire authentication and unlock abuse

Try twelve invalid passwords, usernames, or encryption keys against a real SQL server. Assert authentication/unlock SQLSTATEs and absence of supplied credentials in errors; verify valid reads continue and survive a process restart.

This suite is fully skipped in the native port: native nodes expose no
wire auth surface — no user, password, or unlock handshake to abuse —
so no leg is expressible (`harness: wire authentication and unlock
handshake`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/unlock-abuse/
```

Authentication failures use 28P01; unlock key failures use 28000. This bounded denial test is not a rate-limit or network-flood benchmark.
