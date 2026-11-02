# exclude-rejoin

Three meshed native nodes converge on 5 rows; node3 is removed on
both survivors via `murmur_remove_peer`. Sessions to node3 drop, its
writes stop arriving, and survivor writes stop reaching it (the
handshake refuses excluded peers in both directions). A survivor
restart reloads the durable exclusion: the restarted node re-meshes
only its fellow survivor and never re-meshes node3.

There is no re-add leg: exclusion is one-way (no SQL verb clears
`murmur_excluded`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/exclude-rejoin/
```
