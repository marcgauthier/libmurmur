# SQL key rotation and crash recovery

Rotate the encryption key, kill the server immediately after the acknowledged command. Reopen using the new key, reject the old key, verify existing data, write more data, and restart again.

This suite is fully skipped in the native port: the bindings expose no
key-rotation verb, the harness cannot restart a node with a different
key, and there is no wire surface to reject the old key on
(`harness: key rotation (rotate verb, restart with new key, old-key
rejection)`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/rekey/
```

The kill tests acknowledged key rotation durability. It does not inject a crash at every internal rewrap instruction.
