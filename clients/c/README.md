# C client (libmurmur embedder)

Home of the pure-C client: applications linking `libmurmur.a`
directly, with no Go runtime involved.

Layout (N7 target):

- `demo/` — the proving client: open a database through the murmur
  VFS, provision the key via `murmur_db_key`, run SQL, configure
  replication through the public C API, and sync against a peer.
  This demo is the N7 completion gate: every Murmur feature usable
  from C, Go-free.
- `examples/` — small focused snippets (open/key/query, backup,
  offline rekey) over the public `libmurmur.h` + subsystem headers.

Build: link `../../libmurmur.a` plus `-lstdc++ -lm -ldl -lpthread`
(see the `build/synctest` recipe in `../../Makefile` for the exact
working link). Public entry points live in `libmurmur.h`;
subsystem APIs in `deps/murmur/*.h` (`sync.h`, `retain.h`,
`config.h`, `framing.h`, `msgcodec.h`, `member.h`, `open.h`).
