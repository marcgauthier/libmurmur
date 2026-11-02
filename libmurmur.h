/* libmurmur - unified Murmur library, public umbrella header.
 *
 * libmurmur.a packs every native Murmur component into one archive:
 * SQLite, cr-sqlite (C wrapper + Rust bundle), the page codec
 * (AEGIS-256 + Zstandard), the keyring, Argon2, the C++ VFS/storage
 * managers, and the picoquic+picotls+mbedTLS QUIC transport (RocksDB
 * is repacked from its own archive). Clients - the Go client in
 * clients/go, or a pure-C application - link this one file.
 *
 * Process lifecycle: call murmur_init() once before any other murmur
 * call, murmur_shutdown() at exit. Subsystem specifics stay with each
 * subsystem (the transport self-registers its TLS provider on first
 * use; the VFS registers through the storage open call).
 */
#ifndef LIBMURMUR_H
#define LIBMURMUR_H

#include <stddef.h>
#include <stdint.h>

/* Opt-in native foundations; these do not enable a new wire protocol. */
#include "deps/murmur/scheduler.h"
#include "deps/murmur/origin.h"
#include "deps/murmur/managed.h"
#include "deps/murmur/causal.h"
#include "deps/murmur/managed_origin.h"
#include "deps/murmur/managed_schema.h"
#include "deps/murmur/bridge_codec.h"
#include "deps/murmur/bridge_store.h"
#include "deps/murmur/bridge_publish.h"
#include "deps/murmur/bridge_ferry.h"
#include "deps/murmur/bridge_sender.h"
#include "deps/murmur/bridge_rows.h"
#include "deps/murmur/bridge_capture.h"
#include "deps/murmur/bridge_peer.h"

#define MURMUR_VERSION_MAJOR 0
#define MURMUR_VERSION_MINOR 1
#define MURMUR_VERSION_PATCH 0
#define MURMUR_VERSION_STRING "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration so the key API needs no sqlite3.h include. */
struct sqlite3;

/* Library version string, e.g. "0.1.0". Never NULL. */
const char *murmur_version(void);

/* Process-level init. Returns 0 on success, nonzero SQLite error code
 * otherwise. Idempotent; safe to call more than once. */
int murmur_init(void);

/* Register the built-in SQLite VFS as "sqlite-murmur". Call once after
 * murmur_init() and before opening Murmur stores with sqlite3_open_v2().
 * cache_pages<=0 and flush_interval_ms==0 select native defaults. */
int murmur_vfs_register(int cache_pages, unsigned flush_interval_ms);

/* Initialize cr-sqlite replication on a connection opened with the
 * bundled SQLite engine. Enable a table with crsql_as_crr() SQL. */
int murmur_crsqlite_init(struct sqlite3 *db);

/* Process-level shutdown. Safe to call even if murmur_init failed. */
void murmur_shutdown(void);

/* Provisions the 32-byte master key on an open connection's main
 * database. This is the primary key API for ordinary clients (C or
 * Go): pass key bytes, not SQL. SQL `PRAGMA key='<64 hex>'` stays as
 * a compatibility alias and takes the same code path.
 *
 * Returns a SQLite primary result code: 0 on success, 11 (CORRUPT)
 * when the key does not unlock a sealed store, 21 (MISUSE) for a
 * second, different key or a null argument, 12 (NOTFOUND) when the
 * connection's main database is not a murmur store.
 *
 * Threading: serialized by the connection mutex, like any file
 * control; one connection, one caller at a time. */
int murmur_db_key(struct sqlite3 *db, const uint8_t key[32]);

#ifdef __cplusplus
}
#endif

#endif /* LIBMURMUR_H */
