/* libmurmur - unified Murmur library entry point.
 *
 * Component map (all linked into libmurmur.a by the root Makefile):
 *
 *   deps/sqlite            SQLite engine (pristine amalgamation)
 *   deps/crsqlite/src      cr-sqlite C wrapper (+ Rust bundle repacked)
 *   deps/codec             page codec: AES-256-GCM (AWS-LC)
 *                            + Zstandard
 *   deps/keyring           sealed key storage primitives
 *   deps/zstd              Zstandard (flat sources)
 *   deps/aws-lc            libcrypto repacked from its own archive (not rebuilt)
 *   deps/mbedtls           mbedTLS (sole X.509 backend)
 *   deps/picotls           picotls (no minicrypto; stubbed fail-closed)
 *   deps/picoquic          picoquic + mbedTLS backend (no fusion)
 *   deps/rocksdb           repacked from its own archive (not rebuilt)
 *   deps/murmur            project managers: VFS/storage + QUIC transport
 *
 * This TU owns process-level lifecycle shared by every embedder.
 */
#include "libmurmur.h"

#include "sqlite3.h"

const char *murmur_version(void) { return MURMUR_VERSION_STRING; }

int murmur_init(void) {
  /* Explicit SQLite init so pure-C embedders (no Go runtime) get a fully
   * initialized engine before any other murmur call. Idempotent. */
  return sqlite3_initialize();
}

void murmur_shutdown(void) { (void)sqlite3_shutdown(); }
