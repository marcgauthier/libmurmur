/* keys.enc v3 keyring envelope: C++ port of pkgs/storage/keyring.go.
 *
 * Byte-identical protector derivation (HKDF-SHA256, Argon2id +
 * HKDF-SHA256), envelope layout ("SPLK" magic, CRC32-Castagnoli
 * header checksum, AES-256-GCM body), and error taxonomy (auth /
 * corrupt / misuse). Pinned by the Go differential test
 * (bindings/nvfs/keyring_diff_test.go) against the Go implementation
 * and the sqlite-murmur fixed vectors.
 *
 * Robustness note: hostile envelopes (e.g. Argon2 threads=255) fail
 * closed with CORRUPT here; the Go implementation can panic inside
 * x/crypto on the same inputs. Fail-closed is the intended behavior.
 */
#ifndef MURMUR_KEYRING_H
#define MURMUR_KEYRING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* KDF ids match the Go KDFDirectHKDF/KDFArgon2ID. */
enum {
  MURMUR_KDF_DIRECT = 0,
  MURMUR_KDF_ARGON2ID = 1,
};

/* Result codes. */
enum {
  MURMUR_KR_OK = 0,
  MURMUR_KR_AUTH = 1,    /* wrong key/passphrase (GCM tag failure) */
  MURMUR_KR_CORRUPT = 2, /* malformed envelope or undecryptable */
  MURMUR_KR_MISUSE = 3,  /* caller error (bad params, dup ids, ...) */
  MURMUR_KR_NOMEM = 4,   /* allocation, RNG, or AES-NI failure */
};

typedef struct {
  uint32_t id;
  uint8_t key[32];
  int64_t created_at; /* unix nanos */
  int active;
} murmur_key_entry_t;

typedef struct {
  uint64_t seq;
  uint8_t kdf;
  uint32_t argon_time;
  uint32_t argon_mem_kib;
  uint8_t argon_threads;
  uint8_t context[16];
  uint8_t *wrap_id;
  size_t wrap_len;
  murmur_key_entry_t *keys; /* id-sorted */
  size_t nkeys;
  uint32_t current; /* highest active id */
} murmur_keyring_t;

/* Opens and authenticates an envelope. Exactly one protector form
 * must match the header KDF: a 32-byte master (master_len == 32) or
 * a non-empty passphrase. Returns a heap ring (wipe with
 * murmur_kr_free_ring) or NULL with *rc set. */
murmur_keyring_t *murmur_kr_open(const uint8_t *env, size_t env_len,
                                 const uint8_t *master, size_t master_len,
                                 const uint8_t *pass, size_t pass_len,
                                 const uint8_t store_id[16],
                                 const uint8_t context_id[16], int *rc);

/* Seals a fresh single-key envelope (id 1, seq 1), mirroring Create. */
int murmur_kr_create(uint8_t kdf, uint32_t argon_time, uint32_t argon_mem_kib,
                     uint8_t argon_threads, const uint8_t *wrap_id,
                     size_t wrap_len, const uint8_t store_id[16],
                     const uint8_t context_id[16], const uint8_t *master,
                     size_t master_len, const uint8_t *pass, size_t pass_len,
                     uint8_t **out_env, size_t *out_len);

/* Seals a successor revision: retires ring->current, mints the next
 * id. Mirrors Keyring.Rotate (caller re-opens to install). */
int murmur_kr_rotate(const murmur_keyring_t *ring, const uint8_t store_id[16],
                     const uint8_t *master, size_t master_len,
                     const uint8_t *pass, size_t pass_len, uint8_t **out_env,
                     size_t *out_len, uint32_t *out_next);

/* Seals a revision without the listed retired ids. Mirrors DropKeys. */
int murmur_kr_drop(const murmur_keyring_t *ring, const uint32_t *drop_ids,
                   size_t ndrop, const uint8_t store_id[16],
                   const uint8_t *master, size_t master_len,
                   const uint8_t *pass, size_t pass_len, uint8_t **out_env,
                   size_t *out_len);

/* Wipes and frees a ring / malloc'd envelope. */
void murmur_kr_free_ring(murmur_keyring_t *ring);
void murmur_kr_free(void *p);

/* ---- Test-only flat API (differential test, no handles) ----
 * murmur_kr_open_flat authenticates env and packs the ring flat:
 *   seq u64le, kdf u8, atime u32le, amem u32le, athreads u8,
 *   current u32le, nkeys u32le, wraplen u8, wrapid,
 *   keys x {id u32le, created i64le, active u8, key[32]}.
 * murmur_kr_seal_flat seals explicit keys (flat in the same entry
 * layout, nkeys entries, arbitrary order) at the given seq.
 * Return the result code; *out_* is malloc'd on success. */
int murmur_kr_open_flat(const uint8_t *env, size_t env_len,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        uint8_t **out_flat, size_t *out_len);
int murmur_kr_seal_flat(uint8_t kdf, uint64_t seq, const uint8_t store_id[16],
                        const uint8_t context_id[16], const uint8_t *wrap_id,
                        size_t wrap_len, uint32_t argon_time,
                        uint32_t argon_mem_kib, uint8_t argon_threads,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t *flat_keys, size_t nkeys,
                        uint8_t **out_env, size_t *out_len);
/* murmur_kr_rotate_flat / murmur_kr_drop_flat open env, apply the op,
 * and return the new envelope (plus the fresh id for rotate). */
int murmur_kr_rotate_flat(const uint8_t *env, size_t env_len,
                          const uint8_t store_id[16],
                          const uint8_t context_id[16], const uint8_t *master,
                          size_t master_len, const uint8_t *pass,
                          size_t pass_len, uint8_t **out_env, size_t *out_len,
                          uint32_t *out_next);
int murmur_kr_drop_flat(const uint8_t *env, size_t env_len,
                        const uint32_t *drop_ids, size_t ndrop,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        uint8_t **out_env, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
