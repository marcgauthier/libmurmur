/* sqlite-murmur page codec: seal/open page records entirely in C++.
 *
 * Part of the sqlite-murmur C++ library: SQLite + VFS + page engine +
 * codec + zstd + RocksDB + CRR capture, with Go talking only to the
 * SQLite API and the murmur control API. No per-page callbacks into
 * Go: key material is provisioned once at create/rekey time.
 *
 * Record layouts mirror pkgs/storage/crypto.go exactly (EXP1-EXP4); the Go
 * engine stays the differential oracle until the staged path is gone.
 */
#ifndef MURMUR_CODEC_H
#define MURMUR_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ciphers mirror storage.Cipher. */
enum {
  MURMUR_CIPHER_AES256GCM = 1,
  MURMUR_CIPHER_AEGIS256 = 2,
};

typedef struct MurmurCodec MurmurCodec;

/* Creates a codec, copying all key material. cipher is 1 (AES-256-GCM)
 * or 2 (AEGIS-256); level is 0 (no compression) or 1..22 (zstd).
 * page_key seals legacy records (master when unsealed, active data key
 * when sealed). sealed!=0 installs the ring trial set (active data key
 * + current id + retired keys); master backs legacy records on sealed
 * stores only, exactly like the Go trial chain. Returns NULL on misuse,
 * OOM, or a missing AES backend (AES cipher only; AWS-LC is always
 * linked, so this only fires when availability is compiled out). */
MurmurCodec *murmur_codec_create(int cipher, int level,
                                 const uint8_t page_key[32], int sealed,
                                 const uint8_t active[32], uint32_t current_id,
                                 const uint32_t *retired_ids,
                                 const uint8_t *retired_keys, size_t retired_count,
                                 const uint8_t master[32]);

/* Cold updates; all copy material in. Return 0 or -5 (misuse). */
int murmur_codec_set_cipher(MurmurCodec *c, int cipher);
int murmur_codec_set_level(MurmurCodec *c, int level);
int murmur_codec_install_ring(MurmurCodec *c, const uint8_t active[32],
                              uint32_t current_id, const uint32_t *retired_ids,
                              const uint8_t *retired_keys, size_t retired_count);

/* Seals 4096 plaintext bytes for page into out (cap >= 8192). Returns
 * the record length, or a negative nv_crypto.h code. payload_len (may
 * be NULL) receives the pre-encryption payload bytes for stats. */
int murmur_codec_seal(MurmurCodec *c, uint64_t page, const uint8_t in[4096],
                      uint8_t *out, size_t out_cap, size_t *payload_len);

/* Seals like murmur_codec_seal but with an explicit data-key id
 * (0 selects the legacy unkeyed formats). Offline rekey uses it to
 * preserve each page's keyed/legacy shape while rotating the key. */
int murmur_codec_seal_as(MurmurCodec *c, uint64_t page,
                         const uint8_t in[4096], uint8_t *out, size_t out_cap,
                         uint32_t key_id, size_t *payload_len);

/* Peeks the data-key id of a keyed (EXP3/EXP4) record into *key_id.
 * Returns 1 when keyed, 0 for legacy/corrupt/short records. */
int murmur_record_key_id(const uint8_t *in, size_t in_len, uint32_t *key_id);

/* Opens one record for page into out (cap >= 4096). Returns 4096, or a
 * negative nv_crypto.h code (-2 auth, -3 corrupt, -5 misuse). */
int murmur_codec_open(MurmurCodec *c, uint64_t page, const uint8_t *in,
                      size_t in_len, uint8_t *out, size_t out_cap);

/* Destroys the codec, wiping all key material. */
void murmur_codec_destroy(MurmurCodec *c);

#ifdef __cplusplus
}
#endif

#endif
