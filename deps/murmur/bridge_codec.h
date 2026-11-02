/* Native HighLow sealed envelopes. This format is distinct from legacy
 * Murmur-SQL bundles. Successful authentication does not advance progress:
 * callers must commit imported effects and receipts in one transaction. */
#ifndef MURMUR_BRIDGE_CODEC_H
#define MURMUR_BRIDGE_CODEC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define MURMUR_BRIDGE_MAX_BUNDLE (16u << 20)
#define MURMUR_BRIDGE_MAX_PAYLOAD (64u << 20)
typedef struct {
  uint8_t database[16], node[16], transaction[16];
  uint64_t sequence;
  char stream[65];
  uint8_t schema[32];
} murmur_bridge_header_t;
typedef struct {
  uint8_t *data;
  size_t len;
} murmur_bridge_bytes_t;
void murmur_bridge_bytes_free(murmur_bridge_bytes_t *);
/* Derives the receiver public key from its X25519 private key. */
int murmur_bridge_recipient_public(const uint8_t secret[32], uint8_t out[32]);
/* Fresh ephemeral key and nonce on every call. Caller owns out on success;
 * out is empty on failure. Header identifiers and sequence must be nonzero.
 * Stream permits 1..64 ASCII letters, digits, underscores and hyphens. */
int murmur_bridge_seal(const murmur_bridge_header_t *, const uint8_t signer[32],
                       const uint8_t recipient[32], const void *payload,
                       size_t payload_len, size_t max_bundle,
                       size_t max_payload, murmur_bridge_bytes_t *out);
/* Expected source, stream, signer and recipient are supplied by trusted
 * configuration, never taken from the unverified envelope. No plaintext or
 * header escapes on failure. Authenticate before bounded decompression. */
int murmur_bridge_unseal(const void *bundle, size_t bundle_len,
                         const uint8_t expected_database[16],
                         const char *expected_stream,
                         const uint8_t trusted_signer[32],
                         const uint8_t receiver_secret[32], size_t max_bundle,
                         size_t max_payload, murmur_bridge_header_t *header,
                         murmur_bridge_bytes_t *payload);
#ifdef __cplusplus
}
#endif
#endif
