/* Causal state for Counter, Set, Json and List policies. Values are opaque
 * canonical application-value bytes. Row generations/baselines belong to
 * the managed policy layer, not this join/codec core. Not thread safe. */
#ifndef MURMUR_CAUSAL_H
#define MURMUR_CAUSAL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { MURMUR_CAUSAL_COUNTER, MURMUR_CAUSAL_SET,
               MURMUR_CAUSAL_JSON, MURMUR_CAUSAL_LIST } murmur_causal_kind_t;
typedef struct murmur_causal murmur_causal_t;
typedef struct {
  uint8_t database[16], node[16], transaction[16];
  uint32_t operation;
} murmur_causal_tag_t;
typedef enum { MURMUR_CAUSAL_ADD, MURMUR_CAUSAL_REMOVE } murmur_causal_op_t;
int murmur_causal_create(murmur_causal_kind_t, murmur_causal_t **);
int murmur_causal_kind(const murmur_causal_t *,murmur_causal_kind_t *);
void murmur_causal_free(murmur_causal_t *);
int murmur_causal_counter_add(murmur_causal_t *,const uint8_t database[16],
                              const uint8_t node[16],int64_t delta);
int murmur_causal_counter_value(const murmur_causal_t *,int64_t *);
/* Project baseline + positive components - negative components using a wide
 * accumulator; the causal delta alone need not fit in int64. */
int murmur_causal_counter_project(const murmur_causal_t *,int64_t baseline,int64_t *);
/* ADD is Set.add / Json.set / List.append. REMOVE retires only observed
 * writes for the value (Set/List) or path (Json). tag required for ADD.
 * Each ADD must have a unique tag. Counter uses counter_add instead. */
int murmur_causal_apply(murmur_causal_t *,murmur_causal_op_t,
    const void *path,size_t path_len,const void *value,size_t value_len,
    const murmur_causal_tag_t *tag);
/* Kind mismatch is SQLITE_MISMATCH, conflicting values under one tag are
 * SQLITE_CORRUPT. Failed operations leave the destination unchanged. */
int murmur_causal_join(murmur_causal_t *,const murmur_causal_t *);
/* Authenticate a complete incoming state before join. Only the signing
 * database/node may introduce actor components or operation tags. Other
 * actors must already be covered by known (including deterministic baseline
 * seeds). Unseen dependencies/removals return SQLITE_BUSY so the caller can
 * fetch their original signed records. This does not mutate either state.
 * It supplements envelope verification; it does not verify signatures. */
int murmur_causal_authorize(const murmur_causal_t *known,
    const murmur_causal_t *incoming,const uint8_t database[16],
    const uint8_t signer[16]);
typedef int (*murmur_causal_visit_fn)(void *,const void *path,size_t,
                                     const void *value,size_t);
int murmur_causal_values(const murmur_causal_t *,murmur_causal_visit_fn,void *);
/* Go-reference EncodeCausal postcard layout. malloc-owned output; free().
 * Decoding is bounded to 64MiB and rejects truncation/overflow/trailing data. */
int murmur_causal_encode(const murmur_causal_t *,uint8_t **,size_t *);
int murmur_causal_decode(const void *,size_t,murmur_causal_t **);
#ifdef __cplusplus
}
#endif
#endif
