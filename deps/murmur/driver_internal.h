/* Internals exposed only for white-box selftests (see e.g.
 * bridge_peer_internal.h for the same convention): these are not
 * part of the public driver.h API. */
#ifndef MURMUR_DRIVER_INTERNAL_H
#define MURMUR_DRIVER_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Exponential-backoff delay (ms) for a dial failure streak of
 * fail_count consecutive failures against one address. fail_count==0
 * (or a prior success) yields the 5s base window; failures double
 * the window up to a 300s (5min) cap, jittered +/-25% deterministically
 * from `seed` (see dial_backoff_seed). Pure function: no clock reads,
 * no global state, safe to call from any thread/context. */
uint64_t dial_backoff_ms(uint32_t fail_count, uint64_t seed);

/* Deterministic jitter seed derived from the dial address and the
 * wall-clock time of the failure, so repeated failures against the
 * same address at different times (and different addresses at the
 * same time) land on different jittered delays. */
uint64_t dial_backoff_seed(const char *addr, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_DRIVER_INTERNAL_H */
