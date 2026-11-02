/* murmur fetch - native file fetch service
 * (replication/filefetch_service.go + filefetch.go).
 *
 * Serves file objects over an independent mTLS QUIC endpoint
 * (ALPN "murmur-sqlite/files/1"); metadata replicates through the
 * ordinary mesh. fetchMissing is one scheduler step: the driver
 * tick (N8d) supplies sources from live peers every FetchInterval.
 *
 * Status reuse: murmur_files_status_t covers the fetch taxonomy
 * (transport timeouts surface as UNAVAILABLE, like Go's
 * context-deadline mapping). detail_out is the owned message.
 */
#ifndef MURMUR_FETCH_H
#define MURMUR_FETCH_H

#include <stddef.h>
#include <stdint.h>

#include "files.h"
#include "member.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_FETCH_ALPN "murmur-sqlite/files/1"
#define MURMUR_FETCH_SNI "murmur.invalid"
#define MURMUR_FETCH_TIMEOUT_MS 300000
#define MURMUR_FETCH_LINGER_MS 30000
#define MURMUR_FETCH_SERVE_CHUNK (64u << 10)

typedef struct {
  const char *bind_ip; /* NULL = 127.0.0.1 */
  uint16_t bind_port;  /* 0 = ephemeral */
  const uint8_t **chain_der;
  const size_t *chain_lens;
  size_t chain_n;
  const uint8_t *key_pem;
  size_t key_len;
  const uint8_t **ca_der;
  const size_t *ca_lens;
  size_t ca_n;
  const uint8_t *crl_der; /* NULL/0 disables revocation */
  size_t crl_len;
  murmur_node_t self;
  const murmur_node_t *allowed; /* empty = all authenticated */
  size_t n_allowed;
  const char **allow_cidrs; /* empty = all networks */
  size_t n_cidrs;
  int concurrent_fetches;
  uint64_t max_staging_bytes;
  uint32_t max_conns; /* 0 = default */
} murmur_fetch_config_t;

/* Sources reuse member.h's murmur_fetch_source_t (node + addr),
 * which membership fills in for the driver tick (N8d). */
typedef struct murmur_fetch_t murmur_fetch_t;

/* Starts the endpoint and accept loop. objects/database borrowed. */
murmur_files_status_t murmur_fetch_start(const murmur_fetch_config_t *config,
                                         murmur_files_t *objects,
                                         const murmur_node_t *database,
                                         murmur_fetch_t **out,
                                         char **detail_out);
void murmur_fetch_stop(murmur_fetch_t *s);

/* Bound "ip:port" of the endpoint. */
int murmur_fetch_local_addr(murmur_fetch_t *s, char *ip, size_t ip_len,
                            uint16_t *port);

/* One scheduler step: reap staging orphans, then spawn bounded
 * fetches for locally-missing objects. Returns after spawning;
 * transfers complete on worker threads. */
murmur_files_status_t murmur_fetch_missing(murmur_fetch_t *s,
                                           const murmur_fetch_source_t *sources,
                                           size_t n_sources, char **detail_out,
                                           int *sqlrc);

/* Resume offset for a staged partial (unresumable bytes without a
 * 32-byte sidecar are discarded). Exposed for tests. */
murmur_files_status_t murmur_fetch_resume_offset(const char *path,
                                                 uint64_t *offset,
                                                 char **detail_out);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_FETCH_H */
