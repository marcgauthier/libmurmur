/* Native writer admission. One scheduler per database; no SQLite locks may
 * be held while acquiring. Destroy only after all callers have joined. */
#ifndef MURMUR_SCHEDULER_H
#define MURMUR_SCHEDULER_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct murmur_scheduler murmur_scheduler_t;
typedef enum { MURMUR_WRITER_LOCAL, MURMUR_WRITER_REMOTE,
               MURMUR_WRITER_MAINTENANCE } murmur_writer_class_t;
typedef struct {
  unsigned local_share; /* 1..99, remote = 100-local */
  uint64_t max_debt_ns;
  uint64_t maintenance_every;
} murmur_scheduler_config_t;
typedef struct {
  uint64_t acquisitions, cancels, wait_ns, service_ns, waiters;
} murmur_writer_stats_t;
typedef struct {
  murmur_scheduler_config_t config;
  murmur_writer_stats_t classes[3];
  int64_t debt_ns;
  int active, closed;
} murmur_scheduler_stats_t;
/* SQLite return codes. timeout_ms < 0 waits indefinitely, zero polls.
 * cancel is called without scheduler/SQLite locks; return nonzero to cancel.
 * Exactly one release per successful acquire, on the acquiring thread.
 * Recursive acquire is MISUSE. close cancels waiters, not the active owner. */
typedef int (*murmur_cancel_fn)(void *);
murmur_scheduler_config_t murmur_scheduler_defaults(void);
int murmur_scheduler_create(const murmur_scheduler_config_t *, murmur_scheduler_t **);
int murmur_scheduler_acquire(murmur_scheduler_t *, murmur_writer_class_t,
                             int64_t timeout_ms, murmur_cancel_fn, void *);
int murmur_scheduler_release(murmur_scheduler_t *);
void murmur_scheduler_snapshot(murmur_scheduler_t *, murmur_scheduler_stats_t *);
void murmur_scheduler_close(murmur_scheduler_t *);
void murmur_scheduler_destroy(murmur_scheduler_t *);
#ifdef __cplusplus
}
#endif
#endif
