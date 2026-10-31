/* murmur config - native settings surface: defaults, Validate,
 * Setting, SetSetting over a sqlite3 connection.
 *
 * Port of config.go (defaults + Validate) and schema.go Setting /
 * SetSetting: names, defaults, ranges, and accept/reject behavior
 * match Go. Validation errors report INVALID (Go Validate returns
 * plain errors; only accept/reject is observable); SQLite failures
 * report SQLITE. Address validation mirrors Go SplitHostPort /
 * ResolveTCPAddr / ParseCIDR semantics, including DNS and service
 * resolution through the system resolver (getaddrinfo consults the
 * same databases Go does, so answers agree on any machine; like Go,
 * validation of a name may block on DNS).
 */
#ifndef MURMUR_CONFIG_H
#define MURMUR_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "sync.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/* Default for a stripped setting name, or NULL when unknown. */
const char *murmur_cfg_default(const char *name);

/* Strict u64 parse mirroring Go atoi (digits only, no sign). */
int murmur_cfg_atoi(const char *s, uint64_t *v);

/* u64 parse mirroring Go strconv.ParseUint base 10 (digits
 * only; unlike ParseInt, no sign is allowed). */
int murmur_cfg_parse_uint(const uint8_t *s, size_t n, uint64_t *v);

/* Parses a 32-hex-digit node id (dashes stripped, nonzero). */
int murmur_cfg_parse_id(const uint8_t *s, size_t n, murmur_node_t *out);

/* Validates one setting value (explicit length; NULs rejected).
 * Needs db only for the JSON-shaped settings (parsed via JSON1
 * with encoding/json accept/reject semantics). 0 = valid. */
int murmur_cfg_validate(sqlite3 *db, const char *name, const uint8_t *value,
                        size_t len);

/* table_replication map (last duplicate wins, like Go). */
typedef struct {
  char *table; /* ASCII-lowercased */
  int enabled;
} murmur_table_flag_t;

typedef struct {
  murmur_table_flag_t *ents;
  size_t n;
} murmur_table_flags_t;

void murmur_cfg_table_flags_free(murmur_table_flags_t *f);

/* Loads table_replication (default "{}") with Go encoding/json
 * semantics for the {"table":bool} shape. */
murmur_sync_status_t murmur_cfg_table_flags(sqlite3 *db,
                                            murmur_table_flags_t *f,
                                            int *sqlrc);

/* Reports whether table is explicitly disabled (matched
 * ASCII-lowercased on both sides; Go uses Unicode lowercase and
 * agrees on ASCII names). */
int murmur_cfg_table_disabled(const murmur_table_flags_t *f,
                              const uint8_t *table, size_t table_len);

/* Reports whether any table is disabled. */
int murmur_cfg_table_filtering(const murmur_table_flags_t *f);

/* Reads one stripped setting (persisted value or default;
 * writer_remote_share derives) into a malloc'd string. */
murmur_sync_status_t murmur_cfg_setting(sqlite3 *db, const char *name,
                                        char **out, int *sqlrc);

/* Validates and persists one stripped setting. */
murmur_sync_status_t murmur_cfg_set_setting(sqlite3 *db, const char *name,
                                            const uint8_t *value, size_t len,
                                            int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_CONFIG_H */
