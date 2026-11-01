#ifndef MURMUR_MANAGED_SCHEMA_H
#define MURMUR_MANAGED_SCHEMA_H
#include "managed_origin.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Pin the schema authority before data history exists. Default is the local
 * origin. The authority must already be a trusted origin on followers. */
int murmur_managed_schema_master(murmur_managed_t *,const uint8_t origin[16]);
/* Export current or look up a historical schema by its 32-byte digest.
 * Records use MMS2 payloads and the origin envelope; record_free owns output.
 * Historical imports are retained for applying old transactions without
 * rolling back the current schema. */
int murmur_managed_schema_export(murmur_managed_t *,murmur_origin_record_t *);
int murmur_managed_schema_find(murmur_managed_t *,const uint8_t digest[32],murmur_origin_record_t *);
int murmur_managed_schema_adopt(murmur_managed_t *,const murmur_origin_record_t *,int *changed);
#ifdef __cplusplus
}
#endif
#endif
