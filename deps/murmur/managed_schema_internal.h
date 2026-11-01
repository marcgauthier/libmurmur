#ifndef MURMUR_MANAGED_SCHEMA_INTERNAL_H
#define MURMUR_MANAGED_SCHEMA_INTERNAL_H
#include "managed_internal.h"
#include "managed_origin.h"
#include <array>
#include <map>
struct ManagedSchemaColumn {
  std::string id,name;
  unsigned policy=0,fts=0,dimensions=0,distance=0;
};
struct ManagedSchemaTable {
  std::string id,name,ddl;
  std::vector<ManagedSchemaColumn> columns;
};
struct ManagedSchemaIndex { std::string name,table,ddl; };
struct ManagedSchema {
  std::vector<ManagedSchemaTable> tables;
  std::vector<ManagedSchemaIndex> indexes;
};
struct ManagedSchemaMigration {
  struct Shape { std::string name,type,default_sql; int not_null=0,pk=0; };
  ManagedSchema before;
  std::map<std::string,std::vector<Shape>> shapes;
  std::vector<murmur_rename_t> mappings; /* borrowed until migrate returns */
};
int managed_schema_initialize(murmur_managed *);
int managed_schema_activate(murmur_managed *,const uint8_t node[16]);
int managed_schema_publish(murmur_managed *);
bool managed_schema_authority(murmur_managed *);
int managed_schema_require_authority(murmur_managed *,const char *table=nullptr);
int managed_schema_migration_begin(murmur_managed *,const murmur_rename_t *,size_t);
int managed_schema_migration_finish(murmur_managed *);
int managed_schema_authorize(murmur_managed *,int,const char *,const char *,const char *);
std::array<uint8_t,32> managed_schema_digest(murmur_managed *);
ManagedSchema managed_schema_capture(murmur_managed *);
ManagedSchema managed_schema_decode(const std::string &);
std::string managed_schema_encode(const ManagedSchema &);
/* Validate old signed schema and map immutable IDs to current SQL names. */
std::string managed_schema_translate_cells(murmur_managed *,const uint8_t digest[32],const uint8_t *,size_t);
int managed_origin_sign_record(murmur_managed *,murmur_origin_envelope_t *,const void *,size_t);
int managed_origin_verify_record(murmur_managed *,const murmur_origin_record_t *);
int managed_origin_identity_internal(murmur_managed *,murmur_origin_identity_t *);
int managed_origin_observe_record(murmur_managed *,const murmur_origin_envelope_t *);
#endif
