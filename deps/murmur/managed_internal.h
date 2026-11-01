#ifndef MURMUR_MANAGED_INTERNAL_H
#define MURMUR_MANAGED_INTERNAL_H
#include "managed.h"
#include "search.h"
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct Coordinator {
  murmur_scheduler_t *scheduler = nullptr;
  Coordinator() { murmur_scheduler_create(nullptr, &scheduler); }
  ~Coordinator() { murmur_scheduler_destroy(scheduler); }
};
struct ManagedPolicies;
struct ManagedOrigin;
struct ManagedSchemaMigration;
struct murmur_managed {
  sqlite3 *db = nullptr;
  bool crsqlite = false;
  uint64_t store_ref = 0;
  std::shared_ptr<ManagedOrigin> origin;
  std::shared_ptr<Coordinator> coordinator;
  int access = 0; /* 0 deny, 1 app prepare, 2 migration, 3 internal, 4 vetted step, 5 constrained remote DDL */
  std::shared_ptr<ManagedPolicies> policies;
  murmur_transaction *active_transaction = nullptr;
  bool policy_altered = false;
  std::shared_ptr<ManagedSchemaMigration> schema_migration;
  int ddl_action=0;
  std::string ddl_name,ddl_table;
  murmur_search_manager_t *search = nullptr;
  int64_t search_generation = -1, search_data_version = -1;
  std::vector<std::string> search_sources;
  std::string search_error;
  std::thread search_worker;
  std::mutex worker_mu;
  std::condition_variable worker_cv;
  bool worker_stop = false;
};
struct murmur_transaction {
  murmur_managed *owner;
  std::thread::id thread;
  size_t policy_operations = 0;
};
int managed_policy_initialize(murmur_managed *);
int managed_policy_sync(murmur_managed *,bool install=false);
bool managed_policy_trusted_trigger(murmur_managed *,const char *);
bool managed_policy_update_denied(murmur_managed *,const char *,const char *);
bool managed_policy_sql_function(const char *);
bool managed_policy_ddl_denied(murmur_managed *,int,const char *);
int managed_origin_initialize(murmur_managed *);
int managed_origin_sync(murmur_managed *);
int managed_origin_begin(murmur_managed *,int64_t *);
int managed_origin_finish(murmur_managed *,int64_t,bool *);
bool managed_origin_trusted_trigger(murmur_managed *,const char *);
bool managed_origin_ddl_denied(murmur_managed *,int,const char *);
bool managed_origin_replicated(murmur_managed *,const char *);
/* All except start/stop require the database scheduler grant. */
int managed_search_sync(murmur_managed *, bool force = false);
int managed_search_work(murmur_managed *, bool drain);
void managed_search_start(murmur_managed *);
void managed_search_stop(murmur_managed *);
/* Replace temp tables within the caller's transaction. Complete(commit=false)
 * restores the old manager after the SQLite rollback restores old tables. */
struct ManagedSearchChange {
  murmur_search_manager_t *old = nullptr;
  int64_t generation = -1;
  std::vector<std::string> sources;
  bool changed = false;
};
int managed_search_change(murmur_managed *, ManagedSearchChange &);
void managed_search_complete(murmur_managed *, ManagedSearchChange &, bool commit);
#endif
