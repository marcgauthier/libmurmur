#ifndef MURMUR_TEST_MANAGED_SUPPORT_H
#define MURMUR_TEST_MANAGED_SUPPORT_H
#include "../../libmurmur.h"
#include "managed_value.h"
#include "managed_internal.h"
#include <array>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

namespace managed_test {
inline void require(bool condition,const std::string &message) {
  if(!condition) throw std::runtime_error(message);
}
inline void check(int rc,const std::string &where) {
  require(rc==SQLITE_OK,where+": rc="+std::to_string(rc));
}
using Rows=std::vector<std::vector<ManagedValue>>;
struct Request { std::vector<std::string> sql; Rows rows; };
inline int collect(void *ctx,int n,const murmur_value_t *v) {
  try {
    std::vector<ManagedValue> row;
    for(int i=0;i<n;++i) row.push_back(ManagedValue::from(v[i]));
    ((Request *)ctx)->rows.push_back(std::move(row)); return 0;
  } catch(...) { return 1; }
}
inline int execute(murmur_transaction_t *tx,void *ctx) {
  auto &request=*(Request *)ctx;
  for(auto &sql:request.sql) {
    int rc=murmur_transaction_execute(tx,sql.c_str(),nullptr,0,collect,&request);
    if(rc) return rc;
  }
  return SQLITE_OK;
}
inline int run(murmur_managed_t *db,const std::vector<std::string> &sql,Rows *rows=nullptr,
               murmur_writer_class_t cls=MURMUR_WRITER_LOCAL) {
  Request request{sql,{}};
  int rc=murmur_managed_transaction(db,cls,-1,nullptr,nullptr,execute,&request);
  if(rows) *rows=std::move(request.rows);
  return rc;
}
inline Rows query(murmur_managed_t *db,const std::string &sql) {
  Rows rows; check(run(db,{sql},&rows),sql); return rows;
}
inline void sql(murmur_managed_t *db,const std::vector<std::string> &statements) {
  check(run(db,statements),statements.empty()?"empty transaction":statements.front());
}
struct Record {
  murmur_origin_record_t value{};
  Record()=default;
  explicit Record(murmur_origin_record_t r):value(r) {}
  Record(const Record &)=delete;
  Record &operator=(const Record &)=delete;
  Record(Record &&other) noexcept:value(other.value) { other.value={}; }
  Record &operator=(Record &&other) noexcept {
    if(this!=&other) { murmur_origin_record_free(&value); value=other.value; other.value={}; }
    return *this;
  }
  ~Record() { murmur_origin_record_free(&value); }
};
struct Cluster {
  std::string root;
  std::array<uint8_t,32> key{};
  std::array<uint8_t,16> database{};
  struct Node {
    murmur_managed_t *db=nullptr;
    std::string path;
    std::array<uint8_t,16> id{};
    std::array<uint8_t,32> seed{};
    murmur_origin_identity_t identity{};
  };
  std::vector<Node> nodes;
  bool preserve=false;
  explicit Cluster(size_t count) {
    char pattern[]="/tmp/murmur-native-tests-XXXXXX";
    auto *dir=mkdtemp(pattern); require(dir,"mkdtemp"); root=dir;
    key[0]=41; database[0]=73; nodes.resize(count);
    try {
      for(size_t i=0;i<count;++i) {
        auto &node=nodes[i]; node.path=root+"/node-"+std::to_string(i); node.id[0]=(uint8_t)(i+1); node.seed[0]=(uint8_t)(i+11);
        check(murmur_managed_open(node.path.c_str(),key.data(),&node.db),"open node");
        check(murmur_managed_origin_configure(node.db,database.data(),node.id.data(),node.seed.data()),"configure node");
        check(murmur_managed_origin_identity(node.db,&node.identity),"identity");
      }
      for(size_t i=0;i<count;++i) for(size_t j=0;j<count;++j) if(i!=j)
        check(murmur_managed_origin_trust(nodes[i].db,&nodes[j].identity,1),"trust");
      for(size_t i=1;i<count;++i) check(murmur_managed_schema_master(nodes[i].db,nodes[0].id.data()),"schema authority");
    } catch(...) { close(); std::filesystem::remove_all(root); throw; }
  }
  void close() { for(auto &node:nodes) if(node.db) { murmur_managed_close(node.db); node.db=nullptr; } }
  ~Cluster() { close(); if(!preserve) { std::error_code ec; std::filesystem::remove_all(root,ec); } }
  void schema() {
    Record record; check(murmur_managed_schema_export(nodes[0].db,&record.value),"schema export");
    for(size_t i=1;i<nodes.size();++i) { int changed=0; check(murmur_managed_schema_adopt(nodes[i].db,&record.value,&changed),"schema adopt"); }
  }
  void reopen(size_t i) {
    auto &node=nodes.at(i); murmur_managed_close(node.db); node.db=nullptr;
    check(murmur_managed_open(node.path.c_str(),key.data(),&node.db),"reopen");
    check(murmur_managed_origin_configure(node.db,database.data(),node.id.data(),node.seed.data()),"reopen identity");
  }
  Record next(size_t i,uint64_t previous) {
    Record out; check(murmur_managed_origin_next(nodes[i].db,nodes[i].id.data(),previous,&out.value),"next origin record");
    require(out.value.envelope.sequence==previous+1,"noncontiguous local sequence"); return out;
  }
};
inline std::string hex(const void *raw,size_t size) {
  static const char digits[]="0123456789abcdef"; auto *p=(const uint8_t *)raw; std::string out; out.reserve(size*2);
  for(size_t i=0;i<size;++i) { out+=digits[p[i]>>4]; out+=digits[p[i]&15]; } return out;
}
/* Test-only inspection of owned persistent state, always under admission.
 * Public queries/progress cannot detect an invisible poisoned causal state. */
inline std::string persistent_snapshot(murmur_managed *db) {
  check(murmur_scheduler_acquire(db->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr),"snapshot admission");
  struct Restore { murmur_managed *db; int previous; ~Restore() { db->access=previous; murmur_scheduler_release(db->coordinator->scheduler); } } restore{db,db->access}; db->access=3;
  std::string out;
  for(auto *sql:{"SELECT * FROM murmur_origin_heads ORDER BY origin",
                 "SELECT * FROM murmur_origin_log ORDER BY origin,sequence",
                 "SELECT * FROM murmur_managed_row_epochs ORDER BY table_id,row_key",
                 "SELECT * FROM murmur_managed_policy_state ORDER BY column_id,row_key,epoch",
                 "SELECT * FROM murmur_replica_current ORDER BY table_id,row_key",
                 "SELECT * FROM murmur_replica_rows ORDER BY table_id,row_key,epoch",
                 "SELECT * FROM murmur_replication_history ORDER BY table_id",
                 "SELECT * FROM murmur_managed_generation",
                 "SELECT * FROM murmur_managed_columns ORDER BY table_id,name",
                 "SELECT * FROM murmur_managed_policies ORDER BY column_id",
                 "SELECT * FROM murmur_schema_control",
                 "SELECT * FROM murmur_schema_artifacts ORDER BY master,sequence",
                 "SELECT clock_ms,clock_logic FROM murmur_origin_config",
                 "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name"}) {
    out+=sql; sqlite3_stmt *raw=nullptr; check(sqlite3_prepare_v2(db->db,sql,-1,&raw,nullptr),"snapshot prepare");
    std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> owned(raw,sqlite3_finalize); int rc;
    while((rc=sqlite3_step(raw))==SQLITE_ROW) { std::vector<ManagedValue> values; for(int i=0;i<sqlite3_column_count(raw);++i) values.push_back(ManagedValue::column(raw,i)); out+=managed_encode_values(values); }
    require(rc==SQLITE_DONE,"snapshot rows");
  }
  return out;
}
}
#endif
