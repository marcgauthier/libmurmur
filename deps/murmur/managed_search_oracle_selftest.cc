#include "test_managed_support.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <map>
#include <random>
#include <set>

using namespace managed_test;
namespace {
struct Doc { std::string body,title; std::array<float,3> point; };
struct Indexes { std::string fts,vector; };
struct StaleProbe { std::string mutation,query; int query_rc=SQLITE_OK; };
int stale_probe(murmur_transaction_t *tx,void *ctx) {
  auto &probe=*(StaleProbe *)ctx;
  int rc=murmur_transaction_execute(tx,probe.mutation.c_str(),nullptr,0,nullptr,nullptr); if(rc) return rc;
  probe.query_rc=murmur_transaction_execute(tx,probe.query.c_str(),nullptr,0,nullptr,nullptr);
  return probe.query_rc==SQLITE_AUTH?SQLITE_OK:SQLITE_ABORT;
}
int status(void *ctx,int n,const murmur_value_t *v) {
  if(n!=6 || v[0].type!=MURMUR_TEXT) return 1;
  std::string name((const char *)v[0].data,v[0].bytes); auto &out=*(Indexes *)ctx;
  (name.find("murmur_fts_")==0?out.fts:out.vector)=name; return 0;
}
Indexes indexes(murmur_managed *db) {
  Indexes out; check(murmur_managed_search_status(db,status,&out),"search status");
  require(!out.fts.empty() && !out.vector.empty(),"both search declarations present"); return out;
}
std::string blob(const std::array<float,3> &point) { return "x'"+hex(point.data(),sizeof(point))+"'"; }
struct Oracle {
  sqlite3 *db=nullptr;
  Oracle() { check(sqlite3_open(":memory:",&db),"open independent FTS"); }
  ~Oracle() { sqlite3_close(db); }
  void rebuild(const std::map<int,Doc> &docs) {
    check(sqlite3_exec(db,"DROP TABLE IF EXISTS fresh; CREATE VIRTUAL TABLE fresh USING fts5(body,title)",nullptr,nullptr,nullptr),"fresh FTS rebuild");
    sqlite3_stmt *raw=nullptr; check(sqlite3_prepare_v2(db,"INSERT INTO fresh(rowid,body,title) VALUES(?1,?2,?3)",-1,&raw,nullptr),"fresh FTS insert");
    std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> statement(raw,sqlite3_finalize);
    for(auto &entry:docs) {
      check(sqlite3_bind_int(raw,1,entry.first),"FTS rowid");
      check(sqlite3_bind_text(raw,2,entry.second.body.c_str(),-1,SQLITE_TRANSIENT),"FTS body");
      check(sqlite3_bind_text(raw,3,entry.second.title.c_str(),-1,SQLITE_TRANSIENT),"FTS title");
      require(sqlite3_step(raw)==SQLITE_DONE,"fresh FTS populate"); check(sqlite3_reset(raw),"FTS reset");
    }
  }
  std::vector<int64_t> match(const char *term) {
    sqlite3_stmt *raw=nullptr; check(sqlite3_prepare_v2(db,"SELECT rowid FROM fresh WHERE fresh MATCH ?1 ORDER BY rowid",-1,&raw,nullptr),"fresh FTS match");
    std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> statement(raw,sqlite3_finalize); check(sqlite3_bind_text(raw,1,term,-1,SQLITE_TRANSIENT),"match operand");
    std::vector<int64_t> out; int rc; while((rc=sqlite3_step(raw))==SQLITE_ROW) out.push_back(sqlite3_column_int64(raw,0)); require(rc==SQLITE_DONE,"FTS match complete"); return out;
  }
};
struct Fixture {
  Cluster cluster{1};
  murmur_managed *other=nullptr;
  Oracle oracle;
  std::mt19937 random{7183};
  std::map<int,Doc> docs;
  std::string table="docs",body="body",point="embedding";
  Fixture() {
    check(murmur_managed_migrate(a(),"CREATE TABLE docs(id INTEGER PRIMARY KEY,body TEXT,title TEXT,embedding BLOB)"),"search source schema");
    for(int i=0;i<620;++i) docs.emplace(i,doc(i));
    std::vector<std::string> statements; for(auto &entry:docs) statements.push_back(insert(entry.first,entry.second)); sql(a(),statements);
    check(murmur_managed_set_search(a(),"docs","body",1,0,0),"FTS body declaration");
    check(murmur_managed_set_search(a(),"docs","title",1,0,0),"FTS title declaration");
    check(murmur_managed_set_search(a(),"docs","embedding",0,3,0),"vector declaration");
    check(murmur_managed_open(cluster.nodes[0].path.c_str(),cluster.key.data(),&other),"second source handle");
  }
  ~Fixture() { if(other) murmur_managed_close(other); }
  murmur_managed *a() { return cluster.nodes[0].db; }
  Doc doc(int id) {
    static const char *words[]={"alpha beta","beta gamma","alpha delta","epsilon gamma","alpha beta gamma"};
    Doc d; d.body=words[random()%5]; d.title=id%3?"heading alpha":"heading gamma";
    for(int i=0;i<3;++i) d.point[i]=(float)((int)(random()%201)-100)/11.0f+(float)(id+1)*(float)(i+1)*0.0017f;
    return d;
  }
  std::string insert(int id,const Doc &d) {
    return "INSERT OR REPLACE INTO "+table+"(id,"+body+",title,"+point+") VALUES("+std::to_string(id)+",'"+d.body+"','"+d.title+"',"+blob(d.point)+")";
  }
  void verify(int metric) {
    oracle.rebuild(docs);
    auto original=indexes(a());
    for(auto *db:{a(),other}) {
      check(murmur_managed_refresh_indexes(db),"drain incremental search"); auto idx=indexes(db);
      require(idx.fts==original.fts && idx.vector==original.vector,"index identities differ between handles");
      for(auto *term:{"alpha","beta","alpha OR gamma","alpha NOT beta","\"alpha beta\"","heading AND gamma"}) {
        std::vector<int64_t> actual;
        for(auto &row:query(db,"SELECT rowid FROM temp.\""+idx.fts+"\" WHERE \""+idx.fts+"\" MATCH '"+term+"' ORDER BY rowid")) actual.push_back(row[0].integer);
        require(actual==oracle.match(term),"incremental FTS differs from fresh rebuild: "+std::string(term));
      }
      for(auto q:{std::array<double,3>{0.137,-0.283,0.419},std::array<double,3>{2.31,-4.07,1.83},std::array<double,3>{-3.2,0.91,-0.77}}) {
        std::vector<std::pair<double,int>> brute;
        for(auto &entry:docs) {
          double squared=0,l1=0,dot=0,norm=0,query_norm=0;
          for(int i=0;i<3;++i) {
            /* vec0 parses query operands as float32. */
            double operand=(float)q[i],coordinate=entry.second.point[i],delta=coordinate-operand;
            squared+=delta*delta; l1+=std::abs(delta); dot+=coordinate*operand; norm+=coordinate*coordinate; query_norm+=operand*operand;
          }
          double distance=metric==0?std::sqrt(squared):(metric==1?1.0-dot/std::sqrt(norm*query_norm):l1);
          brute.emplace_back(distance,entry.first);
        }
        std::sort(brute.begin(),brute.end());
        std::string operand="["+std::to_string(q[0])+","+std::to_string(q[1])+","+std::to_string(q[2])+"]";
        auto rows=query(db,"SELECT rowid,distance FROM temp.\""+idx.vector+"\" WHERE \""+point+"\" MATCH '"+operand+"' AND k=7 ORDER BY distance");
        require(rows.size()==7,"vector top-k cardinality");
        std::set<int64_t> ids;
        for(auto &row:rows) {
          require(ids.insert(row[0].integer).second,"duplicate vector neighbor");
          auto expected=std::find_if(brute.begin(),brute.end(),[&](auto &entry){return entry.second==row[0].integer;});
          require(expected!=brute.end(),"vector index returned deleted/unknown row");
          double distance=row[1].type==MURMUR_REAL?row[1].real:(double)row[1].integer;
          double tolerance=1e-5*std::max(1.0,std::abs(expected->first));
          require(std::abs(distance-expected->first)<=tolerance,"vector distance differs from independent arithmetic");
          require(expected->first<=brute[6].first+tolerance,"vector top-k missed a closer row");
        }
        for(size_t i=0;i<7;++i) if(brute[i].first<brute[6].first-1e-5*std::max(1.0,std::abs(brute[6].first)))
          require(ids.count(brute[i].second),"vector neighbor strictly inside top-k omitted");
      }
    }
  }
  void run() {
    verify(0);
    auto changed=doc(900); auto initial=indexes(a());
    StaleProbe probe{insert(900,changed),"SELECT rowid FROM temp.\""+initial.fts+"\" WHERE \""+initial.fts+"\" MATCH 'alpha'"};
    check(murmur_managed_transaction(a(),MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,stale_probe,&probe),"pending index query must be denied before commit");
    require(probe.query_rc==SQLITE_AUTH,"unpublished incremental result was readable"); docs[900]=changed; verify(0);
    for(int step=0;step<80;++step) {
      int id=(int)(random()%700); auto *writer=step%2?a():other;
      if(step%4==0) { sql(writer,{"DELETE FROM "+table+" WHERE id="+std::to_string(id)}); docs.erase(id); }
      else { auto d=doc(id); sql(writer,{insert(id,d)}); docs[id]=std::move(d); }
      if(step%10==9) verify(0);
    }
    auto original=indexes(a());
    require(murmur_managed_migrate(a(),"ALTER TABLE docs ADD COLUMN partial TEXT; CREATE TABLE malformed(")!=SQLITE_OK,"invalid migration succeeded"); verify(0);
    murmur_rename_t mappings[]={{"docs",nullptr,"body","content"},{"docs",nullptr,"embedding","point"},{"docs","papers",nullptr,nullptr}};
    check(murmur_managed_migrate_mapped(a(),"ALTER TABLE docs RENAME COLUMN body TO content; ALTER TABLE docs RENAME COLUMN embedding TO point; ALTER TABLE docs RENAME TO papers",mappings,3),"mapped search rename");
    table="papers"; body="content"; point="point"; verify(0);
    require(indexes(a()).fts==original.fts && indexes(a()).vector==original.vector,"rename changed stable search identities");
    int bad=docs.begin()->first;
    sql(other,{"UPDATE papers SET point=x'00' WHERE id="+std::to_string(bad)});
    require(murmur_managed_refresh_indexes(a())!=SQLITE_OK,"invalid vector accepted");
    require(run_bad_query(original.vector)!=SQLITE_OK,"failed vector index remained queryable");
    sql(a(),{"UPDATE papers SET point="+blob(docs.at(bad).point)+" WHERE id="+std::to_string(bad)}); verify(0);
    for(int metric:{1,2,0}) { check(murmur_managed_set_search(other,table.c_str(),point.c_str(),0,3,metric),"change vector distance"); verify(metric); }
    murmur_managed_close(other); other=nullptr; cluster.reopen(0);
    check(murmur_managed_open(cluster.nodes[0].path.c_str(),cluster.key.data(),&other),"reopen second search handle"); verify(0);
  }
  int run_bad_query(const std::string &index) { return managed_test::run(a(),{"SELECT rowid FROM temp.\""+index+"\" WHERE point MATCH '[1,0,0]' AND k=1"}); }
};
}
int main() {
  try { Fixture fixture; fixture.run(); puts("MANAGED-SEARCH-ORACLE-OK (fresh FTS, brute-force L2/cosine/L1, handles, migrations, repair, reopen)"); }
  catch(const std::exception &e) { fprintf(stderr,"MANAGED-SEARCH-ORACLE-FAIL %s\n",e.what()); return 1; }
  catch(const ManagedError &e) { fprintf(stderr,"MANAGED-SEARCH-ORACLE-FAIL native rc=%d\n",e.code); return 1; }
}
