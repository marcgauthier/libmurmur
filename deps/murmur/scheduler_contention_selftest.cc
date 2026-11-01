#include "scheduler.h"
#include "sqlite3.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

static std::atomic<uint64_t> accounting_time{0};
uint64_t murmur_scheduler_test_clock_ns() { return accounting_time.load(); }
static void require(bool ok,const char *message) { if(!ok) throw std::runtime_error(message); }
template<class Fn> static void until(Fn fn) {
  auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(5);
  while(!fn()) { require(std::chrono::steady_clock::now()<limit,"waiter setup timed out"); std::this_thread::yield(); }
}
struct Scheduler {
  murmur_scheduler_t *p=nullptr;
  explicit Scheduler(murmur_scheduler_config_t cfg) { require(murmur_scheduler_create(&cfg,&p)==SQLITE_OK,"create scheduler"); }
  ~Scheduler() { murmur_scheduler_destroy(p); }
  murmur_scheduler_stats_t stats() { murmur_scheduler_stats_t out; murmur_scheduler_snapshot(p,&out); return out; }
};
static void contention(unsigned local_share) {
  auto config=murmur_scheduler_defaults(); config.local_share=local_share; config.maintenance_every=7; config.max_debt_ns=1000000;
  Scheduler scheduler(config); require(murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr)==SQLITE_OK,"initial owner");
  struct Grant { int cls; uint64_t cost; };
  std::vector<Grant> history; std::vector<std::thread> workers; std::exception_ptr failure; std::mutex failure_mutex;
  for(int cls=0;cls<3;++cls) for(int worker=0;worker<2;++worker) workers.emplace_back([&,cls] {
    bool owned=false;
    try {
      for(;;) {
        int rc=murmur_scheduler_acquire(scheduler.p,(murmur_writer_class_t)cls,-1,nullptr,nullptr);
        if(rc==SQLITE_ABORT) break;
        require(rc==SQLITE_OK,"contention acquire"); owned=true;
        require(scheduler.stats().debt_ns<= (int64_t)config.max_debt_ns && scheduler.stats().debt_ns>=-(int64_t)config.max_debt_ns,"debt exceeds bound");
        uint64_t cost=(uint64_t)(history.size()%5+1)*(cls==0?1000:(cls==1?7000:3000)); history.push_back({cls,cost});
        if(history.size()<240) {
          /* Keep all classes backlogged before every release. This proves
           * service fairness without depending on OS thread wake ordering. */
          until([&] { auto s=scheduler.stats(); return s.classes[0].waiters && s.classes[1].waiters && s.classes[2].waiters; });
        }
        accounting_time.fetch_add(cost);
        if(history.size()==240) murmur_scheduler_close(scheduler.p);
        require(murmur_scheduler_release(scheduler.p)==SQLITE_OK,"contention release"); owned=false;
      }
    } catch(...) {
      { std::lock_guard<std::mutex> lock(failure_mutex); if(!failure) failure=std::current_exception(); }
      murmur_scheduler_close(scheduler.p); if(owned) murmur_scheduler_release(scheduler.p);
    }
  });
  until([&] { auto s=scheduler.stats(); return s.classes[0].waiters==2 && s.classes[1].waiters==2 && s.classes[2].waiters==2; });
  require(murmur_scheduler_release(scheduler.p)==SQLITE_OK,"release initial owner");
  for(auto &worker:workers) worker.join();
  if(failure) std::rethrow_exception(failure);
  auto final=scheduler.stats(); require(history.size()==240 && final.closed && !final.active,"shutdown state");
  uint64_t service[3]{},grants[3]{},since_maintenance=0; int64_t debt=0;
  for(auto grant:history) {
    if(grant.cls==2) { require(since_maintenance<=6,"maintenance starved"); since_maintenance=0; }
    else {
      require(grant.cls==(debt<=0?0:1),"class selection violates service debt"); ++since_maintenance;
      unsigned share=grant.cls==0?local_share:100-local_share;
      auto delta=(int64_t)(grant.cost*100/share); debt+=grant.cls==0?delta:-delta;
      debt=std::max(-(int64_t)config.max_debt_ns,std::min((int64_t)config.max_debt_ns,debt));
    }
    service[grant.cls]+=grant.cost; ++grants[grant.cls];
  }
  require(debt==final.debt_ns,"reported debt differs from independent service calculation");
  for(int cls=0;cls<3;++cls) {
    require(final.classes[cls].service_ns==service[cls],"service accounting differs from injected clock");
    require(final.classes[cls].acquisitions==grants[cls]+(cls==2?1:0),"acquisition accounting differs");
    require(!final.classes[cls].waiters && grants[cls]>0,"class failed to progress or leaked waiters");
  }
  int64_t imbalance=(int64_t)(service[0]*(100-local_share))-(int64_t)(service[1]*local_share);
  /* Finite non-preemptible transactions permit one service quantum of
   * overshoot. Integer debt normalization adds less than 100 per grant. */
  require(imbalance<=5000*(int64_t)(100-local_share)+24000 && imbalance>=-35000*(int64_t)local_share-24000,"service share exceeds transaction-quantum bound");
  printf("SCHEDULER-CONTENTION share=%u local_ns=%llu remote_ns=%llu maintenance=%llu\n",local_share,(unsigned long long)service[0],(unsigned long long)service[1],(unsigned long long)grants[2]);
}
static void fifo() {
  Scheduler scheduler(murmur_scheduler_defaults()); require(murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr)==SQLITE_OK,"FIFO owner");
  std::vector<int> order; std::vector<std::thread> threads; std::atomic<bool> failed{false};
  for(int i=0;i<12;++i) {
    threads.emplace_back([&,i] {
      if(murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_REMOTE,-1,nullptr,nullptr)!=SQLITE_OK) { failed=true; return; }
      order.push_back(i); accounting_time.fetch_add(1);
      if(murmur_scheduler_release(scheduler.p)!=SQLITE_OK) failed=true;
    });
    until([&] { return scheduler.stats().classes[1].waiters==(uint64_t)i+1; });
  }
  require(murmur_scheduler_release(scheduler.p)==SQLITE_OK,"FIFO release owner"); for(auto &thread:threads) thread.join();
  require(!failed && order.size()==12,"FIFO worker error"); for(int i=0;i<12;++i) require(order[i]==i,"class FIFO order changed");
}
struct Cancel { Scheduler *scheduler; std::atomic<bool> flag{false}; };
static int cancel(void *ctx) {
  auto *c=(Cancel *)ctx; c->scheduler->stats(); /* Callback must not hold scheduler mutex. */
  return c->flag.load();
}
static void cancellation() {
  Scheduler scheduler(murmur_scheduler_defaults()); require(murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr)==SQLITE_OK,"cancel owner");
  Cancel state{&scheduler}; std::atomic<int> result{-1};
  std::thread waiter([&] { result=murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_REMOTE,-1,cancel,&state); });
  until([&] { return scheduler.stats().classes[1].waiters==1; }); state.flag=true; waiter.join();
  require(result==SQLITE_ABORT && scheduler.stats().classes[1].waiters==0,"queued cancellation leaked waiter");
  murmur_scheduler_close(scheduler.p); require(murmur_scheduler_release(scheduler.p)==SQLITE_OK,"close canceled active owner");
  require(murmur_scheduler_acquire(scheduler.p,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr)==SQLITE_ABORT,"closed scheduler admitted writer");
}
int main() {
  try { for(unsigned share:{50u,75u,90u}) contention(share); fifo(); cancellation(); puts("SCHEDULER-CONTENTION-OK"); }
  catch(const std::exception &e) { fprintf(stderr,"SCHEDULER-CONTENTION-FAIL %s\n",e.what()); return 1; }
}
