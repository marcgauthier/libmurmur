#include "scheduler.h"
#include "sqlite3.h"
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstdio>
static int cancelled(void *) { return 1; }
int main() {
  murmur_scheduler_t *s=nullptr;
  auto cfg=murmur_scheduler_defaults(); cfg.maintenance_every=2;
  assert(murmur_scheduler_create(&cfg,&s)==SQLITE_OK);
  assert(murmur_scheduler_acquire(s,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr)==SQLITE_OK);
  murmur_scheduler_t *independent=nullptr;
  assert(murmur_scheduler_create(nullptr,&independent)==SQLITE_OK);
  assert(murmur_scheduler_acquire(independent,MURMUR_WRITER_LOCAL,0,nullptr,nullptr)==SQLITE_OK);
  assert(murmur_scheduler_release(independent)==SQLITE_OK);
  murmur_scheduler_destroy(independent);
  assert(murmur_scheduler_acquire(s,MURMUR_WRITER_LOCAL,0,nullptr,nullptr)==SQLITE_MISUSE);
  std::thread timeout([&] {
    assert(murmur_scheduler_acquire(s,MURMUR_WRITER_REMOTE,0,nullptr,nullptr)==SQLITE_BUSY);
    assert(murmur_scheduler_acquire(s,MURMUR_WRITER_REMOTE,-1,cancelled,nullptr)==SQLITE_ABORT);
    assert(murmur_scheduler_release(s)==SQLITE_MISUSE);
  }); timeout.join();
  std::atomic<int> first{-1};
  auto worker=[&](murmur_writer_class_t cls) {
    assert(murmur_scheduler_acquire(s,cls,-1,nullptr,nullptr)==SQLITE_OK);
    int expected=-1; first.compare_exchange_strong(expected,cls);
    assert(murmur_scheduler_release(s)==SQLITE_OK);
  };
  std::thread remote(worker,MURMUR_WRITER_REMOTE),maintenance(worker,MURMUR_WRITER_MAINTENANCE);
  murmur_scheduler_stats_t st;
  for (;;) {
    murmur_scheduler_snapshot(s,&st);
    if (st.classes[1].waiters && st.classes[2].waiters) break;
    std::this_thread::yield();
  }
  assert(murmur_scheduler_release(s)==SQLITE_OK);
  remote.join(); maintenance.join();
  assert(first==MURMUR_WRITER_MAINTENANCE);
  murmur_scheduler_snapshot(s,&st);
  assert(st.classes[0].acquisitions==1 && st.classes[1].cancels==2 && !st.active);
  assert(murmur_scheduler_acquire(s,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr)==SQLITE_OK);
  std::thread shutdown([&] {
    assert(murmur_scheduler_acquire(s,MURMUR_WRITER_REMOTE,-1,nullptr,nullptr)==SQLITE_ABORT);
  });
  murmur_scheduler_close(s); shutdown.join();
  assert(murmur_scheduler_release(s)==SQLITE_OK);
  murmur_scheduler_destroy(s); puts("SCHEDULER-OK");
}
