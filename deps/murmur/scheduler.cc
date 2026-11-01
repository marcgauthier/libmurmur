#include "scheduler.h"
#include "sqlite3.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <new>
#include <thread>
#include <limits>

using Clock = std::chrono::steady_clock;
/* Only the accounting clock is replaceable in the dedicated test binary.
 * Admission deadlines and condition-variable waits always use real time. */
static Clock::time_point service_now() {
#ifdef MURMUR_SCHEDULER_TEST_CLOCK
  extern uint64_t murmur_scheduler_test_clock_ns();
  return Clock::time_point(std::chrono::nanoseconds(murmur_scheduler_test_clock_ns()));
#else
  return Clock::now();
#endif
}
struct Waiter { int cls; Clock::time_point since; };
struct murmur_scheduler {
  std::mutex mu;
  std::condition_variable cv;
  murmur_scheduler_stats_t stats{};
  std::deque<Waiter *> queues[3];
  std::thread::id owner;
  Clock::time_point started;
  int active_class = 0;
  bool contested = false;
  uint64_t grants = 0;
};
static uint64_t ns(Clock::duration d) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
}
static void add(uint64_t &a, uint64_t b) {
  a = b > UINT64_MAX-a ? UINT64_MAX : a+b;
}
static int pick(murmur_scheduler *s) {
  if (!s->queues[2].empty() &&
      (s->grants >= s->stats.config.maintenance_every-1 ||
       (s->queues[0].empty() && s->queues[1].empty()))) return 2;
  if (s->queues[0].empty()) return s->queues[1].empty() ? -1 : 1;
  if (s->queues[1].empty()) return 0;
  return s->stats.debt_ns <= 0 ? 0 : 1;
}
extern "C" {
murmur_scheduler_config_t murmur_scheduler_defaults(void) {
  return {90, 1000000000, 100};
}
int murmur_scheduler_create(const murmur_scheduler_config_t *c, murmur_scheduler_t **out) {
  if (!out) return SQLITE_MISUSE;
  *out = nullptr;
  auto config = c ? *c : murmur_scheduler_defaults();
  if (!config.local_share || config.local_share >= 100 ||
      !config.max_debt_ns || config.max_debt_ns > INT64_MAX ||
      !config.maintenance_every) return SQLITE_MISUSE;
  auto *s = new(std::nothrow) murmur_scheduler;
  if (!s) return SQLITE_NOMEM;
  s->stats.config = config;
  *out = s;
  return SQLITE_OK;
}
int murmur_scheduler_acquire(murmur_scheduler_t *s, murmur_writer_class_t cls,
                             int64_t timeout, murmur_cancel_fn cancel, void *ctx) {
  if (!s || cls < 0 || cls > 2) return SQLITE_MISUSE;
  auto now = Clock::now();
  /* Clamp timeouts before converting milliseconds to the clock duration. */
  auto deadline = Clock::time_point::max();
  if (timeout >= 0) {
    auto max_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-now).count();
    if (timeout < max_ms) deadline = now + std::chrono::milliseconds(timeout);
  }
  Waiter w{int(cls), now};
  std::unique_lock<std::mutex> lock(s->mu);
  if (s->stats.active && s->owner == std::this_thread::get_id()) return SQLITE_MISUSE;
  if (s->stats.closed) return SQLITE_ABORT;
  try { s->queues[cls].push_back(&w); } catch (...) { return SQLITE_NOMEM; }
  auto &st = s->stats.classes[cls];
  ++st.waiters;
  int rc = SQLITE_OK;
  for (;;) {
    lock.unlock();
    int cancelled = cancel && cancel(ctx);
    lock.lock();
    if (cancelled || s->stats.closed) { rc = SQLITE_ABORT; break; }
    if (!s->stats.active && pick(s) == cls && s->queues[cls].front() == &w) {
      s->stats.active = 1;
      s->active_class = cls;
      s->owner = std::this_thread::get_id();
      s->started = service_now();
      s->contested = !s->queues[0].empty() && !s->queues[1].empty();
      add(st.acquisitions, 1);
      if (cls == 2) s->grants = 0; else add(s->grants, 1);
      break;
    }
    now = Clock::now();
    if (now >= deadline) { rc = SQLITE_BUSY; break; }
    s->cv.wait_until(lock, std::min(deadline, now+std::chrono::milliseconds(10)));
  }
  auto &q = s->queues[cls];
  q.erase(std::find(q.begin(), q.end(), &w));
  --st.waiters;
  add(st.wait_ns, ns(Clock::now()-w.since));
  if (rc) add(st.cancels, 1);
  s->cv.notify_all();
  return rc;
}
int murmur_scheduler_release(murmur_scheduler_t *s) {
  if (!s) return SQLITE_MISUSE;
  std::lock_guard<std::mutex> lock(s->mu);
  if (!s->stats.active || s->owner != std::this_thread::get_id()) return SQLITE_MISUSE;
  uint64_t elapsed = ns(service_now()-s->started);
  add(s->stats.classes[s->active_class].service_ns, elapsed);
  if (s->contested && s->active_class < 2) {
    /* Normalized service debt: local/local_share - remote/remote_share. */
    unsigned share = s->active_class == 0 ? s->stats.config.local_share : 100-s->stats.config.local_share;
    __int128 debt = s->stats.debt_ns;
    __int128 delta = (__int128)elapsed*100/share;
    debt += s->active_class == 0 ? delta : -delta;
    __int128 bound = s->stats.config.max_debt_ns;
    s->stats.debt_ns = (int64_t)std::max(-bound, std::min(bound, debt));
  }
  s->stats.active = 0;
  s->owner = {};
  s->cv.notify_all();
  return SQLITE_OK;
}
void murmur_scheduler_snapshot(murmur_scheduler_t *s, murmur_scheduler_stats_t *out) {
  if (!s || !out) return;
  std::lock_guard<std::mutex> lock(s->mu);
  *out = s->stats;
}
void murmur_scheduler_close(murmur_scheduler_t *s) {
  if (!s) return;
  std::lock_guard<std::mutex> lock(s->mu);
  s->stats.closed = 1;
  s->cv.notify_all();
}
void murmur_scheduler_destroy(murmur_scheduler_t *s) { delete s; }
}
