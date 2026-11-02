#ifndef MURMUR_BRIDGE_WORKER_INTERNAL_H
#define MURMUR_BRIDGE_WORKER_INTERNAL_H
#include "sqlite3.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

/* Shared lifecycle for native ferry workers. SQL admission belongs to each
 * operation, never to a caller starting or joining the polling thread. */
class BridgeWorker {
  std::mutex lifecycle_, wake_lock_;
  std::condition_variable wake_;
  std::thread thread_;
  bool stopping_ = false;

public:
  ~BridgeWorker() { stop(); }
  template <typename Fn> int manual(Fn fn) {
    std::lock_guard<std::mutex> guard(lifecycle_);
    if (thread_.joinable())
      return SQLITE_MISUSE;
    {
      std::lock_guard<std::mutex> wake(wake_lock_);
      stopping_ = false;
    }
    return fn();
  }
  template <typename Fn> int start(unsigned interval, Fn fn) {
    if (interval < 10 || interval > 60000)
      return SQLITE_MISUSE;
    std::lock_guard<std::mutex> guard(lifecycle_);
    if (thread_.joinable())
      return SQLITE_MISUSE;
    try {
      {
        std::lock_guard<std::mutex> wake(wake_lock_);
        stopping_ = false;
      }
      thread_ = std::thread([this, interval, fn] {
        for (;;) {
          {
            std::lock_guard<std::mutex> wake(wake_lock_);
            if (stopping_)
              return;
          }
          fn();
          std::unique_lock<std::mutex> wake(wake_lock_);
          if (wake_.wait_for(wake, std::chrono::milliseconds(interval),
                             [this] { return stopping_; }))
            return;
        }
      });
      return SQLITE_OK;
    } catch (...) {
      return SQLITE_ERROR;
    }
  }
  bool stopping() {
    std::lock_guard<std::mutex> wake(wake_lock_);
    return stopping_;
  }
  void stop() {
    std::lock_guard<std::mutex> guard(lifecycle_);
    {
      std::lock_guard<std::mutex> wake(wake_lock_);
      stopping_ = true;
    }
    wake_.notify_all();
    if (thread_.joinable())
      thread_.join();
  }
};
#endif
