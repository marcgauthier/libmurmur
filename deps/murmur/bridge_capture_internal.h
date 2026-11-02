#ifndef MURMUR_BRIDGE_CAPTURE_INTERNAL_H
#define MURMUR_BRIDGE_CAPTURE_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
typedef struct sqlite3 sqlite3;
int bridge_capture_enqueue(sqlite3 *, const void *, size_t);
void bridge_capture_pause(sqlite3 *, bool);
void bridge_capture_invalidate(sqlite3 *);
bool bridge_capture_accepts(sqlite3 *, const uint8_t source[16]);
bool bridge_capture_exports(sqlite3 *, const uint8_t source[16],
                            const char *stream);
struct BridgeCapturePause {
  sqlite3 *db;
  explicit BridgeCapturePause(sqlite3 *d) : db(d) {
    bridge_capture_pause(db, true);
  }
  ~BridgeCapturePause() { bridge_capture_pause(db, false); }
};
#endif
