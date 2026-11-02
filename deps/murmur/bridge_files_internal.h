#ifndef MURMUR_BRIDGE_FILES_INTERNAL_H
#define MURMUR_BRIDGE_FILES_INTERNAL_H
#include "bridge_store.h"
#include "files.h"
#include <functional>
struct BridgeFileExporter;
int bridge_files_init(sqlite3 *);
BridgeFileExporter *bridge_files_exporter_new(sqlite3 *, murmur_files_t *,
                                              const uint8_t source[16],
                                              const char *stream);
void bridge_files_exporter_free(BridgeFileExporter *);
int bridge_files_export_step(BridgeFileExporter *, size_t budget,
                             const std::function<bool()> &stop,
                             uint64_t *queued);
int bridge_files_stage(sqlite3 *, const murmur_bridge_header_t *, const void *,
                       size_t, uint64_t capacity);
int bridge_files_finish_one(sqlite3 *, murmur_files_t *,
                            const uint8_t source[16], const char *stream,
                            const std::function<bool()> &stop,
                            uint64_t *completed);
int bridge_rows_import(sqlite3 *, const murmur_bridge_header_t *, const void *,
                       size_t);
#endif
