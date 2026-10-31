#ifndef MURMUR_VEC0_H
#define MURMUR_VEC0_H

#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Registers murmur's brute-force vec0 virtual table module
 * (deps/vec0/vec0.c, vendored from the reference implementation).
 * Per-connection, like any sqlite3_create_module call. */
int murmurRegisterVec0(sqlite3 *db);

#ifdef __cplusplus
}
#endif

#endif
