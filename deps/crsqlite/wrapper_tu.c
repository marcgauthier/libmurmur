/* cr-sqlite C wrapper, single translation unit.
 *
 * The three wrapper sources share extension state
 * (SQLITE_EXTENSION_INIT1 in crsqlite.c, referenced from the other two
 * via SQLITE_EXTENSION_INIT3). They must be compiled as one TU so all
 * three see the same instance; separate objects segfault at init.
 */
#include "src/crsqlite.c"
#include "src/changes-vtab.c"
#include "src/ext-data.c"
