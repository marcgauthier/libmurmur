#ifndef MURMUR_BRIDGE_ARTIFACT_INTERNAL_H
#define MURMUR_BRIDGE_ARTIFACT_INTERNAL_H
#include <stddef.h>
/* Publish bounded raw ciphertext using its immutable SHA-256 name. The
 * operator-owned directory must exist. No SQL or queue acknowledgement. */
int bridge_artifact_publish(const char *directory, const void *, size_t);
#endif
