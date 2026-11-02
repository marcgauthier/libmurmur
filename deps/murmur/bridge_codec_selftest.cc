#include "bridge_codec.h"
#include "origin.h"
#include "sqlite3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge codec failure line %d: %s\n", __LINE__, #x);     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
int main() {
  uint8_t signer[32] = {1}, receiver[32] = {2}, recipient[32], pub[32],
          other[32] = {3};
  other[16] = 1; /* Low private-key bits are clamped by X25519. */
  CHECK(murmur_bridge_recipient_public(receiver, recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(signer, pub) == SQLITE_OK);
  murmur_bridge_header_t h{};
  h.database[0] = 1;
  h.node[0] = 2;
  h.transaction[0] = 3;
  h.sequence = 1;
  strcpy(h.stream, "overwatch");
  const uint8_t payload[] = {0, 1, 2, 255, 0, 42};
  murmur_bridge_bytes_t b{}, b2{}, out{};
  murmur_bridge_header_t got{};
  const size_t mb = MURMUR_BRIDGE_MAX_BUNDLE, mp = MURMUR_BRIDGE_MAX_PAYLOAD;
  CHECK(murmur_bridge_seal(&h, signer, recipient, payload, sizeof(payload), mb,
                           mp, &b) == SQLITE_OK);
  CHECK(murmur_bridge_seal(&h, signer, recipient, payload, sizeof(payload), mb,
                           mp, &b2) == SQLITE_OK);
  CHECK(b.len == b2.len && memcmp(b.data, b2.data, b.len));
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, pub, receiver,
                             mb, mp, &got, &out) == SQLITE_OK);
  CHECK(out.len == sizeof(payload) && !memcmp(out.data, payload, out.len));
  CHECK(got.sequence == 1 && !strcmp(got.stream, h.stream) &&
        !memcmp(got.transaction, h.transaction, 16));
  murmur_bridge_bytes_free(&out);
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, pub, other,
                             mb, mp, &got, &out) == SQLITE_AUTH);
  CHECK(!out.data && !out.len && !got.sequence);
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, "other", pub, receiver,
                             mb, mp, &got, &out) == SQLITE_AUTH);
  CHECK(murmur_bridge_unseal(b.data, b.len, other, h.stream, pub, receiver, mb,
                             mp, &got, &out) == SQLITE_AUTH);
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, other,
                             receiver, mb, mp, &got, &out) == SQLITE_AUTH);
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, pub, receiver,
                             mb, 1, &got, &out) == SQLITE_TOOBIG);
  for (size_t i = 0; i < b.len; ++i) {
    b.data[i] ^= 1;
    CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, pub,
                               receiver, mb, mp, &got, &out) != SQLITE_OK);
    CHECK(!out.data && !out.len && !got.sequence);
    b.data[i] ^= 1;
  }
  for (size_t n = 0; n < b.len; ++n) {
    CHECK(murmur_bridge_unseal(b.data, n, h.database, h.stream, pub, receiver,
                               mb, mp, &got, &out) != SQLITE_OK);
    CHECK(!out.data && !out.len);
  }
  std::vector<uint8_t> extra(b.data, b.data + b.len);
  extra.push_back(0);
  CHECK(murmur_bridge_unseal(extra.data(), extra.size(), h.database, h.stream,
                             pub, receiver, mb, mp, &got, &out) != SQLITE_OK);
  murmur_bridge_bytes_free(&b);
  murmur_bridge_bytes_free(&b2);
  CHECK(murmur_bridge_seal(&h, signer, recipient, nullptr, 0, mb, mp, &b) ==
        SQLITE_OK);
  CHECK(murmur_bridge_unseal(b.data, b.len, h.database, h.stream, pub, receiver,
                             mb, mp, &got, &out) == SQLITE_OK &&
        out.len == 0);
  murmur_bridge_bytes_free(&out);
  murmur_bridge_bytes_free(&b);
  h.sequence = 0;
  CHECK(murmur_bridge_seal(&h, signer, recipient, payload, sizeof(payload), mb,
                           mp, &b) == SQLITE_MISUSE &&
        !b.data);
  h.sequence = 1;
  strcpy(h.stream, "../bad");
  CHECK(murmur_bridge_seal(&h, signer, recipient, payload, sizeof(payload), mb,
                           mp, &b) == SQLITE_MISUSE);
  strcpy(h.stream, "overwatch");
  CHECK(murmur_bridge_seal(&h, signer, recipient, payload, sizeof(payload), mb,
                           1, &b) == SQLITE_TOOBIG);
  uint8_t invalid[32]{};
  CHECK(murmur_bridge_seal(&h, signer, invalid, payload, sizeof(payload), mb,
                           mp, &b) != SQLITE_OK);
  puts("BRIDGE-CODEC-OK");
}
