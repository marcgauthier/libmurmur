#ifndef MURMUR_MANAGED_CODEC_H
#define MURMUR_MANAGED_CODEC_H
#include "managed_value.h"
#include "postcard.h"
#include "msgcodec.h"
#include <cstring>
/* Bounded postcard primitives shared by signed schema/state/snapshot records. */
struct ManagedEncoder {
  std::string bytes;
  void raw(const void *p,size_t n) {
    if(n>(64u<<20)-bytes.size()) throw ManagedError{SQLITE_TOOBIG};
    if(n) bytes.append((const char *)p,n);
  }
  void number(uint64_t n) {
    uint8_t buf[10]; size_t count=0;
    do { buf[count++]=(uint8_t)((n&127)|(n>=128?128:0)); n>>=7; } while(n);
    raw(buf,count);
  }
  void blob(const std::string &s) { number(s.size()); raw(s.data(),s.size()); }
};
struct ManagedDecoder {
  murmur_pc_dec_t d{};
  ManagedDecoder(const void *p,size_t n) {
    if(n>(64u<<20)) throw ManagedError{SQLITE_TOOBIG};
    murmur_pc_dec_init(&d,(const uint8_t *)p,n);
  }
  void valid() { if(d.err) throw ManagedError{SQLITE_CORRUPT}; }
  uint64_t number() { auto n=murmur_pc_g_u64(&d); valid(); return n; }
  size_t count(size_t cap) { auto n=number(); if(n>cap || n>d.len-d.off) throw ManagedError{SQLITE_CORRUPT}; return (size_t)n; }
  std::string raw(size_t n) { auto *p=murmur_pc_g_raw(&d,n); valid(); return std::string((const char *)p,n); }
  std::string blob() { size_t n=0; auto *p=murmur_pc_g_bytes(&d,&n); valid(); return std::string((const char *)p,n); }
  std::string text() {
    auto s=blob(); if(s.find('\0')!=std::string::npos || !murmur_utf8_valid((const uint8_t *)s.data(),s.size())) throw ManagedError{SQLITE_CORRUPT}; return s;
  }
  void end() { if(murmur_pc_end(&d)) throw ManagedError{SQLITE_CORRUPT}; }
};
#endif
