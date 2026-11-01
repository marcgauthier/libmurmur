#ifndef MURMUR_MANAGED_VALUE_H
#define MURMUR_MANAGED_VALUE_H
#include "managed.h"
#include "sqlite3.h"
#include <string>
#include <vector>
/* Owned SQL values and the Go model's canonical postcard Value/Vec<Value>. */
struct ManagedValue {
  murmur_value_type_t type=MURMUR_NULL;
  int64_t integer=0;
  double real=0;
  std::string data;
  static ManagedValue from(const murmur_value_t &);
  static ManagedValue column(sqlite3_stmt *,int);
  static ManagedValue argument(sqlite3_value *);
  int bind(sqlite3_stmt *,int) const;
};
struct ManagedError { int code; };
void managed_check(int);
std::string managed_encode_value(const ManagedValue &);
std::string managed_encode_values(const std::vector<ManagedValue> &);
ManagedValue managed_decode_value(const std::string &);
std::vector<ManagedValue> managed_decode_values(const std::string &);
int managed_compare(const ManagedValue &,const ManagedValue &);
std::string managed_json_quote(const std::string &);
std::string managed_json_scalar(const ManagedValue &);
std::vector<std::pair<std::string,ManagedValue>> managed_json_parse(sqlite3 *,const ManagedValue &,bool object);
#endif
