#include "managed_value.h"
#include <cassert>
#include <cmath>
#include <cfloat>
#include <fstream>
#include <map>
#include <cstdio>
static ManagedValue integer(int64_t n) { ManagedValue v; v.type=MURMUR_INTEGER; v.integer=n; return v; }
static ManagedValue real(double n) { ManagedValue v; v.type=MURMUR_REAL; v.real=n; return v; }
int main(int argc,char **argv) {
  std::ifstream in(argc>1?argv[1]:"deps/murmur/testdata/value_vectors.txt"); assert(in.good());
  std::map<std::string,std::string> gold; std::string name,hex;
  while(in>>name>>hex) { std::string raw; for(size_t i=0;i<hex.size();i+=2) raw+=(char)std::stoul(hex.substr(i,2),nullptr,16); gold[name]=raw; }
  assert(gold.size()==19);
  ManagedValue text; text.type=MURMUR_TEXT; text.data="<>&\n\xe2\x80\xa8\xe2\x80\xa9\xff";
  ManagedValue blob; blob.type=MURMUR_BLOB; blob.data=std::string("\0\xff",2);
  std::vector<ManagedValue> values{{},integer(INT64_MIN),integer(INT64_MAX),real(DBL_TRUE_MIN),real(-0.0),text,blob};
  for(size_t i=0;i<values.size();++i) {
    auto bytes=managed_encode_value(values[i]); assert(bytes==gold["value"+std::to_string(i)]);
    assert(managed_encode_value(managed_decode_value(bytes))==bytes);
  }
  assert(managed_encode_values(values)==gold["values"]);
  assert(managed_encode_values(managed_decode_values(gold["values"]))==gold["values"]);
  double floats[]={1e5,1e6,1e-4,1e-5,1e20,1e21,DBL_TRUE_MIN,DBL_MAX,-0.0,1.2345678901234567};
  for(size_t i=0;i<10;++i) {
    auto actual="["+managed_json_scalar(real(floats[i]))+"]";
    auto expected=gold["float"+std::to_string(i)];
    if(actual!=expected) fprintf(stderr,"float%zu native=%s Go=%s\n",i,actual.c_str(),expected.c_str());
    assert(actual==expected);
  }
  auto json="{"+managed_json_quote("<\n\xe2\x80\xa8")+":"+managed_json_scalar(text)+",\"a\":null,\"z\":1.5}";
  assert(json==gold["json"]);
  assert(managed_compare(integer(9007199254740993),real(9007199254740992.0))>0);
  assert(managed_compare(integer(INT64_MAX),real(9223372036854775808.0))<0);
  assert(managed_compare(integer(INT64_MIN),real(-9223372036854775808.0))==0);
  assert(managed_compare(integer(0),real(-0.1))>0);
  puts("MANAGED-VALUE-OK (19 Go vectors and exact numeric comparison)");
}
