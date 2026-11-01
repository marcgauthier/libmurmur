#include "managed_value.h"
#include "postcard.h"
#include <charconv>
#include <cmath>
#include <cstring>
#include <climits>
#include <memory>

void managed_check(int rc) { if(rc!=SQLITE_OK) throw ManagedError{rc}; }
ManagedValue ManagedValue::from(const murmur_value_t &v) {
  if(v.type<MURMUR_NULL || v.type>MURMUR_BLOB || (!v.data && v.bytes) || v.bytes>(64u<<20)) throw ManagedError{SQLITE_MISUSE};
  ManagedValue out; out.type=v.type; out.integer=v.integer; out.real=v.real;
  if(v.type==MURMUR_TEXT || v.type==MURMUR_BLOB) out.data.assign(v.data?(const char *)v.data:"",v.bytes);
  if(v.type==MURMUR_REAL && std::isnan(v.real)) throw ManagedError{SQLITE_MISMATCH};
  return out;
}
ManagedValue ManagedValue::argument(sqlite3_value *v) {
  ManagedValue out;
  if((sqlite3_value_type(v)==SQLITE_TEXT || sqlite3_value_type(v)==SQLITE_BLOB) && sqlite3_value_bytes(v)>(64<<20)) throw ManagedError{SQLITE_TOOBIG};
  switch(sqlite3_value_type(v)) {
    case SQLITE_INTEGER: out.type=MURMUR_INTEGER; out.integer=sqlite3_value_int64(v); break;
    case SQLITE_FLOAT: out.type=MURMUR_REAL; out.real=sqlite3_value_double(v); break;
    case SQLITE_TEXT: out.type=MURMUR_TEXT; out.data.assign((const char *)sqlite3_value_text(v),sqlite3_value_bytes(v)); break;
    case SQLITE_BLOB: out.type=MURMUR_BLOB; if(sqlite3_value_bytes(v)) out.data.assign((const char *)sqlite3_value_blob(v),sqlite3_value_bytes(v)); break;
  }
  return out;
}
ManagedValue ManagedValue::column(sqlite3_stmt *st,int col) { return argument(sqlite3_column_value(st,col)); }
int ManagedValue::bind(sqlite3_stmt *st,int i) const {
  if(data.size()>(64u<<20)) return SQLITE_TOOBIG;
  switch(type) {
    case MURMUR_NULL: return sqlite3_bind_null(st,i);
    case MURMUR_INTEGER: return sqlite3_bind_int64(st,i,integer);
    case MURMUR_REAL: return std::isnan(real)?SQLITE_MISMATCH:sqlite3_bind_double(st,i,real);
    case MURMUR_TEXT: return sqlite3_bind_text64(st,i,data.data(),data.size(),SQLITE_TRANSIENT,SQLITE_UTF8);
    case MURMUR_BLOB: return sqlite3_bind_blob64(st,i,data.data(),data.size(),SQLITE_TRANSIENT);
  }
  return SQLITE_MISUSE;
}
namespace {
void put(std::string &out,uint64_t n) {
  do { out+=(char)((n&127)|(n>=128?128:0)); n>>=7; } while(n);
}
void encode(std::string &out,const ManagedValue &v) {
  put(out,v.type);
  switch(v.type) {
    case MURMUR_INTEGER: put(out,((uint64_t)v.integer<<1) ^ (uint64_t)-(v.integer<0)); break;
    case MURMUR_REAL: {
      uint64_t bits; memcpy(&bits,&v.real,8);
      for(unsigned i=0;i<8;++i) out+=(char)(bits>>(8*i));
      break;
    }
    case MURMUR_TEXT: case MURMUR_BLOB: put(out,v.data.size()); out+=v.data; break;
    default: break;
  }
}
ManagedValue decode(murmur_pc_dec_t &d) {
  ManagedValue v; auto type=murmur_pc_g_disc(&d);
  if(type>4) throw ManagedError{SQLITE_CORRUPT};
  v.type=(murmur_value_type_t)type;
  switch(v.type) {
    case MURMUR_INTEGER: v.integer=murmur_pc_g_i64(&d); break;
    case MURMUR_REAL: v.real=murmur_pc_g_f64(&d); if(std::isnan(v.real)) throw ManagedError{SQLITE_MISMATCH}; break;
    case MURMUR_TEXT: case MURMUR_BLOB: {
      size_t n=0; auto *p=murmur_pc_g_bytes(&d,&n);
      if(!d.err) v.data.assign((const char *)p,n);
      break;
    }
    default: break;
  }
  if(d.err) throw ManagedError{SQLITE_CORRUPT};
  return v;
}
int integer_real(int64_t i,double f) {
  if(std::isnan(f)) throw ManagedError{SQLITE_MISMATCH};
  if(f>=9223372036854775808.0) return -1;
  if(f< -9223372036854775808.0) return 1;
  auto whole=(int64_t)f;
  if(i!=whole) return i<whole?-1:1;
  auto fraction=f-std::trunc(f);
  return fraction>0?-1:(fraction<0?1:0);
}
}
std::string managed_encode_value(const ManagedValue &v) { std::string out; encode(out,v); return out; }
std::string managed_encode_values(const std::vector<ManagedValue> &values) {
  std::string out; put(out,values.size()); for(auto &v:values) encode(out,v); return out;
}
ManagedValue managed_decode_value(const std::string &bytes) {
  murmur_pc_dec_t d; murmur_pc_dec_init(&d,(const uint8_t *)bytes.data(),bytes.size());
  auto v=decode(d); if(murmur_pc_end(&d)) throw ManagedError{SQLITE_CORRUPT}; return v;
}
std::vector<ManagedValue> managed_decode_values(const std::string &bytes) {
  if(bytes.size()>(64u<<20)) throw ManagedError{SQLITE_TOOBIG};
  murmur_pc_dec_t d; murmur_pc_dec_init(&d,(const uint8_t *)bytes.data(),bytes.size());
  auto n=murmur_pc_g_len(&d);
  if(d.err || n>d.len-d.off) throw ManagedError{SQLITE_CORRUPT};
  std::vector<ManagedValue> out;
  for(size_t i=0;i<n;++i) out.push_back(decode(d));
  if(murmur_pc_end(&d)) throw ManagedError{SQLITE_CORRUPT};
  return out;
}
int managed_compare(const ManagedValue &a,const ManagedValue &b) {
  auto rank=[](const ManagedValue &v) { return v.type==MURMUR_REAL?1:(v.type>=MURMUR_TEXT?(int)v.type-1:(int)v.type); };
  int ra=rank(a),rb=rank(b); if(ra!=rb) return ra<rb?-1:1;
  if(a.type==MURMUR_NULL) return 0;
  if(a.type==MURMUR_INTEGER && b.type==MURMUR_REAL) return integer_real(a.integer,b.real);
  if(a.type==MURMUR_REAL && b.type==MURMUR_INTEGER) return -integer_real(b.integer,a.real);
  if(a.type==MURMUR_REAL) {
    if(std::isnan(a.real)||std::isnan(b.real)) throw ManagedError{SQLITE_MISMATCH};
    return a.real<b.real?-1:(a.real>b.real?1:0);
  }
  if(a.type==MURMUR_INTEGER) return a.integer<b.integer?-1:(a.integer>b.integer?1:0);
  return a.data.compare(b.data);
}
std::string managed_json_quote(const std::string &s) {
  std::string out="\""; static const char hex[]="0123456789abcdef";
  for(size_t i=0;i<s.size();) {
    unsigned char c=s[i++];
    if(c=='"'||c=='\\') { out+='\\'; out+=(char)c; }
    else if(c=='\n') out+="\\n";
    else if(c=='\r') out+="\\r";
    else if(c=='\t') out+="\\t";
    else if(c=='\b') out+="\\b";
    else if(c=='\f') out+="\\f";
    else if(c<32 || c=='<' || c=='>' || c=='&') { out+="\\u00"; out+=hex[c>>4]; out+=hex[c&15]; }
    else if(c<128) out+=(char)c;
    else {
      size_t n=c>=0xc2&&c<=0xdf?2:(c>=0xe0&&c<=0xef?3:(c>=0xf0&&c<=0xf4?4:0));
      bool valid=n && n-1<=s.size()-i;
      for(size_t k=0;valid && k<n-1;++k) valid=((unsigned char)s[i+k]&0xc0)==0x80;
      if(valid && n==3) valid=!(c==0xe0&&(unsigned char)s[i]<0xa0) && !(c==0xed&&(unsigned char)s[i]>=0xa0);
      if(valid && n==4) valid=!(c==0xf0&&(unsigned char)s[i]<0x90) && !(c==0xf4&&(unsigned char)s[i]>=0x90);
      if(!valid) out+="\\ufffd";
      else if(n==3 && c==0xe2 && (unsigned char)s[i]==0x80 && ((unsigned char)s[i+1]==0xa8 || (unsigned char)s[i+1]==0xa9)) {
        out+=(unsigned char)s[i+1]==0xa8?"\\u2028":"\\u2029"; i+=2;
      } else { out+=(char)c; out.append(s,i,n-1); i+=n-1; }
    }
  }
  return out+'"';
}
std::string managed_json_scalar(const ManagedValue &v) {
  if(v.type==MURMUR_NULL) return "null";
  if(v.type==MURMUR_INTEGER) return std::to_string(v.integer);
  if(v.type==MURMUR_TEXT) return managed_json_quote(v.data);
  if(v.type!=MURMUR_REAL || !std::isfinite(v.real)) throw ManagedError{SQLITE_MISMATCH};
  char out[64]; auto result=std::to_chars(out,out+sizeof(out),v.real,std::chars_format::general);
  if(result.ec!=std::errc{}) throw ManagedError{SQLITE_MISMATCH};
  return std::string(out,result.ptr);
}
std::vector<std::pair<std::string,ManagedValue>> managed_json_parse(sqlite3 *db,const ManagedValue &v,bool object) {
  std::vector<std::pair<std::string,ManagedValue>> out;
  if(v.type==MURMUR_NULL) return out;
  if(v.type!=MURMUR_TEXT) throw ManagedError{SQLITE_MISMATCH};
  sqlite3_stmt *raw=nullptr;
  managed_check(sqlite3_prepare_v2(db,"SELECT json_valid(?1),CASE WHEN json_valid(?1) THEN json_type(?1) END",-1,&raw,nullptr));
  std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> st(raw,sqlite3_finalize);
  managed_check(v.bind(raw,1));
  if(sqlite3_step(raw)!=SQLITE_ROW || !sqlite3_column_int(raw,0)) throw ManagedError{SQLITE_MISMATCH};
  auto type=(const char *)sqlite3_column_text(raw,1);
  if(!strcmp(type,"null")) return out;
  if(strcmp(type,object?"object":"array")) throw ManagedError{SQLITE_MISMATCH};
  st.reset(); raw=nullptr;
  managed_check(sqlite3_prepare_v2(db,"SELECT key,atom,type FROM json_each(?1) ORDER BY id",-1,&raw,nullptr)); st.reset(raw);
  managed_check(v.bind(raw,1)); int rc;
  while((rc=sqlite3_step(raw))==SQLITE_ROW) {
    auto *type=(const char *)sqlite3_column_text(raw,2);
    if(!strcmp(type,"array")||!strcmp(type,"object")) throw ManagedError{SQLITE_MISMATCH};
    auto value=ManagedValue::column(raw,1);
    if(value.type==MURMUR_REAL && !std::isfinite(value.real)) throw ManagedError{SQLITE_MISMATCH};
    auto name=ManagedValue::column(raw,0);
    out.emplace_back(object?name.data:std::string(),std::move(value));
  }
  if(rc!=SQLITE_DONE) throw ManagedError{rc};
  return out;
}
