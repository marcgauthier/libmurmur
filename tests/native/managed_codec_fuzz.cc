// Reusable input target: the smoke runner supplies seeded mutations; an
// external libFuzzer build may call LLVMFuzzerTestOneInput directly.
#include "managed_codec.h"
#include "managed_policy_state.h"
#include "managed_schema_internal.h"
#include "managed_replica.h"
#include <cstdlib>
#include <memory>
#include <stdexcept>

static void invariant(bool ok) { if(!ok) throw std::runtime_error("codec round-trip/join invariant failed"); }
bool managed_codec_fuzz_one(const uint8_t *input,size_t bytes) {
  if(!bytes || bytes>(1u<<20)) return false;
  unsigned kind=input[0]%8; ++input; --bytes; std::string body((const char *)input,bytes);
  try {
    if(kind==0) {
      murmur_origin_envelope_t e{};
      if(murmur_origin_envelope_decode(input,bytes,&e)!=SQLITE_OK) return false;
      uint8_t wire[MURMUR_ORIGIN_ENVELOPE_BYTES]; managed_check(murmur_origin_envelope_encode(&e,wire,sizeof(wire)));
      invariant(body==std::string((const char *)wire,sizeof(wire)));
    } else if(kind==1) {
      auto schema=managed_schema_decode(body); invariant(managed_schema_encode(schema)==body);
    } else if(kind==2) {
      auto row=managed_row_decode(body); invariant(managed_row_encode(row)==body);
      invariant(managed_row_encode(managed_row_join(row,row))==body);
    } else if(kind==3) {
      murmur_causal_t *raw=nullptr; int rc=murmur_causal_decode(input,bytes,&raw); if(rc!=SQLITE_OK) return false;
      std::unique_ptr<murmur_causal_t,decltype(&murmur_causal_free)> owned(raw,murmur_causal_free);
      auto canonical=managed_causal_bytes(raw); managed_check(murmur_causal_join(raw,raw)); invariant(managed_causal_bytes(raw)==canonical);
      murmur_causal_t *again=nullptr; managed_check(murmur_causal_decode(canonical.data(),canonical.size(),&again));
      std::unique_ptr<murmur_causal_t,decltype(&murmur_causal_free)> copy(again,murmur_causal_free);
      invariant(managed_causal_bytes(again)==canonical);
    } else if(kind==4) {
      auto value=managed_decode_value(body); auto canonical=managed_encode_value(value);
      invariant(managed_encode_value(managed_decode_value(canonical))==canonical);
    } else if(kind==5) {
      auto values=managed_decode_values(body); auto canonical=managed_encode_values(values);
      invariant(managed_encode_values(managed_decode_values(canonical))==canonical);
    } else {
      std::string cells=body;
      if(kind==6) {
        if(bytes<4 || body.compare(0,4,"MMT2")) return false;
        murmur_origin_record_t record{}; record.payload=(uint8_t *)input; record.bytes=bytes;
        auto batch=managed_replica_decode(record); ManagedEncoder e; e.raw("MMT2",4); e.blob(batch.cells); e.number(batch.rows.size());
        for(auto &row:batch.rows) e.blob(managed_row_encode(row));
        invariant(e.bytes==body); cells=batch.cells;
      }
      if(cells.size()<12) return false;
      uint32_t count=0; for(unsigned i=0;i<4;++i) count|=(uint32_t)(uint8_t)cells[8+i]<<(i*8);
      if(count>65536 || count>(cells.size()-12)/49) return false;
      std::vector<murmur_cell_t> decoded(count); size_t actual=0;
      if(murmur_cells_decode((const uint8_t *)cells.data(),cells.size(),decoded.data(),decoded.size(),&actual)!=MURMUR_OK) return false;
      invariant(actual==count);
      std::string encoded("CRSB\1\0\0\0\0\0\0\0",12);
      for(auto &cell:decoded) {
        std::string buffer(cell.table_len+cell.pk_len+cell.cid_len+cell.site_len+cell.val_blob_len+128,'\0');
        auto n=murmur_cell_encode(&cell,(uint8_t *)buffer.data(),buffer.size()); invariant(n!=0); encoded.append(buffer.data(),n);
      }
      for(unsigned i=0;i<4;++i) encoded[8+i]=(char)(count>>(8*i));
      invariant(encoded==cells);
    }
    return true;
  } catch(const ManagedError &) { return false; }
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *input,size_t bytes) {
  managed_codec_fuzz_one(input,bytes); return 0;
}
