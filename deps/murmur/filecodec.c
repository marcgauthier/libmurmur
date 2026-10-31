/* murmur filecodec - see filecodec.h. */
#include "filecodec.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

void murmur_file_frame_encode(murmur_pc_enc_t *e,
                              const murmur_file_frame_t *f) {
  murmur_pc_disc(e, (uint32_t)f->kind);
  switch (f->kind) {
  case MURMUR_FILE_REQUEST:
    murmur_pc_raw(e, f->database.b, 16);
    murmur_pc_raw(e, f->digest, 32);
    murmur_pc_u64(e, f->generation);
    murmur_pc_u64(e, f->offset);
    break;
  case MURMUR_FILE_HEADER:
    murmur_pc_u64(e, f->bytes);
    murmur_pc_raw(e, f->identity, 32);
    break;
  case MURMUR_FILE_CHUNK_FRAME:
    murmur_pc_bytes(e, f->data, f->data_len);
    break;
  case MURMUR_FILE_DONE:
  case MURMUR_FILE_MISSING:
    break;
  }
}

murmur_pc_status_t murmur_file_frame_decode(const uint8_t *b, size_t n,
                                            murmur_file_frame_t *f) {
  memset(f, 0, sizeof(*f));
  murmur_pc_dec_t d;
  murmur_pc_dec_init(&d, b, n);
  switch (murmur_pc_g_disc(&d)) {
  case 0:
    f->kind = MURMUR_FILE_REQUEST;
    break;
  case 1:
    f->kind = MURMUR_FILE_HEADER;
    break;
  case 2:
    f->kind = MURMUR_FILE_CHUNK_FRAME;
    break;
  case 3:
    f->kind = MURMUR_FILE_DONE;
    break;
  case 4:
    f->kind = MURMUR_FILE_MISSING;
    break;
  default:
    murmur_pc_fail(&d, MURMUR_PC_VALUE);
    return murmur_pc_end(&d);
  }
  const uint8_t *r = NULL;
  switch (f->kind) {
  case MURMUR_FILE_REQUEST:
    r = murmur_pc_g_raw(&d, 16);
    if (r) {
      memcpy(f->database.b, r, 16);
    }
    r = murmur_pc_g_raw(&d, 32);
    if (r) {
      memcpy(f->digest, r, 32);
    }
    f->generation = murmur_pc_g_u64(&d);
    f->offset = murmur_pc_g_u64(&d);
    break;
  case MURMUR_FILE_HEADER:
    f->bytes = murmur_pc_g_u64(&d);
    r = murmur_pc_g_raw(&d, 32);
    if (r) {
      memcpy(f->identity, r, 32);
    }
    break;
  case MURMUR_FILE_CHUNK_FRAME:
    f->data = murmur_pc_g_bytes(&d, &f->data_len);
    break;
  case MURMUR_FILE_DONE:
  case MURMUR_FILE_MISSING:
    break;
  }
  return murmur_pc_end(&d);
}

void murmur_file_meta_encode(murmur_pc_enc_t *e,
                             const murmur_file_meta_t *m) {
  murmur_pc_str(e, m->name, m->name_len);
  murmur_pc_raw(e, m->digest, 32);
  murmur_pc_u64(e, m->bytes);
  murmur_pc_u64(e, m->generation);
  murmur_pc_u64(e, m->millis);
  murmur_pc_raw(e, m->node.b, 16);
  murmur_pc_bool(e, m->deleted);
}

murmur_pc_status_t murmur_file_meta_decode(const uint8_t *b, size_t n,
                                           murmur_file_meta_t *m) {
  memset(m, 0, sizeof(*m));
  murmur_pc_dec_t d;
  murmur_pc_dec_init(&d, b, n);
  m->name = murmur_pc_g_str(&d, &m->name_len);
  const uint8_t *r = murmur_pc_g_raw(&d, 32);
  if (r) {
    memcpy(m->digest, r, 32);
  }
  m->bytes = murmur_pc_g_u64(&d);
  m->generation = murmur_pc_g_u64(&d);
  m->millis = murmur_pc_g_u64(&d);
  r = murmur_pc_g_raw(&d, 16);
  if (r) {
    memcpy(m->node.b, r, 16);
  }
  m->deleted = murmur_pc_g_bool(&d);
  return murmur_pc_end(&d);
}

void murmur_file_avail_free(murmur_file_avail_t *a) {
  if (!a) {
    return;
  }
  free(a->remote);
  memset(a, 0, sizeof(*a));
}

void murmur_file_avail_encode(murmur_pc_enc_t *e,
                              const murmur_file_avail_t *a) {
  murmur_pc_disc(e, (uint32_t)a->kind);
  if (a->kind == MURMUR_FILE_REMOTE) {
    murmur_pc_len(e, a->n_remote);
    for (size_t i = 0; i < a->n_remote; i++) {
      murmur_pc_raw(e, a->remote[i].b, 16);
    }
  }
}

murmur_pc_status_t murmur_file_avail_decode(const uint8_t *b, size_t n,
                                            murmur_file_avail_t *a) {
  memset(a, 0, sizeof(*a));
  murmur_pc_dec_t d;
  murmur_pc_dec_init(&d, b, n);
  switch (murmur_pc_g_disc(&d)) {
  case 0:
    a->kind = MURMUR_FILE_LOCAL;
    break;
  case 1: {
    a->kind = MURMUR_FILE_REMOTE;
    size_t m = murmur_pc_g_len(&d);
    if (d.err != MURMUR_PC_OK) {
      break;
    }
    if (m > 0) {
      a->remote = (murmur_node_t *)malloc(m * sizeof(*a->remote));
      if (!a->remote) {
        /* Allocation failure reads as truncated input. */
        murmur_pc_fail(&d, MURMUR_PC_TRUNCATED);
        break;
      }
    }
    for (size_t i = 0; i < m; i++) {
      const uint8_t *r = murmur_pc_g_raw(&d, 16);
      if (!r) {
        break;
      }
      memcpy(a->remote[a->n_remote++].b, r, 16);
    }
    break;
  }
  case 2:
    a->kind = MURMUR_FILE_UNAVAILABLE;
    break;
  default:
    murmur_pc_fail(&d, MURMUR_PC_VALUE);
    break;
  }
  murmur_pc_status_t st = murmur_pc_end(&d);
  if (st != MURMUR_PC_OK) {
    murmur_file_avail_free(a);
  }
  return st;
}

void murmur_file_keyrot_encode(murmur_pc_enc_t *e,
                               const murmur_file_keyrot_t *s) {
  murmur_pc_u64(e, s->current_generation);
  murmur_pc_u64(e, s->old_generation_objects);
  murmur_pc_u64(e, s->old_generation_metadata_missing_locally);
  murmur_pc_u64(e, s->staged_transfers);
  murmur_pc_bool(e, s->previous_key_unused_locally);
}

murmur_pc_status_t murmur_file_keyrot_decode(const uint8_t *b, size_t n,
                                             murmur_file_keyrot_t *s) {
  memset(s, 0, sizeof(*s));
  murmur_pc_dec_t d;
  murmur_pc_dec_init(&d, b, n);
  s->current_generation = murmur_pc_g_u64(&d);
  s->old_generation_objects = murmur_pc_g_u64(&d);
  s->old_generation_metadata_missing_locally = murmur_pc_g_u64(&d);
  s->staged_transfers = murmur_pc_g_u64(&d);
  s->previous_key_unused_locally = murmur_pc_g_bool(&d);
  return murmur_pc_end(&d);
}

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

static void set_detail(char **out, const char *s) {
  if (!out) {
    return;
  }
  *out = s ? strdup(s) : NULL;
}

static const char *io_error(murmur_stream_io_t *io) {
  const char *t = NULL;
  if (io && io->error_text) {
    t = io->error_text(io->ctx);
  }
  return t ? t : "stream error";
}

murmur_sync_status_t murmur_file_write_frame(murmur_stream_io_t *io,
                                             const murmur_file_frame_t *f,
                                             char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  murmur_pc_enc_t e;
  murmur_pc_enc_init(&e);
  murmur_file_frame_encode(&e, f);
  if (e.len > MURMUR_FILE_FRAME_BYTES) {
    murmur_pc_enc_finish(&e);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  uint8_t hdr[12];
  memset(hdr, 0, sizeof(hdr));
  hdr[0] = 'F';
  hdr[1] = 'F';
  hdr[3] = 1;
  hdr[8] = (uint8_t)(e.len >> 24);
  hdr[9] = (uint8_t)(e.len >> 16);
  hdr[10] = (uint8_t)(e.len >> 8);
  hdr[11] = (uint8_t)e.len;
  murmur_sync_status_t st = MURMUR_SYNC_OK;
  if (io->write(io->ctx, hdr, 12) != 0 ||
      (e.len > 0 && io->write(io->ctx, e.b, e.len) != 0)) {
    set_detail(detail_out, io_error(io));
    st = MURMUR_SYNC_PROTOCOL;
  }
  murmur_pc_enc_finish(&e);
  set_sqlrc(sqlrc, SQLITE_OK);
  return st;
}

murmur_sync_status_t murmur_file_read_frame(murmur_stream_io_t *io,
                                            murmur_file_frame_t *f,
                                            uint8_t **owned_out,
                                            char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  if (owned_out) {
    *owned_out = NULL;
  }
  memset(f, 0, sizeof(*f));
  uint8_t hdr[12];
  if (io->read_full(io->ctx, hdr, 12) != 0) {
    set_detail(detail_out, io_error(io));
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint32_t n = ((uint32_t)hdr[8] << 24) | ((uint32_t)hdr[9] << 16) |
               ((uint32_t)hdr[10] << 8) | hdr[11];
  uint16_t ver = ((uint16_t)hdr[2] << 8) | hdr[3];
  if (hdr[0] != 'F' || hdr[1] != 'F' || ver != 1 ||
      n > MURMUR_FILE_FRAME_BYTES) {
    set_detail(detail_out, "file frame");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint8_t *b = (uint8_t *)malloc(n ? n : 1);
  if (!b) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  if (n > 0 && io->read_full(io->ctx, b, n) != 0) {
    free(b);
    set_detail(detail_out, io_error(io));
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_pc_status_t ps = murmur_file_frame_decode(b, n, f);
  if (ps != MURMUR_PC_OK) {
    free(b);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_INVALID;
  }
  if (!owned_out) {
    /* The frame borrows its buffer; an owner is required. */
    free(b);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  *owned_out = b;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}
