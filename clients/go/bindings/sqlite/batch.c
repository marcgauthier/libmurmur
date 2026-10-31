/* Fused statement helpers: collapse N cgo crossings (reset, binds,
 * steps, column decodes) into one C call. Adapted from the
 * sqlite-fastgo fast.c technique set; cgo transitions dominate the
 * statement profile, so fusion is the biggest available win on
 * statement-heavy paths (seeds, scans, point lookups).
 *
 * All helpers take Go-owned buffers that the caller keeps alive for
 * the synchronous call; TEXT/BLOB binds use SQLITE_TRANSIENT so C
 * never retains Go pointers.
 */
#include "../../../../deps/sqlite/sqlite3.h"

#include <string.h>

static const char murmur_empty[1] = {0};

/* Step a DML statement and reset it in one call. Returns the step code. */
int murmur_step_once(sqlite3_stmt *s) {
	int rc = sqlite3_step(s);
	sqlite3_reset(s);
	return rc;
}

/* Argument kinds for murmur_exec_batch. Must match Go ArgType. */
#define MA_INT 0
#define MA_FLOAT 1
#define MA_TEXT 2
#define MA_BLOB 3
#define MA_NULL 4

/* One bound value. Layout must match Go Arg: 16 bytes, no pointers.
 * v holds int64/float64 bits or the arena offset of a text/blob payload. */
typedef struct {
	unsigned long long v;
	int n;
	unsigned char t;
} murmur_arg;
typedef char murmur_arg_size_check[sizeof(murmur_arg) == 16 ? 1 : -1];
typedef char murmur_arg_off_check[__builtin_offsetof(murmur_arg, t) == 12 ? 1 : -1];

/* Batch execution status, returned by value: row is nrows on success
 * or the failing row index otherwise; rc is SQLITE_DONE or the error. */
typedef struct {
	int row;
	int rc;
} murmur_exec_out;

/* Bind one row's args (parameters base+1..base+nparams) from the
 * payload arena. Returns SQLITE_OK, or the failing bind code with
 * the statement reset. */
static int murmur_bind_row(sqlite3_stmt *s, const murmur_arg *args, int nparams,
                           const char *arena, int base) {
	for (int p = 0; p < nparams; p++) {
		int rc;
		switch (args[p].t) {
		case MA_INT:
			rc = sqlite3_bind_int64(s, base + p + 1, (long long)args[p].v);
			break;
		case MA_FLOAT: {
			double f;
			memcpy(&f, &args[p].v, 8);
			rc = sqlite3_bind_double(s, base + p + 1, f);
			break;
		}
		case MA_TEXT:
			rc = sqlite3_bind_text(s, base + p + 1, arena + args[p].v, args[p].n,
			                       SQLITE_TRANSIENT);
			break;
		case MA_BLOB:
			rc = sqlite3_bind_blob(s, base + p + 1, arena + args[p].v, args[p].n,
			                       SQLITE_TRANSIENT);
			break;
		default: /* MA_NULL */
			rc = sqlite3_bind_null(s, base + p + 1);
			break;
		}
		if (rc != SQLITE_OK) {
			sqlite3_reset(s);
			return rc;
		}
	}
	return SQLITE_OK;
}

/* Execute nrows DML rows in one call: args holds nrows*nparams
 * entries row-major, text/blob bytes live in arena (copied TRANSIENT
 * per bind). Returns DONE + nrows on full success, else the failing
 * row and code. */
murmur_exec_out murmur_exec_batch(sqlite3_stmt *s, const murmur_arg *args, int nparams,
                                 int nrows, const char *arena) {
	murmur_exec_out out = {0, SQLITE_DONE};
	if (!arena) {
		arena = murmur_empty;
	}
	for (int i = 0; i < nrows; i++) {
		int rc = murmur_bind_row(s, args + i * nparams, nparams, arena, 0);
		if (rc != SQLITE_OK) {
			out.row = i;
			out.rc = rc;
			return out;
		}
		rc = sqlite3_step(s);
		sqlite3_reset(s);
		if (rc != SQLITE_DONE) {
			out.row = i;
			out.rc = rc;
			return out;
		}
	}
	out.row = nrows;
	out.rc = SQLITE_DONE;
	return out;
}

/* Column types for murmur_step_rows/fetch. Must match Go ColType. */
#define MC_INT 0
#define MC_FLOAT 1
#define MC_TEXT 2
#define MC_BLOB 3
#define MC_ANY 4

/* Internal sentinel: the row did not fit the arena (no SQLite code is -1). */
#define MURMUR_TRUNCATED -1

/* One decoded batch cell. Layout must match Go Cell: 16 bytes, no
 * pointers. v holds int64/float64 bits or the arena offset of a
 * text/blob payload; n its length; t the storage class. */
typedef struct {
	unsigned long long v;
	int n;
	unsigned char t;
} murmur_cell;
typedef char murmur_cell_size_check[sizeof(murmur_cell) == 16 ? 1 : -1];
typedef char murmur_cell_off_check[__builtin_offsetof(murmur_cell, t) == 12 ? 1 : -1];

/* Decode the current row into 16-byte cells, copying payloads to arena
 * at *used (advanced past the copied bytes). Returns 1 if the row fit,
 * 0 if truncated (*used unchanged, the row stays current). */
static int murmur_decode_row(sqlite3_stmt *s, const unsigned char *types, murmur_cell *dst,
                             int ncol, char *arena, int alen, int *used) {
	int u = *used;
	for (int c = 0; c < ncol; c++) {
		switch (types[c]) {
		case MC_INT:
			dst[c].v = (unsigned long long)sqlite3_column_int64(s, c);
			dst[c].n = 0;
			dst[c].t = SQLITE_INTEGER;
			break;
		case MC_FLOAT: {
			double f = sqlite3_column_double(s, c);
			memcpy(&dst[c].v, &f, 8);
			dst[c].n = 0;
			dst[c].t = SQLITE_FLOAT;
			break;
		}
		case MC_TEXT: {
			int t = sqlite3_column_type(s, c);
			dst[c].t = (unsigned char)t;
			if (t == SQLITE_NULL) {
				dst[c].v = 0;
				dst[c].n = 0;
			} else {
				int nb = sqlite3_column_bytes(s, c);
				if (u + nb > alen) {
					return 0;
				}
				const char *p = (const char *)sqlite3_column_text(s, c);
				dst[c].v = (unsigned long long)u;
				dst[c].n = nb;
				if (nb > 0) {
					memcpy(arena + u, p, (unsigned)nb);
					u += nb;
				}
			}
			break;
		}
		default: { /* MC_BLOB */
			int t = sqlite3_column_type(s, c);
			dst[c].t = (unsigned char)t;
			if (t == SQLITE_NULL) {
				dst[c].v = 0;
				dst[c].n = 0;
			} else {
				int nb = sqlite3_column_bytes(s, c);
				if (u + nb > alen) {
					return 0;
				}
				const char *p = (const char *)sqlite3_column_blob(s, c);
				dst[c].v = (unsigned long long)u;
				dst[c].n = nb;
				if (nb > 0) {
					memcpy(arena + u, p, (unsigned)nb);
					u += nb;
				}
			}
			break;
		}
		case MC_ANY: {
			int t = sqlite3_column_type(s, c);
			dst[c].t = (unsigned char)t;
			if (t == SQLITE_INTEGER) {
				dst[c].v = (unsigned long long)sqlite3_column_int64(s, c);
				dst[c].n = 0;
			} else if (t == SQLITE_FLOAT) {
				double f = sqlite3_column_double(s, c);
				memcpy(&dst[c].v, &f, 8);
				dst[c].n = 0;
			} else if (t == SQLITE_NULL) {
				dst[c].v = 0;
				dst[c].n = 0;
			} else {
				int nb = sqlite3_column_bytes(s, c);
				if (u + nb > alen) {
					return 0;
				}
				const char *p = (const char *)(t == SQLITE_TEXT ?
					(const char *)sqlite3_column_text(s, c) :
					(const char *)sqlite3_column_blob(s, c));
				dst[c].v = (unsigned long long)u;
				dst[c].n = nb;
				if (nb > 0) {
					memcpy(arena + u, p, (unsigned)nb);
					u += nb;
				}
			}
			break;
		}
		}
	}
	*used = u;
	return 1;
}

/* Batch status, returned by value. n: rows delivered (0..maxrows).
 * rc: SQLITE_ROW if more rows may follow (call again), SQLITE_DONE
 * if the cursor is exhausted, or an error code (already delivered
 * rows remain valid). truncated: the next row did not fit and is
 * left current on the cursor. */
typedef struct {
	int n;
	int rc;
	int truncated;
} murmur_rows_out;

/* Fetch up to maxrows rows. types/ncol describe one row; cols has room
 * for maxrows*ncol cells; arena (alen bytes) receives TEXT/BLOB
 * payload copies. skip_step continues after a previous truncation by
 * decoding the current row first without stepping. */
murmur_rows_out murmur_step_rows(sqlite3_stmt *s, int skip_step, const unsigned char *types,
                                murmur_cell *cols, int ncol, char *arena, int alen,
                                int maxrows) {
	murmur_rows_out out = {0, SQLITE_ROW, 0};
	int used = 0;
	if (!skip_step) {
		out.rc = sqlite3_step(s);
		if (out.rc != SQLITE_ROW) {
			return out;
		}
	}
	for (;;) {
		if (!murmur_decode_row(s, types, cols + out.n * ncol, ncol, arena, alen, &used)) {
			out.truncated = 1;
			out.rc = SQLITE_ROW;
			return out;
		}
		out.n++;
		if (out.n == maxrows) {
			out.rc = SQLITE_ROW;
			return out;
		}
		out.rc = sqlite3_step(s);
		if (out.rc != SQLITE_ROW) {
			return out;
		}
	}
}

/* One-shot int-key point lookup: reset, bind key to parameter 1,
 * step, decode. Returns SQLITE_ROW, SQLITE_DONE (no row),
 * MURMUR_TRUNCATED, or an error code. */
int murmur_fetch_i1(sqlite3_stmt *s, long long key, const unsigned char *types,
                    murmur_cell *cols, int ncol, char *arena, int alen) {
	sqlite3_reset(s);
	int rc = sqlite3_bind_int64(s, 1, key);
	if (rc != SQLITE_OK) {
		return rc;
	}
	rc = sqlite3_step(s);
	if (rc == SQLITE_ROW) {
		int used = 0;
		if (!murmur_decode_row(s, types, cols, ncol, arena, alen, &used)) {
			return MURMUR_TRUNCATED;
		}
		/* Payloads are arena copies: reset now to release read
		 * locks before the caller's next write. */
		sqlite3_reset(s);
	}
	return rc;
}

/* Batched int-key point lookups: reset+bind+step+decode per key in a
 * single crossing. Cells land at cols+k*ncol; payloads share the
 * arena (offsets accumulate); hits[k] reports row found. Returns
 * SQLITE_OK, MURMUR_TRUNCATED (keys before the truncated one are
 * valid, hits set through the last completed key), or the first
 * bind/step error code. */
int murmur_fetch_many(sqlite3_stmt *s, const long long *keys, int nkeys,
                      const unsigned char *types, murmur_cell *cols, int ncol,
                      char *arena, int alen, unsigned char *hits) {
	int used = 0;
	for (int k = 0; k < nkeys; k++) {
		sqlite3_reset(s);
		int rc = sqlite3_bind_int64(s, 1, keys[k]);
		if (rc != SQLITE_OK) {
			return rc;
		}
		rc = sqlite3_step(s);
		if (rc == SQLITE_DONE) {
			hits[k] = 0;
			continue;
		}
		if (rc != SQLITE_ROW) {
			return rc;
		}
		if (!murmur_decode_row(s, types, cols + k * ncol, ncol, arena, alen, &used)) {
			return MURMUR_TRUNCATED;
		}
		hits[k] = 1;
		/* Payloads are arena copies: reset now to release read
		 * locks before the caller's next write. */
		sqlite3_reset(s);
	}
	return SQLITE_OK;
}

/* One-shot text-key point lookup. NULL/empty key binds empty (never NULL). */
int murmur_fetch_t1(sqlite3_stmt *s, const char *key, int keylen, const unsigned char *types,
                    murmur_cell *cols, int ncol, char *arena, int alen) {
	sqlite3_reset(s);
	if (!key) {
		key = murmur_empty;
	}
	int rc = sqlite3_bind_text(s, 1, key, keylen, SQLITE_TRANSIENT);
	if (rc != SQLITE_OK) {
		return rc;
	}
	rc = sqlite3_step(s);
	if (rc == SQLITE_ROW) {
		int used = 0;
		if (!murmur_decode_row(s, types, cols, ncol, arena, alen, &used)) {
			return MURMUR_TRUNCATED;
		}
		sqlite3_reset(s);
	}
	return rc;
}
