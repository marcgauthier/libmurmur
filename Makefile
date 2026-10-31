# libmurmur - unified Murmur library.
#
# Produces libmurmur.a from every native component: SQLite, cr-sqlite
# (C wrapper + Rust bundle), the page codec (AES-256-GCM via AWS-LC +
# AEGIS-256 + Zstandard), the
# keyring, Argon2, the C++ VFS/storage managers, and the
# picoquic+picotls+mbedTLS QUIC transport. Third-party archives (RocksDB,
# the cr-sqlite Rust bundle) are repacked in, so clients link exactly one
# file. Per-component flags below replicate the cgo flags each source set
# was previously built with; do not "simplify" them without re-running
# the full gates.
#
#   make [-jN] [MURMUR_VFS_STATS=1]
#
# The Go client in clients/go links this archive: build it before any go
# command (or use the go-* targets, which build it first). Toggling
# MURMUR_VFS_STATS needs a clean rebuild: make clean && make
# MURMUR_VFS_STATS=1.

CC      ?= cc
CXX     ?= c++
AR      ?= ar
BUILD   := build
LIB     := libmurmur.a

OPT      := -O2
PIC      := -fPIC
DEPFLAGS := -MMD -MP

SQLITE_DEFS := -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1
PQ_DEFS     := -DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS \
               -DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD
ZSTD_DEFS   := -DZSTD_DISABLE_ASM=1

INC_SQLITE := -Ideps/sqlite
INC_CRSQL  := -Ideps/sqlite -Ideps/crsqlite/include
INC_ZSTD   := -Ideps/zstd
INC_AEGIS  := -Ideps/aegis/src/include
INC_AWSLC  := -Ideps/aws-lc/include
INC_MBED   := -Ideps/mbedtls/include
INC_PTLS   := -Ideps/picotls/include
INC_PICO   := -Ideps/picoquic/picoquic -Ideps/picoquic/picoquic_mbedtls
# Project C/C++ (codec, keyring, argon2, murmur managers): same superset
# the nvfs cgo package used, so headers resolve as before.
INC_NATIVE := -Ideps/murmur -Ideps/codec -Ideps/keyring \
              -Ideps/argon2 -Ideps/argon2/blake2 \
              -Ideps/sqlite -Ideps/zstd -Ideps/vec0 \
              -Ideps/aegis/src/include -Ideps/rocksdb/include \
              $(INC_PICO) $(INC_PTLS) $(INC_MBED)

ifdef MURMUR_VFS_STATS
MURMUR_DEFS := -DMURMUR_VFS_STATS=1
endif
# mbedTLS threading: concurrent QUIC handshakes race in PSA globals
# without it (ASan-proven PSA-slot UAF in three-way-heal). transport.cc
# includes mbedtls headers, so murmur TUs need the same defines.
MURMUR_DEFS += -DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD

SRC_SQLITE  := deps/sqlite/sqlite3.c
# Single TU: the wrapper sources share extension statics (see wrapper_tu.c).
SRC_CRSQL   := deps/crsqlite/wrapper_tu.c
SRC_CODEC   := deps/codec/codec.cc deps/codec/aesgcm.cc
SRC_KEYRING := deps/keyring/sha256.c deps/keyring/hkdf.c \
               deps/keyring/crc32c.c deps/keyring/keyring.cc
SRC_ARGON2  := deps/argon2/argon2.c deps/argon2/core.c \
               deps/argon2/ref.c deps/argon2/encoding.c \
               deps/argon2/thread.c deps/argon2/blake2/blake2b.c
SRC_ZSTD    := $(wildcard deps/zstd/*.c)
SRC_AEGIS   := $(shell find deps/aegis/src -name '*.c')
SRC_MBED    := $(wildcard deps/mbedtls/library/*.c)
SRC_PTLS    := $(wildcard deps/picotls/lib/*.c)
# picoquic core minus the fusion TU (minicrypto-free build), plus the two
# mbedTLS backend files.
SRC_PICO    := $(filter-out deps/picoquic/picoquic/picoquic_ptls_fusion.c,\
                 $(wildcard deps/picoquic/picoquic/*.c)) \
               deps/picoquic/picoquic_mbedtls/ptls_mbedtls.c \
               deps/picoquic/picoquic_mbedtls/ptls_mbedtls_sign.c
# Project managers: VFS/storage + QUIC transport + minicrypto stub +
# membership/framing (member.c, framing.c). Selftests are excluded here
# and built by the selftest target instead.
SRC_MURMUR  := $(wildcard deps/murmur/*.cc) \
               $(filter-out deps/murmur/%_selftest.c, \
                 $(wildcard deps/murmur/*.c))
SRC_VEC0    := deps/vec0/vec0.c
SRC_LIB     := libmurmur.c

SRCS := $(SRC_SQLITE) $(SRC_CRSQL) $(SRC_CODEC) $(SRC_KEYRING) \
        $(SRC_ARGON2) $(SRC_ZSTD) $(SRC_AEGIS) $(SRC_MBED) \
        $(SRC_PTLS) $(SRC_PICO) $(SRC_MURMUR) $(SRC_VEC0) $(SRC_LIB)

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(filter %.c,$(SRCS))) \
        $(patsubst %.cc,$(BUILD)/%.o,$(filter %.cc,$(SRCS)))

# Per-component flags (pattern-specific). Vendored sets keep the exact
# defines/includes their cgo package used.
$(BUILD)/deps/sqlite/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(SQLITE_DEFS) $(INC_SQLITE)
# SQLITE_CORE: the wrapper links statically, so it calls sqlite3_* directly
# instead of through the extension API table (Go passes pApi=NULL).
$(BUILD)/deps/crsqlite/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) -DSQLITE_CORE $(SQLITE_DEFS) $(INC_CRSQL)
$(BUILD)/deps/zstd/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(ZSTD_DEFS) $(INC_ZSTD)
$(BUILD)/deps/aegis/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_AEGIS)
$(BUILD)/deps/mbedtls/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED)
$(BUILD)/deps/picotls/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED)
$(BUILD)/deps/picoquic/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED) -Wno-pragma-once-outside-header
$(BUILD)/deps/codec/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE) $(INC_AWSLC)
$(BUILD)/deps/keyring/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE)
$(BUILD)/deps/keyring/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE)
$(BUILD)/deps/argon2/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE)
$(BUILD)/deps/murmur/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE)
$(BUILD)/deps/murmur/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE)
$(BUILD)/deps/vec0/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_SQLITE) -Wno-unused-function
$(BUILD)/libmurmur.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_SQLITE) -I.

.PHONY: all clean go-build go-test go-vet xcheck selftest

all: $(LIB)

# Native selftests: dependency-free module mains (member, framing,
# msgcodec) plus the archive-linked proving runs (sync, AES-GCM,
# driver over QUIC loopback).
selftest: $(BUILD)/membertest $(BUILD)/framingtest $(BUILD)/msgcodectest \
    $(BUILD)/filecodectest $(BUILD)/synctest $(BUILD)/aestest \
    $(BUILD)/drivertest $(BUILD)/filestest $(BUILD)/fetchtest \
    $(BUILD)/vectest $(BUILD)/searchtest
	$(BUILD)/membertest
	$(BUILD)/framingtest
	$(BUILD)/msgcodectest
	$(BUILD)/filecodectest
	$(BUILD)/synctest
	$(BUILD)/aestest
	$(BUILD)/drivertest
	$(BUILD)/filestest
	$(BUILD)/fetchtest
	$(BUILD)/vectest
	$(BUILD)/searchtest

$(BUILD)/membertest: deps/murmur/member.c deps/murmur/member_selftest.c \
    deps/murmur/member.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur deps/murmur/member.c \
	  deps/murmur/member_selftest.c -o $@

$(BUILD)/framingtest: deps/murmur/member.c deps/murmur/framing.c \
    deps/murmur/framing_selftest.c deps/murmur/member.h \
    deps/murmur/framing.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur deps/murmur/member.c \
	  deps/murmur/framing.c deps/murmur/framing_selftest.c -o $@

$(BUILD)/msgcodectest: deps/murmur/member.c deps/murmur/msgcodec.c \
    deps/murmur/msgcodec_selftest.c deps/murmur/member.h \
    deps/murmur/msgcodec.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur deps/murmur/member.c \
	  deps/murmur/msgcodec.c deps/murmur/msgcodec_selftest.c -o $@

$(BUILD)/filecodectest: deps/murmur/member.c deps/murmur/msgcodec.c \
    deps/murmur/postcard.c deps/murmur/filecodec.c \
    deps/murmur/filecodec_selftest.c
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  deps/murmur/member.c deps/murmur/msgcodec.c deps/murmur/postcard.c \
	  deps/murmur/filecodec.c deps/murmur/filecodec_selftest.c -o $@

# synctest links the full archive: the first C program proving sync
# over real SQLite + cr-sqlite with no Go involved.
$(BUILD)/synctest: $(LIB) deps/murmur/sync_selftest.c \
    deps/murmur/sync.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include \
	  deps/murmur/sync_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# aestest links the full archive: proves the AES-256-GCM backend
# (mbedTLS) through the codec C API with no Go involved.
$(BUILD)/aestest: $(LIB) deps/codec/aesgcm_selftest.c \
    deps/codec/aesgcm.h deps/codec/murmur_codec.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/codec \
	  deps/codec/aesgcm_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# drivertest links the full archive: two live drivers replicate over
# real QUIC loopback with mutual TLS, no Go involved.
$(BUILD)/drivertest: $(LIB) deps/murmur/driver_selftest.c \
    deps/murmur/driver.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include \
	  deps/murmur/driver_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# filestest links the full archive: the native FileObjects store
# over real SQLite with no Go involved.
$(BUILD)/filestest: $(LIB) deps/murmur/files_selftest.c \
    deps/murmur/files.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/codec -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include \
	  deps/murmur/files_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# fetchtest links the full archive: two live fetch services move a
# file object over real QUIC loopback with mutual TLS, no Go involved.
$(BUILD)/fetchtest: $(LIB) deps/murmur/fetch_selftest.c \
    deps/murmur/fetch.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/codec -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include -Ideps/mbedtls/include \
	  deps/murmur/fetch_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# vectest compiles the vec0 module against the amalgamation directly:
# module behavior with no archive involved.
$(BUILD)/vectest: deps/vec0/vec0.c deps/vec0/vec0_selftest.c \
    deps/vec0/vec0.h deps/sqlite/sqlite3.c deps/sqlite/sqlite3.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Wno-unused-function -Ideps/vec0 -Ideps/sqlite \
	  $(SQLITE_DEFS) \
	  deps/vec0/vec0.c deps/sqlite/sqlite3.c deps/vec0/vec0_selftest.c \
	  -lm -ldl -lpthread -o $@

# searchtest links the full archive: the native search manager over
# real SQLite + FTS5 + vec0 with no Go involved.
$(BUILD)/searchtest: $(LIB) deps/murmur/search_selftest.c \
    deps/murmur/search.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include -Ideps/vec0 \
	  deps/murmur/search_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# demo is the proving C client (N7 gate): two processes replicate a
# Murmur store with no Go involved. See clients/c/demo/README.md.
$(BUILD)/demo: $(LIB) clients/c/demo/demo.c libmurmur.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -I. -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include \
	  clients/c/demo/demo.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

demo: $(BUILD)/demo

democheck: $(BUILD)/demo
	sh clients/c/demo/check.sh

# admin is the C operator CLI (N10): the 9 murmur-admin subcommands
# over libmurmur.a with no Go involved.
$(BUILD)/admin: $(LIB) clients/c/admin/admin.c libmurmur.h \
    deps/murmur/store.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -I. -Ideps -Ideps/murmur -Ideps/keyring \
	  -Ideps/sqlite \
	  clients/c/admin/admin.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

admin: $(BUILD)/admin

admincheck: $(BUILD)/admin
	sh clients/c/admin/check.sh

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) -std=c++17 $(CXXFLAGS) -c $< -o $@

# Third-party archives are merged, not rebuilt. An MRI script (ADDLIB)
# copies every member verbatim: plain extract+repack would lose members
# that share a basename (RocksDB has two format.cc.o / merge_operator.cc.o
# from different dirs; ar x overwrites one copy).
ROCKSDB_A  := deps/rocksdb/lib/librocksdb.a
CRSQL_A    := deps/crsqlite/lib/libcrsql_bundle_isolated.a
AWSLC_A    := deps/aws-lc/lib/libcrypto.a

$(LIB): $(OBJS) $(ROCKSDB_A) $(CRSQL_A) $(AWSLC_A)
	@(echo 'create $@'; \
	  for o in $(OBJS); do echo "addmod $$o"; done; \
	  echo 'addlib $(abspath $(ROCKSDB_A))'; \
	  echo 'addlib $(abspath $(CRSQL_A))'; \
	  echo 'addlib $(abspath $(AWSLC_A))'; \
	  echo 'save'; echo 'end') | $(AR) -M

-include $(OBJS:.o=.d)

clean:
	rm -rf $(BUILD) $(LIB)

# Go client gates. The library is always built first.
go-build: $(LIB)
	cd clients/go && go build ./...

go-test: $(LIB)
	cd clients/go && go test ./...

go-vet: $(LIB)
	cd clients/go && go vet ./...

xcheck: $(LIB)
	sh clients/go/tools/format_xcheck.sh
