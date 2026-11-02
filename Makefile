# libmurmur - unified Murmur library.
#
# Produces libmurmur.a from every native component: SQLite, cr-sqlite
# (C wrapper + Rust bundle), the page codec (AES-256-GCM via AWS-LC +
# AES-256-GCM + Zstandard), the
# keyring, scrypt, the C++ VFS/storage managers, and the
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
.DEFAULT_GOAL := all
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
INC_AWSLC  := -Ideps/aws-lc/include
INC_MBED   := -Ideps/mbedtls/include
INC_PTLS   := -Ideps/picotls/include
INC_PICO   := -Ideps/picoquic/picoquic -Ideps/picoquic/picoquic_mbedtls
# Project C/C++ (codec, keyring, scrypt, murmur managers): same superset
# the nvfs cgo package used, so headers resolve as before.
INC_NATIVE := -Ideps/murmur -Ideps/codec -Ideps/keyring \
              -Ideps/sqlite -Ideps/zstd -Ideps/vec0 \
              -Ideps/rocksdb/include \
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
               deps/keyring/crc32c.c deps/keyring/keyring.cc deps/keyring/scrypt.cc
SRC_ZSTD    := $(wildcard deps/zstd/*.c)
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
SRC_MURMUR  := $(filter-out deps/murmur/%_selftest.cc,$(wildcard deps/murmur/*.cc)) \
               $(filter-out deps/murmur/%_selftest.c, \
                 $(wildcard deps/murmur/*.c))
SRC_VEC0    := deps/vec0/vec0.c
SRC_LIB     := libmurmur.c

SRCS := $(SRC_SQLITE) $(SRC_CRSQL) $(SRC_CODEC) $(SRC_KEYRING) \
        $(SRC_ZSTD) $(SRC_MBED) \
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
$(BUILD)/deps/mbedtls/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED)
$(BUILD)/deps/picotls/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED)
$(BUILD)/deps/picoquic/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(PQ_DEFS) $(INC_PICO) $(INC_PTLS) $(INC_MBED) -Wno-pragma-once-outside-header
$(BUILD)/deps/codec/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE) $(INC_AWSLC)
$(BUILD)/deps/keyring/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE)
$(BUILD)/deps/keyring/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(INC_NATIVE) $(INC_AWSLC)
$(BUILD)/deps/murmur/%.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE)
$(BUILD)/deps/murmur/%.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE)
$(BUILD)/deps/murmur/cellsign.o: CFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE) $(INC_AWSLC)
$(BUILD)/deps/murmur/origin.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE) $(INC_AWSLC)
$(BUILD)/deps/murmur/bridge_codec.o: CXXFLAGS := $(OPT) $(PIC) $(DEPFLAGS) $(MURMUR_DEFS) $(INC_NATIVE) $(INC_AWSLC)

$(BUILD)/bridgecodectest: $(LIB) deps/murmur/bridge_codec_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_codec_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

.PHONY: bridgecheck
bridgecheck: $(BUILD)/bridgecodectest
	./$(BUILD)/bridgecodectest
	./$(BUILD)/bridgestoretest
	./$(BUILD)/bridgeownershiptest
	./$(BUILD)/bridgerowstest
	./$(BUILD)/bridgecapturetest
	./$(BUILD)/bridgeferrytest
	./$(BUILD)/bridgefilestest
	./$(BUILD)/bridgepeertest
	./$(BUILD)/bridgelowpeertest

bridgecheck: $(BUILD)/bridgestoretest
bridgecheck: $(BUILD)/bridgeownershiptest
bridgecheck: $(BUILD)/bridgerowstest
bridgecheck: $(BUILD)/bridgecapturetest
bridgecheck: $(BUILD)/bridgeferrytest
bridgecheck: $(BUILD)/bridgefilestest
bridgecheck: $(BUILD)/bridgepeertest
bridgecheck: $(BUILD)/bridgelowpeertest

$(BUILD)/bridgelowpeertest: $(LIB) deps/murmur/bridge_low_peer_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_low_peer_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgepeertest: $(LIB) deps/murmur/bridge_peer_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_peer_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgefilestest: $(LIB) deps/murmur/bridge_files_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_files_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgeferrytest: $(LIB) deps/murmur/bridge_ferry_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_ferry_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgecapturetest: $(LIB) deps/murmur/bridge_capture_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_capture_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgerowstest: $(LIB) deps/murmur/bridge_rows_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_rows_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgeownershiptest: $(LIB) deps/murmur/bridge_ownership_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_ownership_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/bridgestoretest: $(LIB) deps/murmur/bridge_store_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/bridge_store_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

selftest: $(BUILD)/bridgecodectest
selftest: $(BUILD)/bridgestoretest
selftest: $(BUILD)/bridgeownershiptest
selftest: $(BUILD)/bridgerowstest
selftest: $(BUILD)/bridgecapturetest
selftest: $(BUILD)/bridgeferrytest
selftest: $(BUILD)/bridgefilestest
selftest: $(BUILD)/bridgepeertest
selftest: $(BUILD)/bridgelowpeertest
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
    $(BUILD)/transporttest $(BUILD)/replicatest \
    $(BUILD)/vectest $(BUILD)/searchtest $(BUILD)/schedulertest $(BUILD)/origintest $(BUILD)/managedtest $(BUILD)/managedsearchtest $(BUILD)/causaltest $(BUILD)/managedpolicytest $(BUILD)/managedvaluetest $(BUILD)/managedorigintest $(BUILD)/managedschematest $(BUILD)/managedrowtest $(BUILD)/managedreplicatest

selftest: $(BUILD)/managedmodeltest $(BUILD)/managedfaulttest $(BUILD)/schedulercontentiontest $(BUILD)/managedsearchoracletest $(BUILD)/managedfuzztest
	$(BUILD)/bridgecodectest
	$(BUILD)/bridgestoretest
	$(BUILD)/bridgeownershiptest
	$(BUILD)/bridgerowstest
	$(BUILD)/bridgecapturetest
	$(BUILD)/bridgeferrytest
	$(BUILD)/bridgefilestest
	$(BUILD)/bridgepeertest
	$(BUILD)/bridgelowpeertest
	$(BUILD)/membertest
	$(BUILD)/framingtest
	$(BUILD)/msgcodectest
	$(BUILD)/filecodectest
	$(BUILD)/synctest
	$(BUILD)/aestest
	$(BUILD)/drivertest
	$(BUILD)/filestest
	$(BUILD)/fetchtest
	$(BUILD)/transporttest
	$(BUILD)/replicatest
	$(BUILD)/vectest
	$(BUILD)/searchtest
	$(BUILD)/schedulertest
	$(BUILD)/origintest
	$(BUILD)/managedtest
	$(BUILD)/managedsearchtest
	$(BUILD)/causaltest
	$(BUILD)/managedpolicytest
	$(BUILD)/managedvaluetest
	$(BUILD)/managedorigintest
	$(BUILD)/managedschematest
	$(BUILD)/managedrowtest
	$(BUILD)/managedreplicatest
	$(BUILD)/managedmodeltest
	$(BUILD)/managedfaulttest
	$(BUILD)/schedulercontentiontest
	$(BUILD)/managedsearchoracletest
	$(BUILD)/managedfuzztest

$(BUILD)/managedfuzztest: $(LIB) deps/murmur/managed_fuzz_selftest.cc tests/native/managed_codec_fuzz.cc deps/murmur/test_managed_support.h
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_fuzz_selftest.cc tests/native/managed_codec_fuzz.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/tests/asan/managedfuzztest: $(LIB) $(MANAGED_ASAN_OBJS) deps/murmur/managed_fuzz_selftest.cc tests/native/managed_codec_fuzz.cc deps/murmur/test_managed_support.h
	$(CXX) $(MANAGED_ASAN_FLAGS) deps/murmur/managed_fuzz_selftest.cc tests/native/managed_codec_fuzz.cc $(MANAGED_ASAN_OBJS) $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedsearchoracletest: $(LIB) deps/murmur/managed_search_oracle_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_search_oracle_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/schedulercontentiontest: deps/murmur/scheduler.cc deps/murmur/scheduler_contention_selftest.cc deps/murmur/scheduler.h
	$(CXX) $(OPT) -Wall -Wextra -DMURMUR_SCHEDULER_TEST_CLOCK -Ideps/murmur -Ideps/sqlite deps/murmur/scheduler.cc deps/murmur/scheduler_contention_selftest.cc -lpthread -o $@

$(BUILD)/managedfaulttest: $(LIB) deps/murmur/managed_fault_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_fault_selftest.cc $(LIB) -Wl,--wrap=sqlite3_exec,--wrap=nv_store_write_batch,--wrap=nv_store_sync -lm -ldl -lpthread -o $@

$(BUILD)/managedmodeltest: $(LIB) deps/murmur/managed_model_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_model_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

# Instrument owned managed code; vendored RocksDB has no RTTI, so vptr
# checks are disabled. The storage/SQLite archives remain the same inputs
# used by normal clients. ASan leak detection remains enabled.
MANAGED_TEST_PARTS := managed managed_search managed_policy managed_policy_state managed_value managed_origin managed_schema managed_row managed_replica causal scheduler origin
MANAGED_ASAN_OBJS := $(addprefix $(BUILD)/tests/asan/,$(addsuffix .o,$(MANAGED_TEST_PARTS)))
MANAGED_ASAN_FLAGS := -std=c++17 -O1 -g -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer -Ideps/murmur -Ideps/sqlite -Ideps/keyring -Ideps/aws-lc/include

$(BUILD)/tests/asan/managedfuzztest: $(MANAGED_ASAN_OBJS)

$(BUILD)/tests/asan/%.o: deps/murmur/%.cc
	@mkdir -p $(@D)
	$(CXX) $(MANAGED_ASAN_FLAGS) -MMD -MP -c $< -o $@

$(BUILD)/tests/asan/managedmodeltest: $(LIB) $(MANAGED_ASAN_OBJS) deps/murmur/managed_model_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(MANAGED_ASAN_FLAGS) deps/murmur/managed_model_selftest.cc $(MANAGED_ASAN_OBJS) $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/tests/asan/managedfaulttest: $(LIB) $(MANAGED_ASAN_OBJS) deps/murmur/managed_fault_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(MANAGED_ASAN_FLAGS) deps/murmur/managed_fault_selftest.cc $(MANAGED_ASAN_OBJS) $(LIB) -Wl,--wrap=sqlite3_exec,--wrap=nv_store_write_batch,--wrap=nv_store_sync -lm -ldl -lpthread -o $@

$(BUILD)/tests/asan/managedsearchoracletest: $(LIB) $(MANAGED_ASAN_OBJS) deps/murmur/managed_search_oracle_selftest.cc deps/murmur/test_managed_support.h
	$(CXX) $(MANAGED_ASAN_FLAGS) deps/murmur/managed_search_oracle_selftest.cc $(MANAGED_ASAN_OBJS) $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/tests/asan/schedulercontentiontest: deps/murmur/scheduler.cc deps/murmur/scheduler_contention_selftest.cc deps/murmur/scheduler.h
	@mkdir -p $(@D)
	$(CXX) $(MANAGED_ASAN_FLAGS) -DMURMUR_SCHEDULER_TEST_CLOCK deps/murmur/scheduler.cc deps/murmur/scheduler_contention_selftest.cc -lpthread -o $@

.PHONY: test-native-sanitize
test-native-sanitize: $(BUILD)/tests/asan/managedmodeltest $(BUILD)/tests/asan/managedfaulttest $(BUILD)/tests/asan/schedulercontentiontest $(BUILD)/tests/asan/managedsearchoracletest $(BUILD)/tests/asan/managedfuzztest
	$(BUILD)/tests/asan/managedmodeltest 2 220 5
	$(BUILD)/tests/asan/managedfaulttest
	$(BUILD)/tests/asan/schedulercontentiontest
	$(BUILD)/tests/asan/managedsearchoracletest
	$(BUILD)/tests/asan/managedfuzztest

-include $(MANAGED_ASAN_OBJS:.o=.d)

# Instrument every owned codec branch for coverage-guided fuzzing.
FUZZ_CXX ?= clang++-17
FUZZ_CXX += --gcc-install-dir=$(patsubst %/,%,$(dir $(shell $(CXX) -print-libgcc-file-name)))
FUZZ_FLAGS := -std=c++17 -O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer -Ideps/murmur -Ideps/sqlite -Ideps/keyring -Ideps/aws-lc/include
FUZZ_OBJS := $(addprefix $(BUILD)/tests/libfuzzer/,$(addsuffix .o,$(MANAGED_TEST_PARTS)))
$(BUILD)/tests/libfuzzer/%.o: deps/murmur/%.cc
	@mkdir -p $(@D)
	$(FUZZ_CXX) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@
$(BUILD)/managed-codec-fuzzer: $(LIB) $(FUZZ_OBJS) tests/native/managed_codec_fuzz.cc
	$(FUZZ_CXX) $(FUZZ_FLAGS) -fsanitize=fuzzer tests/native/managed_codec_fuzz.cc $(FUZZ_OBJS) $(LIB) -lm -ldl -lpthread -o $@
.PHONY: test-native-libfuzzer
test-native-libfuzzer: $(BUILD)/managed-codec-fuzzer $(BUILD)/managedfuzztest
	@mkdir -p $(BUILD)/tests/fuzz-corpus
	MURMUR_FUZZ_CORPUS=$(BUILD)/tests/fuzz-corpus $(BUILD)/managedfuzztest 42 0
	$(BUILD)/managed-codec-fuzzer -max_total_time=60 -max_len=65536 -timeout=10 $(BUILD)/tests/fuzz-corpus
-include $(FUZZ_OBJS:.o=.d)

# Focused managed gates; live tests build their own process fault hooks.
.PHONY: test-go-managed test-live-managed test-managed test-managed-stress
test-go-managed: $(LIB)
	cd clients/go && CGO_ENABLED=1 CGO_CXXFLAGS="$$CGO_CXXFLAGS -DMURMUR_TEST_LIBRARY_REV=$$(stat -c %Y ../../$(LIB))" go test -race -count=1 -timeout 180s ./bindings/sqlite ./murmurdb ./tests-live/managedharness

test-live-managed: $(LIB)
	MURMUR_ENGINE_INTEGRATION=1 bash clients/go/tests-live/run.sh managed

test-managed: $(BUILD)/managedmodeltest $(BUILD)/managedfaulttest $(BUILD)/schedulercontentiontest $(BUILD)/managedsearchoracletest $(BUILD)/managedfuzztest
	$(BUILD)/managedmodeltest 2 220 5
	$(BUILD)/managedfaulttest
	$(BUILD)/schedulercontentiontest
	$(BUILD)/managedsearchoracletest
	$(BUILD)/managedfuzztest
	$(MAKE) test-go-managed
	$(MAKE) test-live-managed

test-managed-stress: $(BUILD)/managedmodeltest $(BUILD)/managedfuzztest
	@for seed in 1 2 3 4 5 6 7 8; do $(BUILD)/managedmodeltest $$seed 500 $$((3 + seed % 3)) || exit; done
	$(BUILD)/managedfuzztest 1592594996 250000
	MURMUR_ENGINE_INTEGRATION=1 MURMUR_MANAGED_RESOURCE_CYCLES=400 MURMUR_MANAGED_TEST_COUNT=3 bash clients/go/tests-live/run.sh managed

$(BUILD)/managedreplicatest: $(LIB) deps/murmur/managed_replica_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_replica_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedrowtest: $(LIB) deps/murmur/managed_row_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_row_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedschematest: $(LIB) deps/murmur/managed_schema_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite -Ideps/keyring deps/murmur/managed_schema_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedorigintest: $(LIB) deps/murmur/managed_origin_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/managed_origin_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedvaluetest: $(LIB) deps/murmur/managed_value_selftest.cc deps/murmur/testdata/value_vectors.txt
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/managed_value_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedpolicytest: $(LIB) deps/murmur/managed_policy_selftest.cc
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/managed_policy_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/causaltest: $(LIB) deps/murmur/causal_selftest.cc deps/murmur/testdata/causal_vectors.txt
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/causal_selftest.cc $(LIB) -lm -ldl -lpthread -o $@

$(BUILD)/managedsearchtest: $(LIB) deps/murmur/managed_search_selftest.c
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/managed_search_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread -o $@

$(BUILD)/schedulertest: deps/murmur/scheduler.cc deps/murmur/scheduler_selftest.cc deps/murmur/scheduler.h
	@mkdir -p $(BUILD)
	$(CXX) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/scheduler.cc deps/murmur/scheduler_selftest.cc -lpthread -o $@

$(BUILD)/origintest: $(LIB) deps/murmur/origin_selftest.c
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/origin_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread -o $@

$(BUILD)/managedtest: $(LIB) deps/murmur/managed_selftest.c
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite deps/murmur/managed_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread -o $@

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

# transporttest links the full archive: direct QUIC transport suites
# (handshake identity, streams, datagrams, gates, close, args) over
# real loopback with mutual TLS, no Go involved.
$(BUILD)/transporttest: $(LIB) deps/murmur/transport_selftest.c \
    deps/murmur/transport.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include -Ideps/mbedtls/include \
	  deps/murmur/transport_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
	  -o $@

# replicatest links the full archive: extended node-to-node
# replication over real QUIC loopback (bidirectional, multi-batch,
# conflict, restart healing, snapshot joiner), no Go involved.
$(BUILD)/replicatest: $(LIB) deps/murmur/replication_selftest.c \
    deps/murmur/driver.h
	@mkdir -p $(BUILD)
	$(CC) $(OPT) -Wall -Wextra -Ideps/murmur -Ideps/sqlite \
	  -Ideps/keyring -Ideps/crsqlite/include \
	  deps/murmur/replication_selftest.c $(LIB) -lstdc++ -lm -ldl -lpthread \
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

# Reuse the vendored SQLite shell, patched only in the build directory.
MURMUR_SHELL_BUILD := $(BUILD)/sqlite3-murmur-tool
MURMUR_SHELL_BIN := $(MURMUR_SHELL_BUILD)/sqlite3-murmur
.PHONY: sqlite3-murmur-tool sqlite3-murmur-tool-check
sqlite3-murmur-tool: $(MURMUR_SHELL_BIN)

# Release artifacts use the directory name requested by the CLI consumer;
# sources remain in sqlite3-murmur-tool/.
MURMUR_TOOL_DIST := sqlite-murmur-tool/bin/linux-x86_64
.PHONY: sqlite3-murmur-tool-bin sqlite3-murmur-tool-linux-bin sqlite3-murmur-tool-win64-bin
sqlite3-murmur-tool-bin: sqlite3-murmur-tool-linux-bin sqlite3-murmur-tool-win64-bin

sqlite3-murmur-tool-win64-bin:
	sh sqlite3-murmur-tool/build-win64.sh

sqlite3-murmur-tool-linux-bin: $(MURMUR_SHELL_BIN)
	@test "$$(uname -sm)" = "Linux x86_64" || { echo 'This packaging target requires Linux x86_64.' >&2; exit 1; }
	@mkdir -p $(MURMUR_TOOL_DIST)
	install -m 755 $(MURMUR_SHELL_BIN) $(MURMUR_TOOL_DIST)/sqlite3-murmur
	cd $(MURMUR_TOOL_DIST) && sha256sum sqlite3-murmur > SHA256SUMS

$(MURMUR_SHELL_BUILD)/shell.c: deps/sqlite/shell.c sqlite3-murmur-tool/shell.patch
	@mkdir -p $(@D)
	patch --batch --fuzz=0 --output=$@.tmp $< sqlite3-murmur-tool/shell.patch
	mv $@.tmp $@

$(MURMUR_SHELL_BUILD)/shell.o: $(MURMUR_SHELL_BUILD)/shell.c sqlite3-murmur-tool/tool.h
	$(CC) $(OPT) $(DEPFLAGS) $(SQLITE_DEFS) -Ideps/sqlite -Isqlite3-murmur-tool \
	  -Dmain=murmur_sqlite_shell_main -DSQLITE_SHELL_INIT_PROC=murmur_tool_init \
	  -c $< -o $@

$(MURMUR_SHELL_BUILD)/tool.o: sqlite3-murmur-tool/tool.c sqlite3-murmur-tool/tool.h
	@mkdir -p $(@D)
	$(CC) -std=c11 $(OPT) $(DEPFLAGS) -Wall -Wextra -Werror -I. -Ideps/sqlite -c $< -o $@

$(MURMUR_SHELL_BIN): $(MURMUR_SHELL_BUILD)/shell.o $(MURMUR_SHELL_BUILD)/tool.o $(LIB)
	$(CC) $^ -lstdc++ -lm -ldl -lpthread -o $@

$(MURMUR_SHELL_BUILD)/native-check: sqlite3-murmur-tool/native-check.c $(LIB)
	@mkdir -p $(@D)
	$(CC) $(OPT) -Wall -Wextra -Werror -I. -Ideps/sqlite $^ -lstdc++ -lm -ldl -lpthread -o $@

$(MURMUR_SHELL_BUILD)/check-extension.so: sqlite3-murmur-tool/check-extension.c deps/sqlite/sqlite3ext.h deps/sqlite/sqlite3.h
	@mkdir -p $(@D)
	$(CC) $(OPT) -Wall -Wextra -Werror -fPIC -shared -Ideps/sqlite $< -o $@

$(MURMUR_SHELL_BUILD)/sqlite3-murmur-fault: sqlite3-murmur-tool/check-flush-fault.c $(MURMUR_SHELL_BUILD)/shell.o $(MURMUR_SHELL_BUILD)/tool.o $(LIB)
	$(CC) $(OPT) -Wall -Wextra -Werror -Ideps/sqlite $^ -Wl,--wrap=nvStoreFlush -lstdc++ -lm -ldl -lpthread -o $@

sqlite3-murmur-tool-check: $(MURMUR_SHELL_BIN) $(MURMUR_SHELL_BUILD)/native-check $(MURMUR_SHELL_BUILD)/check-extension.so $(MURMUR_SHELL_BUILD)/sqlite3-murmur-fault
	python3 sqlite3-murmur-tool/check.py $(MURMUR_SHELL_BIN) $(MURMUR_SHELL_BUILD)/native-check $(MURMUR_SHELL_BUILD)/check-extension.so $(MURMUR_SHELL_BUILD)/sqlite3-murmur-fault

-include $(MURMUR_SHELL_BUILD)/shell.d $(MURMUR_SHELL_BUILD)/tool.d

# Go client gates. The library is always built first.
go-build: $(LIB)
	cd clients/go && go build ./...

go-test: $(LIB)
	cd clients/go && go test ./...

go-vet: $(LIB)
	cd clients/go && go vet ./...

xcheck: $(LIB)
	sh clients/go/tools/format_xcheck.sh
