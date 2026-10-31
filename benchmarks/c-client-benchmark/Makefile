ROOT := ../..
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -I$(ROOT) -I$(ROOT)/deps/sqlite
LDLIBS += $(ROOT)/libmurmur.a -lstdc++ -lpthread -ldl -lm
TARGET := c-client-benchmark

.PHONY: all clean
all: $(TARGET)

$(TARGET): benchmark.c $(ROOT)/libmurmur.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDLIBS)

$(ROOT)/libmurmur.a:
	$(MAKE) -C $(ROOT) libmurmur.a

clean:
	rm -f $(TARGET)
