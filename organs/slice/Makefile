CC        ?= cc
CFLAGS    ?= -std=c11 -O3 -Wall -Wextra
LDFLAGS   ?=
BUILD_DIR ?= ../../build/bin
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    DL_LIBS := -ldl
else
    DL_LIBS :=
endif

HSLICE_BIN  := $(BUILD_DIR)/hslice
HFIND_BIN   := $(BUILD_DIR)/hfind
HSEARCH_BIN := $(BUILD_DIR)/hsearch
COMMON_HDR  := src/hslice_common.h

.PHONY: all test install clean

all: $(HSLICE_BIN) $(HFIND_BIN) $(HSEARCH_BIN)

$(BUILD_DIR):
	@mkdir -p "$(BUILD_DIR)"

$(HSLICE_BIN): src/hslice.c $(COMMON_HDR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o "$@" src/hslice.c $(LDFLAGS) $(DL_LIBS)

$(HFIND_BIN): src/hfind.c $(COMMON_HDR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o "$@" src/hfind.c $(LDFLAGS)

$(HSEARCH_BIN): $(HFIND_BIN) | $(BUILD_DIR)
	ln -sf hfind "$@"

test: all
	HEPHAESTUS_SLICE_BIN_DIR="$(abspath $(BUILD_DIR))" python3 -B -m unittest discover -s tests -p "test_*.py" -v

install: all
	@mkdir -p "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(HSLICE_BIN)" "$(DESTDIR)$(BINDIR)/hslice"
	install -m 0755 "$(HFIND_BIN)" "$(DESTDIR)$(BINDIR)/hfind"
	ln -sf hfind "$(DESTDIR)$(BINDIR)/hsearch"

clean:
	rm -f "$(HSLICE_BIN)" "$(HFIND_BIN)" "$(HSEARCH_BIN)"
