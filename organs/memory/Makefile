CC        ?= cc
CFLAGS    ?= -std=c11 -O3 -Wall -Wextra
LDFLAGS   ?=
BUILD_DIR ?= ../../build/bin
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin

SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null)
ifeq ($(strip $(SQLITE_LIBS)),)
    SQLITE_LIBS := -lsqlite3
endif

HMEMORY_BIN := $(BUILD_DIR)/hmemory
HEADERS     := src/hmemory_stem.h src/hmemory_core.h

.PHONY: all test install clean

all: $(HMEMORY_BIN)

$(BUILD_DIR):
	@mkdir -p "$(BUILD_DIR)"

$(HMEMORY_BIN): src/hmemory.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SQLITE_CFLAGS) -Isrc -o "$@" src/hmemory.c $(LDFLAGS) $(SQLITE_LIBS) -lm

test: all
	PYTHONDONTWRITEBYTECODE=1 HEPHAESTUS_MEMORY_BIN="$(abspath $(HMEMORY_BIN))" python3 -m unittest discover -s tests -p "test_*.py" -v

install: all
	@mkdir -p "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(HMEMORY_BIN)" "$(DESTDIR)$(BINDIR)/hmemory"

clean:
	rm -f "$(HMEMORY_BIN)"
