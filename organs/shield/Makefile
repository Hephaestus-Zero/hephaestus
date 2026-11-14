CC        ?= cc
CFLAGS    ?= -std=c11 -O3 -Wall -Wextra
LDFLAGS   ?=
BUILD_DIR ?= build

BINS := $(BUILD_DIR)/hshield $(BUILD_DIR)/hhook

.PHONY: all clean test

all: $(BINS)

$(BUILD_DIR)/hshield: src/hshield.c
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) src/hshield.c -o "$@" $(LDFLAGS)
	@chmod 0755 "$@"

$(BUILD_DIR)/hhook: src/hhook.c
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) src/hhook.c -o "$@" $(LDFLAGS)
	@chmod 0755 "$@"

test: all
	PYTHONDONTWRITEBYTECODE=1 SHIELD_BUILD_DIR="$(BUILD_DIR)" python3 -B -m unittest discover -s tests -v

clean:
	rm -rf "$(BUILD_DIR)/hshield" "$(BUILD_DIR)/hhook" tests/__pycache__
	@if [ "$(BUILD_DIR)" = "build" ] && [ -d build ]; then rmdir build 2>/dev/null || true; fi
