VERSION   ?= 0.1.0
CC        ?= cc
CFLAGS    ?= -std=c11 -O3 -Wall -Wextra
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
SHAREDIR  ?= $(PREFIX)/share/hephaestus
BUILD_DIR := $(CURDIR)/build/bin
DIST_DIR  := $(CURDIR)/dist
ORGANS    ?= slice shield verify memory voice

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
    OS_TAG := linux
else ifeq ($(UNAME_S),Darwin)
    OS_TAG := macos
else
    OS_TAG := $(shell printf '%s' "$(UNAME_S)" | tr '[:upper:]' '[:lower:]')
endif
DIST_STEM := hephaestus-v$(VERSION)-$(OS_TAG)-$(UNAME_M)

.PHONY: all organs test e2e dist install clean distclean

all: organs $(BUILD_DIR)/hephaestus

organs:
	@mkdir -p "$(BUILD_DIR)"
	@set -e; for organ in $(ORGANS); do \
		$(MAKE) --no-print-directory -C "organs/$$organ" BUILD_DIR="$(BUILD_DIR)" CC="$(CC)" CFLAGS="$(CFLAGS)" || exit 1; \
	done

$(BUILD_DIR)/hephaestus: bin/hephaestus
	@mkdir -p "$(BUILD_DIR)"
	install -m 0755 bin/hephaestus "$(BUILD_DIR)/hephaestus"

test: all
	@set -e; for organ in $(ORGANS); do \
		$(MAKE) --no-print-directory -C "organs/$$organ" test BUILD_DIR="$(BUILD_DIR)" CC="$(CC)" CFLAGS="$(CFLAGS)" || exit 1; \
	done
	PYTHONDONTWRITEBYTECODE=1 HEPHAESTUS_BIN_DIR="$(BUILD_DIR)" python3 -B -m unittest discover -s tests -p "test_*.py" -v

e2e: all
	PYTHONDONTWRITEBYTECODE=1 HEPHAESTUS_BIN_DIR="$(BUILD_DIR)" python3 -B -m unittest discover -s tests -p "test_*.py" -v

install: all
	@mkdir -p "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(SHAREDIR)/mcp" "$(DESTDIR)$(SHAREDIR)/skills"
	install -m 0755 bin/hephaestus "$(DESTDIR)$(BINDIR)/hephaestus"
	install -m 0755 mcp/hephaestus_mcp.py "$(DESTDIR)$(SHAREDIR)/mcp/hephaestus_mcp.py"
	@if [ -x "$(BUILD_DIR)/hslice" ]; then \
		install -m 0755 "$(BUILD_DIR)/hslice" "$(DESTDIR)$(BINDIR)/hslice"; \
		install -m 0755 "$(BUILD_DIR)/hfind" "$(DESTDIR)$(BINDIR)/hfind"; \
		ln -sf hfind "$(DESTDIR)$(BINDIR)/hsearch"; \
	fi
	@if [ -x "$(BUILD_DIR)/hshield" ]; then \
		install -m 0755 "$(BUILD_DIR)/hshield" "$(DESTDIR)$(BINDIR)/hshield"; \
		install -m 0755 "$(BUILD_DIR)/hhook" "$(DESTDIR)$(BINDIR)/hhook"; \
	fi
	@if [ -x "$(BUILD_DIR)/hverify" ]; then \
		install -m 0755 "$(BUILD_DIR)/hverify" "$(DESTDIR)$(BINDIR)/hverify"; \
	fi
	@if [ -x "$(BUILD_DIR)/hmemory" ]; then \
		install -m 0755 "$(BUILD_DIR)/hmemory" "$(DESTDIR)$(BINDIR)/hmemory"; \
	fi
	@if [ -x "$(BUILD_DIR)/hvoice" ]; then \
		install -m 0755 "$(BUILD_DIR)/hvoice" "$(DESTDIR)$(BINDIR)/hvoice"; \
	fi
	@for organ in $(ORGANS); do \
		if [ -f "skills/$$organ/SKILL.md" ]; then \
			mkdir -p "$(DESTDIR)$(SHAREDIR)/skills/$$organ"; \
			install -m 0644 "skills/$$organ/SKILL.md" "$(DESTDIR)$(SHAREDIR)/skills/$$organ/SKILL.md"; \
		fi; \
	done

dist: all
	@rm -rf "$(DIST_DIR)/$(DIST_STEM)"
	@mkdir -p "$(DIST_DIR)/$(DIST_STEM)/bin" "$(DIST_DIR)/$(DIST_STEM)/mcp" "$(DIST_DIR)/$(DIST_STEM)/skills"
	install -m 0755 bin/hephaestus "$(DIST_DIR)/$(DIST_STEM)/bin/hephaestus"
	@if [ -x "$(BUILD_DIR)/hslice" ]; then \
		install -m 0755 "$(BUILD_DIR)/hslice" "$(DIST_DIR)/$(DIST_STEM)/bin/hslice"; \
		install -m 0755 "$(BUILD_DIR)/hfind" "$(DIST_DIR)/$(DIST_STEM)/bin/hfind"; \
		ln -sf hfind "$(DIST_DIR)/$(DIST_STEM)/bin/hsearch"; \
	fi
	@if [ -x "$(BUILD_DIR)/hshield" ]; then \
		install -m 0755 "$(BUILD_DIR)/hshield" "$(DIST_DIR)/$(DIST_STEM)/bin/hshield"; \
		install -m 0755 "$(BUILD_DIR)/hhook" "$(DIST_DIR)/$(DIST_STEM)/bin/hhook"; \
	fi
	@if [ -x "$(BUILD_DIR)/hverify" ]; then \
		install -m 0755 "$(BUILD_DIR)/hverify" "$(DIST_DIR)/$(DIST_STEM)/bin/hverify"; \
	fi
	@if [ -x "$(BUILD_DIR)/hmemory" ]; then \
		install -m 0755 "$(BUILD_DIR)/hmemory" "$(DIST_DIR)/$(DIST_STEM)/bin/hmemory"; \
	fi
	@if [ -x "$(BUILD_DIR)/hvoice" ]; then \
		install -m 0755 "$(BUILD_DIR)/hvoice" "$(DIST_DIR)/$(DIST_STEM)/bin/hvoice"; \
	fi
	install -m 0755 mcp/hephaestus_mcp.py "$(DIST_DIR)/$(DIST_STEM)/mcp/hephaestus_mcp.py"
	install -m 0755 install.sh "$(DIST_DIR)/$(DIST_STEM)/install.sh"
	install -m 0644 LICENSE "$(DIST_DIR)/$(DIST_STEM)/LICENSE"
	@if [ -f README.md ]; then install -m 0644 README.md "$(DIST_DIR)/$(DIST_STEM)/README.md"; fi
	@set -e; for organ in $(ORGANS); do \
		if [ -f "skills/$$organ/SKILL.md" ]; then \
			mkdir -p "$(DIST_DIR)/$(DIST_STEM)/skills/$$organ"; \
			install -m 0644 "skills/$$organ/SKILL.md" "$(DIST_DIR)/$(DIST_STEM)/skills/$$organ/SKILL.md"; \
		fi; \
	done
	tar -czf "$(DIST_DIR)/$(DIST_STEM).tar.gz" -C "$(DIST_DIR)" "$(DIST_STEM)"
	@rm -rf "$(DIST_DIR)/$(DIST_STEM)"
	@cd "$(DIST_DIR)" && (sha256sum "$(DIST_STEM).tar.gz" > SHA256SUMS 2>/dev/null || shasum -a 256 "$(DIST_STEM).tar.gz" > SHA256SUMS)
	@echo "Packaged $(DIST_DIR)/$(DIST_STEM).tar.gz + SHA256SUMS"

clean:
	@for organ in $(ORGANS); do \
		if [ -f "organs/$$organ/Makefile" ]; then \
			$(MAKE) --no-print-directory -C "organs/$$organ" clean BUILD_DIR="$(BUILD_DIR)"; \
		fi; \
	done
	rm -rf "$(CURDIR)/build" __pycache__ tests/__pycache__ bin/__pycache__ mcp/__pycache__

distclean: clean
	rm -rf "$(DIST_DIR)"
