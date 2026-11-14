BUILD_DIR ?= ../../build/bin
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
PYTHON ?= python3

.PHONY: all build install test clean

all: build

build: $(BUILD_DIR)/hverify

$(BUILD_DIR)/hverify: hverify
	mkdir -p "$(BUILD_DIR)"
	chmod 0755 hverify
	cp -f hverify "$(BUILD_DIR)/hverify"
	chmod 0755 "$(BUILD_DIR)/hverify"

install: build
	mkdir -p "$(BINDIR)"
	cp -f hverify "$(BINDIR)/hverify"
	chmod 0755 "$(BINDIR)/hverify"

test:
	chmod 0755 hverify
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B -m unittest discover -s tests -v

clean:
	rm -f "$(BUILD_DIR)/hverify"
	rm -rf __pycache__ tests/__pycache__
