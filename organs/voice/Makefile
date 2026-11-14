BUILD_DIR ?= ../../build/bin
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
PYTHON ?= python3

.PHONY: all build install test clean

all: build

build: $(BUILD_DIR)/hvoice

$(BUILD_DIR)/hvoice: hvoice
	mkdir -p "$(BUILD_DIR)"
	chmod 0755 hvoice
	cp -f hvoice "$(BUILD_DIR)/hvoice"
	chmod 0755 "$(BUILD_DIR)/hvoice"

install: build
	mkdir -p "$(BINDIR)"
	cp -f hvoice "$(BINDIR)/hvoice"
	chmod 0755 "$(BINDIR)/hvoice"

test:
	chmod 0755 hvoice
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B -m unittest discover -s tests -v

clean:
	rm -f "$(BUILD_DIR)/hvoice"
	rm -rf __pycache__ tests/__pycache__
