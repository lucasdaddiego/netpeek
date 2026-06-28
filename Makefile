# netpeek — live per-process network bandwidth TUI (Rust / ratatui).
# `make` builds an optimised release binary and symlinks `netpeek` into ~/.bin.

BINARY      := netpeek
INSTALL_DIR := $(HOME)/.bin
TARGET      := target/release/$(BINARY)

# The pure-logic modules carry the coverage gate; the syscall / TUI / entrypoint
# plumbing (exercised by `--diag` and the smoke test, not unit tests) is excluded.
COV_EXCLUDE := --ignore-filename-regex 'src/(ui|dns|main)\.rs|src/ntstat/(sys|mod)\.rs'
# Homebrew's Rust ships no llvm-tools-preview; if the brew `llvm` keg is present,
# point cargo-llvm-cov at its tools. (CI uses rustup's llvm-tools-preview instead.)
BREW_LLVM_BIN := $(shell brew --prefix llvm 2>/dev/null)/bin

.DEFAULT_GOAL := install
.PHONY: install run test lint coverage clean help

install: ## Build the release binary + symlink `netpeek` into ~/.bin
	cargo build --release
	@mkdir -p "$(INSTALL_DIR)"
	@ln -sf "$(CURDIR)/$(TARGET)" "$(INSTALL_DIR)/$(BINARY)"
	@echo "installed $(TARGET) ($$(du -h "$(TARGET)" | cut -f1 | tr -d ' '))"
	@echo "         launcher: $(INSTALL_DIR)/$(BINARY) — ensure ~/.bin is on your PATH"

run: ## Build + run the TUI (debug)
	cargo run

test: ## Run the unit test suite (no root, no network)
	cargo test

lint: ## rustfmt --check + clippy (warnings are errors)
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

coverage: ## Coverage over the pure core; fails below the line threshold
	@if [ -x "$(BREW_LLVM_BIN)/llvm-cov" ]; then \
		LLVM_COV="$(BREW_LLVM_BIN)/llvm-cov" LLVM_PROFDATA="$(BREW_LLVM_BIN)/llvm-profdata" \
			cargo llvm-cov $(COV_EXCLUDE) --summary-only --fail-under-lines 99; \
	else \
		cargo llvm-cov $(COV_EXCLUDE) --summary-only --fail-under-lines 99; \
	fi

clean: ## Remove build artifacts and the launcher
	cargo clean
	@rm -f "$(INSTALL_DIR)/$(BINARY)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
