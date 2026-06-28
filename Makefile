# netpeek — live per-process network bandwidth TUI (Rust / ratatui).
# `make` (≡ `make install`) builds an optimised binary and symlinks `netpeek`
# into ~/.bin. `make help` lists every target; `make check` runs the full CI gate.

BINARY      := netpeek
INSTALL_DIR ?= $(HOME)/.bin
TARGET      := target/release/$(BINARY)
ARGS        ?=

# The pure-logic modules carry the coverage gate; the syscall / TUI / entrypoint
# plumbing (exercised by --diag and the smoke test, not unit tests) is excluded.
COV_EXCLUDE := --ignore-filename-regex 'src/(ui|dns|main)\.rs|src/ntstat/(sys|mod)\.rs'
COV_MIN     := 99

# cargo-llvm-cov needs llvm-tools. Homebrew's Rust ships none, so when the brew
# `llvm` keg has them, point the tool there; otherwise fall back to whatever's on
# PATH (rustup's llvm-tools-preview, as CI uses). Resolves to an env prefix or "".
BREW_LLVM := $(shell brew --prefix llvm 2>/dev/null)/bin
LLVM_ENV  := $(if $(wildcard $(BREW_LLVM)/llvm-cov),LLVM_COV="$(BREW_LLVM)/llvm-cov" LLVM_PROFDATA="$(BREW_LLVM)/llvm-profdata",)

.DEFAULT_GOAL := install
.PHONY: install run diag fmt lint test coverage cov-html check clean help

install: ## Build the release binary + symlink `netpeek` into ~/.bin
	cargo build --release --locked
	@mkdir -p "$(INSTALL_DIR)"
	@ln -sf "$(CURDIR)/$(TARGET)" "$(INSTALL_DIR)/$(BINARY)"
	@echo "installed $(TARGET) ($$(du -h "$(TARGET)" | cut -f1 | tr -d ' '))"
	@echo "         launcher: $(INSTALL_DIR)/$(BINARY) — ensure ~/.bin is on your PATH"

run: ## Build + run the TUI (debug); pass flags with ARGS="--once"
	cargo run -- $(ARGS)

diag: ## Connectivity / permission check (cargo run -- --diag)
	cargo run -- --diag

fmt: ## Format the source in place (rustfmt)
	cargo fmt

lint: ## rustfmt --check + clippy (warnings are errors)
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

test: ## Run the unit test suite (no root, no network)
	cargo test

coverage: cargo-llvm-cov ## Coverage over the pure core; fails under COV_MIN% lines
	$(LLVM_ENV) cargo llvm-cov $(COV_EXCLUDE) --summary-only --fail-under-lines $(COV_MIN)

cov-html: cargo-llvm-cov ## Generate + open an HTML coverage report
	$(LLVM_ENV) cargo llvm-cov $(COV_EXCLUDE) --html
	@open target/llvm-cov/html/index.html 2>/dev/null || true

check: lint test coverage ## Everything CI runs: lint + tests + coverage gate

clean: ## Remove build artifacts and the launcher
	cargo clean
	@rm -f "$(INSTALL_DIR)/$(BINARY)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

# Guard: a clear message instead of cargo's "no such subcommand" when the
# coverage tooling is missing. Not a real file, never up to date.
.PHONY: cargo-llvm-cov
cargo-llvm-cov:
	@command -v cargo-llvm-cov >/dev/null || { \
		echo "cargo-llvm-cov not found — install it with:"; \
		echo "    cargo install cargo-llvm-cov"; exit 1; }
