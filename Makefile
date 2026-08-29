# biscuits.h -- build, test and analysis driver.
#
# Every target here is also a CI job. If it is not in this file, it does not
# run anywhere, and if it fails locally it fails in CI. There is no second
# source of truth.

.POSIX:
.SUFFIXES:

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
# Prefer a real LLVM over Apple clang: we need clang-tidy, scan-build,
# libFuzzer and llvm-cov, none of which ship with the Apple toolchain.
BREW_LLVM  := $(shell brew --prefix llvm 2>/dev/null)
ifneq ($(wildcard $(BREW_LLVM)/bin/clang),)
  LLVM_BIN := $(BREW_LLVM)/bin/
else
  LLVM_BIN :=
endif

CC        ?= cc
CLANG     := $(LLVM_BIN)clang
CLANG_TIDY:= $(LLVM_BIN)clang-tidy
SCAN_BUILD:= $(LLVM_BIN)scan-build
LLVM_COV  := $(LLVM_BIN)llvm-cov
LLVM_PROF := $(LLVM_BIN)llvm-profdata
PYTHON    ?= python3

UNAME_S   := $(shell uname -s)

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
# Rationale for the non-obvious ones:
#   -fwrapv            signed overflow becomes defined wrapping instead of UB,
#                      so the compiler cannot "optimise away" our own checks.
#                      Datalog arithmetic still uses __builtin_*_overflow to
#                      *detect* overflow, as the spec requires the expression
#                      to fail rather than wrap. See docs/SAFETY.md.
#   -fno-strict-aliasing  we decode wire formats; type-punning must be sane.
#   -Wconversion       catches the silent narrowing that turns a length check
#                      into a no-op. Noisy, and worth every line of it.
CSTD    := -std=c99
WARN    := -Wall -Wextra -Werror -pedantic \
           -Wshadow -Wconversion -Wsign-conversion -Wwrite-strings \
           -Wcast-qual -Wcast-align -Wvla -Wpointer-arith -Wundef \
           -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls \
           -Wswitch-enum -Wformat=2 -Wnull-dereference -Wstrict-overflow=2
SEMANT  := -fwrapv -fno-strict-aliasing
INCLUDE := -I. -Isrc

CFLAGS_COMMON := $(CSTD) $(WARN) $(SEMANT) $(INCLUDE)

# Release: hardened, but the hardening must never be load-bearing. The code is
# correct without it; these are a second line of defence.
HARDEN  := -fstack-protector-strong -ftrivial-auto-var-init=zero
ifeq ($(UNAME_S),Linux)
  HARDEN += -D_FORTIFY_SOURCE=3
endif
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O2 $(HARDEN)
CFLAGS_SIZE    := $(CFLAGS_COMMON) -Os $(HARDEN)
CFLAGS_DEBUG   := $(CFLAGS_COMMON) -O0 -g

SAN_COMMON := -O1 -g -fno-omit-frame-pointer -fno-sanitize-recover=all
CFLAGS_ASAN := $(CFLAGS_COMMON) $(SAN_COMMON) -fsanitize=address,undefined
CFLAGS_MSAN := $(CFLAGS_COMMON) $(SAN_COMMON) -fsanitize=memory \
               -fsanitize-memory-track-origins=2
CFLAGS_COV  := $(CFLAGS_COMMON) -O0 -g \
               -fprofile-instr-generate -fcoverage-mapping

BUILD := build

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
HEADER      := biscuits.h
SRC_PARTS   := $(shell $(PYTHON) tools/amalgamate.py --list 2>/dev/null)
UNIT_SRCS   := $(wildcard tests/unit/*.c)
UNIT_BINS   := $(patsubst tests/unit/%.c,$(BUILD)/unit_%,$(UNIT_SRCS))

.PHONY: all
all: $(HEADER) test

# ---------------------------------------------------------------------------
# Amalgamation
# ---------------------------------------------------------------------------
# We develop in src/*.inc and ship one file. CI enforces that the shipped file
# matches the sources, so the two can never drift.
$(HEADER): $(SRC_PARTS) tools/amalgamate.py
	@$(PYTHON) tools/amalgamate.py --out $@
	@echo "  AMALGAMATE  $@ ($$(wc -l < $@ | tr -d ' ') lines)"

.PHONY: amalgamate
amalgamate:
	@$(PYTHON) tools/amalgamate.py --out $(HEADER)
	@echo "  AMALGAMATE  $(HEADER) ($$(wc -l < $(HEADER) | tr -d ' ') lines)"

.PHONY: check-amalgamation
check-amalgamation:
	@$(PYTHON) tools/amalgamate.py --check $(HEADER)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
.PHONY: test
test: unit

.PHONY: unit
unit: $(UNIT_BINS)
	@fail=0; for t in $(UNIT_BINS); do \
	    if ./$$t; then :; else fail=1; fi; \
	done; exit $$fail

$(BUILD)/unit_%: tests/unit/%.c $(HEADER) | $(BUILD)
	@$(CC) $(CFLAGS_DEBUG) $< -o $@

$(BUILD):
	@mkdir -p $(BUILD)

# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------
.PHONY: asan
asan: $(HEADER) | $(BUILD)
	@fail=0; for s in $(UNIT_SRCS); do \
	    b=$(BUILD)/asan_$$(basename $$s .c); \
	    $(CC) $(CFLAGS_ASAN) $$s -o $$b || exit 1; \
	    ./$$b || fail=1; \
	done; exit $$fail

# MSan needs a real libclang_rt and a Linux target: it is unsupported on
# macOS/arm64. This target is Linux-only by design, not by oversight.
.PHONY: msan
msan: $(HEADER) | $(BUILD)
ifeq ($(UNAME_S),Linux)
	@fail=0; for s in $(UNIT_SRCS); do \
	    b=$(BUILD)/msan_$$(basename $$s .c); \
	    $(CLANG) $(CFLAGS_MSAN) $$s -o $$b || exit 1; \
	    ./$$b || fail=1; \
	done; exit $$fail
else
	@echo "  SKIP  msan: unsupported on $(UNAME_S) (Linux CI job covers it)"
endif

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
.PHONY: tidy
tidy: $(HEADER)
	@$(CLANG_TIDY) --quiet $(UNIT_SRCS) -- $(CFLAGS_COMMON)

.PHONY: cppcheck
cppcheck: $(HEADER)
	@cppcheck --std=c99 --enable=all --inconclusive --error-exitcode=1 \
	    --check-level=exhaustive --inline-suppr \
	    --suppress=missingIncludeSystem \
	    --suppress=unusedFunction \
	    --suppress=unmatchedSuppression \
	    --suppress=checkersReport \
	    $(INCLUDE) src tests

.PHONY: analyze
analyze: $(HEADER)
	@$(SCAN_BUILD) --status-bugs $(CC) $(CFLAGS_DEBUG) -c $(UNIT_SRCS) -o /dev/null

.PHONY: lint
lint: check-amalgamation format-check tidy cppcheck

.PHONY: format
format:
	@$(LLVM_BIN)clang-format -i src/*.inc tests/unit/*.c

.PHONY: format-check
format-check:
	@$(LLVM_BIN)clang-format --dry-run --Werror src/*.inc tests/unit/*.c

# ---------------------------------------------------------------------------
# Size report -- the headline number, so it is measured, not estimated.
# ---------------------------------------------------------------------------
.PHONY: size
size: $(HEADER) | $(BUILD)
	@echo '#define BISCUITS_IMPLEMENTATION' > $(BUILD)/size.c
	@echo '#include "biscuits.h"' >> $(BUILD)/size.c
	@$(CC) $(CFLAGS_SIZE) -c $(BUILD)/size.c -o $(BUILD)/size.o
	@printf "  header      %s lines\n" "$$(wc -l < $(HEADER) | tr -d ' ')"
	@printf "  object -Os  %s bytes\n" "$$(wc -c < $(BUILD)/size.o | tr -d ' ')"

.PHONY: clean
clean:
	@rm -rf $(BUILD)
