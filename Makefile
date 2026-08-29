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

# clang-format output differs between major versions, so the version is pinned
# rather than "whatever the machine has": otherwise the formatting gate passes
# locally and fails in CI, which teaches everyone to ignore it.
CLANG_FORMAT_VERSION := 23.1.0
ifeq ($(shell command -v uvx >/dev/null 2>&1 && echo yes),yes)
  CLANG_FORMAT ?= uvx clang-format@$(CLANG_FORMAT_VERSION)
else
  CLANG_FORMAT ?= clang-format
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

# Sanitizers run at two optimisation levels. -O1 is the fast pass; -O0 exists
# because the optimiser can fold an over-read into a wider load, or delete it
# entirely, before the sanitizer ever sees it -- so a clean -O1 run is not
# evidence of a clean -O0 one.
SAN_COMMON := -g -fno-omit-frame-pointer -fno-sanitize-recover=all
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
SHIM_SRC    := tests/conformance/shim.c
# Everything written by hand, for the formatters and linters. The generated
# header is covered through the fragments it is built from.
ALL_C       := $(UNIT_SRCS) $(SHIM_SRC) tests/build/no_bundled_crypto.c

.PHONY: all
all: $(HEADER) test invariants

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
test: unit conformance portable unbundled

.PHONY: unit
unit: $(UNIT_BINS)
	@fail=0; for t in $(UNIT_BINS); do \
	    if ./$$t; then :; else fail=1; fi; \
	done; exit $$fail

# -MMD emits the header dependencies the compiler actually saw. Listing them
# by hand is how a test stops being rebuilt after its harness changes -- which
# happened here, and showed up only as an assertion count that quietly dropped.
$(BUILD)/unit_%: tests/unit/%.c $(HEADER) | $(BUILD)
	@$(CC) $(CFLAGS_DEBUG) -MMD -MF $(BUILD)/unit_$*.d $< -o $@

$(BUILD):
	@mkdir -p $(BUILD)

# ---------------------------------------------------------------------------
# Conformance
# ---------------------------------------------------------------------------
# The official suite, driven through a shim. See tests/conformance/README.md.
CONFORMANCE_SHIM := $(BUILD)/conformance_shim

$(CONFORMANCE_SHIM): $(SHIM_SRC) $(HEADER) | $(BUILD)
	@$(CC) $(CFLAGS_DEBUG) -MMD -MF $(BUILD)/shim.d $< -o $@

.PHONY: conformance
conformance: $(CONFORMANCE_SHIM)
	@$(PYTHON) tests/conformance/run.py --shim $(CONFORMANCE_SHIM)

# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------
.PHONY: asan
asan: $(HEADER) | $(BUILD)
	@fail=0; for o in -O0 -O1; do \
	  for s in $(UNIT_SRCS); do \
	    b=$(BUILD)/asan$$o_$$(basename $$s .c); \
	    $(CC) $(CFLAGS_ASAN) $$o $$s -o $$b || exit 1; \
	    ./$$b >/dev/null || fail=1; \
	  done; \
	done; exit $$fail

# MSan needs a real libclang_rt and a Linux target: it is unsupported on
# macOS/arm64. This target is Linux-only by design, not by oversight.
.PHONY: msan
msan: $(HEADER) | $(BUILD)
ifeq ($(UNAME_S),Linux)
	@fail=0; for s in $(UNIT_SRCS); do \
	    b=$(BUILD)/msan_$$(basename $$s .c); \
	    $(CLANG) $(CFLAGS_MSAN) -O1 $$s -o $$b || exit 1; \
	    ./$$b || fail=1; \
	done; exit $$fail
else
	@echo "  SKIP  msan: unsupported on $(UNAME_S) (Linux CI job covers it)"
endif

# The bring-your-own-crypto seam, compiled so the claim cannot decay.
.PHONY: unbundled
unbundled: $(HEADER) | $(BUILD)
	@$(CC) $(CFLAGS_DEBUG) tests/build/no_bundled_crypto.c \
	    -o $(BUILD)/no_bundled_crypto
	@./$(BUILD)/no_bundled_crypto

# The portable arithmetic path is dead code on every compiler we test with,
# which is exactly how it rots. This builds the whole suite against it.
.PHONY: portable
portable: $(HEADER) | $(BUILD)
	@fail=0; for s in $(UNIT_SRCS); do \
	    b=$(BUILD)/portable_$$(basename $$s .c); \
	    $(CC) $(CFLAGS_DEBUG) -DBS_NO_OVERFLOW_BUILTINS $$s -o $$b || exit 1; \
	    ./$$b >/dev/null || fail=1; \
	done; exit $$fail

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
.PHONY: tidy
tidy: $(HEADER)
	@$(CLANG_TIDY) --quiet $(ALL_C) -- $(CFLAGS_COMMON)

.PHONY: cppcheck
cppcheck: $(HEADER)
# --language=c is required: cppcheck does not recognise the .inc extension and
# would otherwise analyse zero files from src/ while still exiting 0.
#
# tests/build is excluded: it links the library against a stub verifier that
# always fails, so every status check downstream of it is constant and
# cppcheck reports the whole call chain as dead. The file exists to prove the
# seam compiles, not to be analysed.
	@cppcheck --std=c99 --enable=all --inconclusive --error-exitcode=1 \
	    --check-level=exhaustive --inline-suppr --language=c \
	    --suppress=missingIncludeSystem \
	    --suppress=unusedFunction \
	    --suppress=unmatchedSuppression \
	    --suppress=checkersReport \
	    -i tests/build \
	    $(INCLUDE) src tests

.PHONY: analyze
analyze: $(HEADER) | $(BUILD)
	@for f in $(ALL_C); do \
	    $(SCAN_BUILD) --status-bugs $(CC) $(CFLAGS_DEBUG) \
	        -c $$f -o $(BUILD)/$$(basename $$f .c).analyze.o || exit 1; \
	done

# The five invariants, checked on the compiled artifact rather than asserted
# in the README. See tools/check_invariants.py for what is and is not proved.
.PHONY: invariants
invariants: $(HEADER)
	@$(PYTHON) tools/check_invariants.py --cc $(CLANG)

.PHONY: lint
lint: check-amalgamation format-check tidy cppcheck invariants check-metrics

.PHONY: format
format:
	@$(CLANG_FORMAT) -i src/*.inc $(ALL_C)

.PHONY: format-check
format-check:
	@$(CLANG_FORMAT) --dry-run --Werror src/*.inc $(ALL_C)

# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------
# One measurement path, so the figure in README.md and the figure a developer
# sees are the same number. Plain -Os without the hardening flags: that is what
# a project embedding the header gets by default.
.PHONY: size
size: $(HEADER)
	@$(PYTHON) tools/metrics.py --cc $(CC)

# The headline numbers live in README.md and are regenerated, never typed.
.PHONY: metrics
metrics: $(HEADER)
	@$(PYTHON) tools/metrics.py --cc $(CC) --write

.PHONY: check-metrics
check-metrics: $(HEADER)
	@$(PYTHON) tools/metrics.py --cc $(CC) --check

-include $(wildcard $(BUILD)/*.d)

.PHONY: clean
clean:
	@rm -rf $(BUILD)
