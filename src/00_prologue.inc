/*
 * biscuits.h -- Biscuit authorization tokens in a single C99 header.
 *
 * Copyright 2026 davlgd
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 *
 * GENERATED FILE -- do not edit. Sources live in src/, assembled by
 * tools/amalgamate.py. Run `make amalgamate` after editing a fragment.
 *
 * ---------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------------
 * Drop this file in your project. In exactly one translation unit:
 *
 *     #define BISCUITS_IMPLEMENTATION
 *     #include "biscuits.h"
 *
 * Everywhere else, include it plain.
 *
 * ---------------------------------------------------------------------------
 * Design invariants
 * ---------------------------------------------------------------------------
 * These are not aspirations. Each one is enforced by a CI job, and breaking
 * one is a build failure, not a review comment. See docs/SAFETY.md.
 *
 *   1. No allocation.        The library never calls malloc. All memory comes
 *                            from a caller-provided buffer via bs_arena, which
 *                            bump-allocates and is never freed piecewise. This
 *                            makes use-after-free and double-free unreachable
 *                            by construction, not by discipline.
 *
 *   2. No recursion.         Nested structures (sets, arrays, maps, closures)
 *                            are walked with an explicit, bounded stack. Stack
 *                            depth is therefore a compile-time constant.
 *
 *   3. Bounded loops.        Every loop has a static or caller-supplied upper
 *                            bound. Datalog evaluation is governed by explicit
 *                            fact/iteration limits from the specification.
 *
 *   4. No pointer arithmetic. Byte ranges are bs_span values (pointer+length)
 *                            with checked accessors. Raw pointer arithmetic
 *                            appears only inside bs_span itself.
 *
 *   5. Minimal libc.       memcpy, memcmp and memset, and nothing else --
 *                            no stdio, no locale, no str* family, no floating
 *                            point. Some toolchains lower memset(p, 0, n) to
 *                            bzero, so an embedding target provides one or
 *                            the other. Checked on the compiled object by
 *                            tools/check_invariants.py, not asserted.
 *
 * Invariants 1-3 are the first three rules of the JPL "Power of Ten"; here
 * they are not imposed from outside, they are what the Biscuit threat model
 * demands anyway.
 *
 * ---------------------------------------------------------------------------
 * What this is not
 * ---------------------------------------------------------------------------
 * This library is memory-unsafe in the sense that any C library is: the
 * guarantees above remove whole bug classes but not all of them. The residual
 * risk is spatial safety, and it is addressed by evidence rather than by
 * assertion -- sanitizers, continuous fuzzing and bounded model checking of
 * the wire decoder. The numbers are in SECURITY.md. Read them before trusting
 * this with anything.
 */

#ifndef BISCUITS_H_INCLUDED
#define BISCUITS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
