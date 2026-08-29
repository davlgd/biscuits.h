#ifdef BISCUITS_IMPLEMENTATION

/* The entire libc surface of this library. Invariant 5.
 *
 * memcpy, memcmp and memset only: no stdio, no locale-sensitive string
 * handling, no allocation, no floating point. This is what makes the header
 * usable in a kernel module, a WASM sandbox or a bare-metal firmware without
 * a shim.
 *
 * The str* family is absent by construction, not by discipline: string
 * lengths come from sizeof at compile time, because a hand-written scan for
 * the terminator is recognised by the optimiser and rewritten into a call to
 * strlen. tools/check_invariants.py reads the undefined symbols off the
 * compiled object, which is the only place that shows. */
#include <string.h>
