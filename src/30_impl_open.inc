#ifdef BISCUITS_IMPLEMENTATION

/* The entire libc surface of this library. Invariant 5.
 *
 * memcpy/memcmp/memset only: no stdio, no locale-sensitive string handling,
 * no allocation, no floating point. This is what makes the header usable in
 * a kernel module, a WASM sandbox or a bare-metal firmware without a shim. */
#include <string.h>
