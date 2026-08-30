# Conformance harness

The Biscuit specification ships 38 sample tokens with the authorization result
a correct implementation must produce. `run.py` drives that suite through a
**shim** — a small program in any language that speaks the protocol below.

The runner is implementation-agnostic on purpose. Writing a shim for another
Biscuit library is an afternoon's work, and it is the only honest way to
compare implementations: same input, same expected output, same score.

```sh
make conformance                              # score biscuits.h
tests/conformance/run.py --shim ./other_shim  # score anything else
```

## Why tiers

An implementation under construction scores on what it can already do. The
four tiers run in dependency order:

| Tier | Question |
|---|---|
| `decode` | Does the token parse, and does parsing fail exactly when it should? |
| `revocation_ids` | Are the per-block revocation identifiers byte-identical? |
| `blocks` | Does the decoded Datalog print back to the expected source? |
| `authorize` | Is the authorization decision — and the reason for it — correct? |

A shim declares which tiers it supports; the runner skips the rest rather than
failing them. `decode` and `revocation_ids` between them prove the protobuf
decoder, the symbol table and the signature chain are right long before the
Datalog engine exists, which is exactly when that feedback is most useful.

The `blocks` tier deserves a note: `samples.json` records the expected
pretty-printed Datalog of every block. Decoding a token and printing it back
is therefore a complete round-trip check on the wire decoder, the symbol table
and the term model, for free. It is the cheapest high-signal test in the
suite.

## Protocol

A shim is any executable answering two invocations. It writes one JSON object
to stdout and exits 0. **A rejected token is a result, not a failure**: exit
non-zero only when the shim itself malfunctions.

### Capability probe

```
shim --capabilities
```

```json
{"capabilities": ["decode", "revocation_ids", "blocks", "authorize"]}
```

Declare a tier only once it works. An undeclared tier is skipped; a declared
one that misbehaves is a failure.

### Evaluation

```
shim --token FILE --root-key HEX --authorizer-stdin  < authorizer.datalog
```

The root key is the suite's `root_public_key`, hex-encoded, Ed25519. The
authorizer's Datalog source arrives on stdin. A shim must read stdin to
completion even when it ignores it.

```json
{
  "decode": "ok",
  "revocation_ids": ["6a8f90da…", "…"],
  "blocks": ["right(\"file1\", \"read\");\n", "check if …;\n"],
  "result": {"ok": false, "kind": "unauthorized",
             "failed_checks": ["check if resource($0), right($0, \"read\")"]}
}
```

Fields belonging to undeclared tiers may be omitted. On a decode failure,
report `{"decode": {"error": "…"}}` and omit the rest.

### Result vocabulary

`result` is `{"ok": true, "policy": <index of the matching allow policy>}`, or
`{"ok": false, "kind": "<kind>"}` with one of:

| Kind | Meaning |
|---|---|
| `format` | The token is not well-formed: bad protobuf, bad key or signature encoding. |
| `signature` | Well-formed, but the signature chain does not verify against the root key. |
| `unauthorized` | Verified, but a check failed or no allow policy matched. Include `failed_checks`. |
| `invalid_block_rule` | A block contains a rule with unbound variables. |
| `no_matching_policy` | Every check passed but no policy matched. |
| `overflow` | An expression overflowed. Per the specification the expression fails; it must not wrap. |
| `shadowed_variable` | A closure parameter shadows a variable already in scope. |
| `invalid_type` | An operation was applied to an operand of the wrong type. |

`samples.json` records Rust's error enum. Forcing every implementation to
reproduce another language's struct shapes would test the wrong thing, so the
runner normalises both sides to this vocabulary, which is derived from the
specification. The mapping lives in `canonical_error()` in `run.py` — one
function, easy to audit and to argue with.

## Scope

The two ECDSA `secp256r1` cases (`test036`, `test037`) are out of scope for
biscuits.h 1.0 and fail the `decode` tier with an explicit unsupported error
rather than being silently mis-verified. They still run: a skipped test hides
a regression, an expected failure does not.

`test035_ffi.bc` calls `extern::test`. External calls are
implementation-defined -- the specification says what the opcode is, not what
any particular function means -- so `shim.c` registers that one, exactly as
the harness that produced the sample did. It belongs to the harness and not to
the library: a built-in `extern::test` would be `biscuits.h` inventing
semantics the specification declines to fix.
