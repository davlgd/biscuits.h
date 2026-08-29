# Fuzzing

```sh
make fuzz                        # build the targets
make fuzz-smoke                  # 20 seconds each, seeded, as a gate
make fuzz-smoke FUZZ_SECONDS=600 # longer
build/fuzz_parse build/corpus -dict=fuzz/biscuits.dict   # run one by hand
```

Fuzzing is the load-bearing evidence in this project. The argument in
[`SECURITY.md`](../SECURITY.md) is that the arena removes temporal memory
safety as a bug class and that what remains — spatial safety and integer
overflow — is answered by evidence rather than by assertion. This directory is
that evidence, or it is nothing.

## The targets

| Target | Reaches |
|---|---|
| `fuzz_parse` | The container decoder: protobuf, lengths, key and signature widths. Every other path is downstream of a token that parsed. |
| `fuzz_print` | The deepest code: symbol tables, the term decoder with its nesting bound, the expression opcode machine, the rule and check printers. |
| `fuzz_verify` | The signature chain, including the payload construction and the proof check. |

## Two decisions worth knowing about

**Assertions are on.** `BS_ASSERT` compiles to nothing in a release build —
it states facts the code has already established, and a shipped library should
not pay to restate them. Under the fuzzer that is exactly backwards: each of
those documented beliefs becomes an oracle, and the fuzzer's job is to find
the input that falsifies one. A fuzzer looking only for segfaults finds a
fraction of what is there.

Each target adds its own oracles on top. `fuzz_parse` asserts that a token
which parsed has consistent block counts, signature widths and revocation
identifiers, and that the authority block never carries an external signature.
`fuzz_verify` asserts that a token which *verified* still satisfies every
structural invariant, and that verifying the same bytes twice gives the same
answer — a difference would mean state leaking between calls.

**The seed corpus is the specification's own sample tokens.** Starting from
valid, signed tokens is what gets the fuzzer past the signature check and into
the Datalog; starting from random bytes would spend the entire budget in the
first hundred lines of the decoder. `make fuzz-smoke` copies them into
`build/corpus` automatically.

The dictionary matters for the same reason. Protobuf is tag-length-value, and
a mutation that lands a valid tag byte is worth far more than one that lands a
random byte. `biscuits.dict` carries every field tag in the schema, both key
algorithm encodings, and the two lengths that matter — 32 and 64.

## What this is not

A twenty-second run per target on every commit is a regression gate, not a
security argument. It catches a crash reachable from a sample token before it
is committed, which is worth having, and it proves nothing about the inputs
nobody has thought of yet.

The actual argument requires continuous fuzzing, and that means OSS-Fuzz.
Until this repository is public and enrolled, the row in `SECURITY.md` stays
marked as not started, because it is.
