#!/usr/bin/env python3
"""Run the official Biscuit conformance suite against any implementation.

The suite ships with the specification: 38 binary tokens and, for each, the
authorization result a correct implementation must produce. This runner drives
it through a *shim* -- a small program that speaks the protocol described in
tests/conformance/README.md. The shim is the only implementation-specific
part, so the same runner scores biscuits.h, biscuit-rust, or anything else.

Scoring is tiered. An implementation that decodes tokens but cannot yet
authorize them scores on the decode and signature tiers rather than reporting
a flat zero, which is what makes this usable as a development signal instead
of a release gate that only turns green on the last day.

  run.py --shim build/conformance_shim
  run.py --shim ./my_shim --filter expressions --verbose
"""

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "vendor" / "biscuit-spec" / "samples" / "current"

# Tiers, in dependency order: a failure at one tier makes the later ones
# meaningless for that case, so they are reported as blocked rather than
# failed. Only a tier the shim declares support for is scored at all.
TIERS = ("decode", "revocation_ids", "blocks", "authorize")

# The sample file records Rust's error enum. A C implementation should not be
# forced to reproduce another language's struct shapes, so both sides speak
# this canonical vocabulary instead. It is derived from the specification, not
# from any implementation.
def canonical_error(err: dict) -> str:
    """Map one `result.Err` object from samples.json to a canonical kind."""
    if not isinstance(err, dict) or len(err) != 1:
        return "unknown"
    family, body = next(iter(err.items()))
    inner = next(iter(body)) if isinstance(body, dict) and body else body

    return {
        ("Format", "Signature"): "signature",
        ("Format", "InvalidSignatureSize"): "format",
        ("Format", "BlockSignatureDeserializationError"): "format",
        ("Format", "BlockDeserializationError"): "format",
        ("Format", "DeserializationError"): "format",
        ("FailedLogic", "Unauthorized"): "unauthorized",
        ("FailedLogic", "InvalidBlockRule"): "invalid_block_rule",
        ("FailedLogic", "NoMatchingPolicy"): "no_matching_policy",
        ("Execution", "Overflow"): "overflow",
        ("Execution", "ShadowedVariable"): "shadowed_variable",
        ("Execution", "InvalidType"): "invalid_type",
        ("Execution", "Timeout"): "timeout",
        ("Execution", "TooManyFacts"): "too_many_facts",
        ("Execution", "TooManyIterations"): "too_many_iterations",
    }.get((family, inner), f"{family}/{inner}".lower())


def expected_outcome(validation: dict) -> dict:
    """Reduce an expected result to what an implementation must agree on."""
    result = validation["result"]
    if "Ok" in result:
        return {"ok": True, "policy": result["Ok"]}

    err = result["Err"]
    out = {"ok": False, "kind": canonical_error(err)}
    # For an unauthorized token, which checks failed is the interesting part:
    # agreeing on "denied" while disagreeing on why means the Datalog engine
    # is wrong in a way that will bite on a token nobody tested.
    body = err.get("FailedLogic", {})
    if isinstance(body, dict) and "Unauthorized" in body:
        checks = body["Unauthorized"].get("checks", [])
        out["failed_checks"] = sorted(
            rule
            for c in checks
            for kind in c.values()
            if isinstance(kind, dict)
            for key, rule in kind.items()
            if key == "rule"
        )
    return out


class Shim:
    """A subprocess that answers the conformance protocol."""

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.capabilities = frozenset()

    def probe(self) -> None:
        out = self._run(["--capabilities"])
        self.capabilities = frozenset(out.get("capabilities", []))

    def evaluate(self, token: pathlib.Path, root_key: str,
                 authorizer: str) -> dict:
        return self._run(
            ["--token", str(token), "--root-key", root_key,
             "--authorizer-stdin"],
            stdin=authorizer,
        )

    def _run(self, args, stdin: str = "") -> dict:
        try:
            proc = subprocess.run(
                [str(self.path), *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            sys.exit(f"conformance: no shim at {self.path} (run 'make conformance')")
        except subprocess.TimeoutExpired:
            return {"_shim_error": "timeout"}

        if proc.returncode != 0:
            return {"_shim_error": f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"}
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return {"_shim_error": f"invalid JSON: {exc}"}


def compare(tier: str, expected, actual) -> tuple:
    """Return (passed, detail). detail is only meaningful on failure."""
    if tier == "decode":
        want_ok = expected["ok"] or expected.get("kind") not in ("format", "signature")
        got_ok = actual.get("decode") == "ok"
        if want_ok != got_ok:
            return False, f"expected decode {'ok' if want_ok else 'failure'}, got {actual.get('decode')!r}"
        return True, ""

    if tier == "revocation_ids":
        want = [i.lower() for i in expected["revocation_ids"]]
        got = [str(i).lower() for i in actual.get("revocation_ids", [])]
        if want != got:
            return False, f"expected {want}, got {got}"
        return True, ""

    if tier == "blocks":
        want = expected["blocks"]
        got = actual.get("blocks", [])
        if len(want) != len(got):
            return False, f"expected {len(want)} blocks, got {len(got)}"
        for i, (w, g) in enumerate(zip(want, got)):
            if w.strip() != str(g).strip():
                return False, f"block {i} datalog differs:\n  want: {w.strip()!r}\n  got:  {g.strip()!r}"
        return True, ""

    if tier == "authorize":
        want, got = expected["outcome"], actual.get("result")
        if not isinstance(got, dict):
            return False, f"no result reported (got {got!r})"
        if want["ok"] != bool(got.get("ok")):
            return False, f"expected ok={want['ok']}, got ok={got.get('ok')}"
        if want["ok"]:
            if want["policy"] != got.get("policy"):
                return False, f"expected policy {want['policy']}, got {got.get('policy')}"
        else:
            if want["kind"] != got.get("kind"):
                return False, f"expected error {want['kind']!r}, got {got.get('kind')!r}"
            if "failed_checks" in want:
                g = sorted(str(c) for c in got.get("failed_checks", []))
                if want["failed_checks"] != g:
                    return False, f"failed checks differ:\n  want: {want['failed_checks']}\n  got:  {g}"
        return True, ""

    raise AssertionError(f"unknown tier {tier}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--shim", default=str(ROOT / "build" / "conformance_shim"))
    ap.add_argument("--filter", default="", help="substring match on the test title or filename")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json", metavar="FILE", help="write a machine-readable report")
    args = ap.parse_args()

    samples_file = SAMPLES / "samples.json"
    if not samples_file.is_file():
        sys.exit(
            "conformance: specification samples not found.\n"
            "  Run: git submodule update --init --depth 1"
        )
    suite = json.loads(samples_file.read_text())
    root_key = suite["root_public_key"]

    shim = Shim(pathlib.Path(args.shim))
    shim.probe()
    if not shim.capabilities:
        print(f"# shim {args.shim} declares no capabilities; everything is skipped")

    cases, report = [], []
    for tc in suite["testcases"]:
        if args.filter and args.filter not in tc["title"] and args.filter not in tc["filename"]:
            continue
        for name, validation in tc["validations"].items():
            cases.append((tc, name, validation))

    n = 0
    tally = {t: [0, 0, 0] for t in TIERS}  # pass, fail, skip
    for tc, vname, validation in cases:
        token = SAMPLES / tc["filename"]
        actual = shim.evaluate(token, root_key, validation["authorizer_code"])
        label = f"{tc['filename']}[{vname or 'default'}]"

        expected = {
            "outcome": expected_outcome(validation),
            "revocation_ids": validation["revocation_ids"],
            "blocks": [b.get("code", "") for b in tc["token"]],
        }
        expected.update(expected["outcome"])

        if "_shim_error" in actual:
            n += 1
            print(f"not ok {n} - {label} # shim error: {actual['_shim_error']}")
            for t in TIERS:
                tally[t][1] += 1
            continue

        for tier in TIERS:
            n += 1
            if tier not in shim.capabilities:
                tally[tier][2] += 1
                print(f"ok {n} - {label} {tier} # SKIP not implemented")
                continue
            passed, detail = compare(tier, expected, actual)
            tally[tier][0 if passed else 1] += 1
            print(f"{'ok' if passed else 'not ok'} {n} - {label} {tier}")
            if not passed:
                for line in detail.splitlines():
                    print(f"#   {line}")
            report.append({"case": label, "tier": tier,
                           "passed": passed, "detail": detail})

    print(f"1..{n}")
    print("#")
    print("# tier              pass  fail  skip")
    for t in TIERS:
        p, f, s = tally[t]
        print(f"# {t:<17} {p:>4}  {f:>4}  {s:>4}")

    full = sum(1 for tc in suite["testcases"]) if not args.filter else len(
        {c[0]["filename"] for c in cases})
    scored = tally["authorize"][0]
    print(f"#\n# conformance: {scored}/{len(cases)} validations authorized correctly "
          f"across {full} sample tokens")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"tally": tally, "results": report}, indent=2))

    return 1 if any(tally[t][1] for t in TIERS) else 0


if __name__ == "__main__":
    sys.exit(main())
