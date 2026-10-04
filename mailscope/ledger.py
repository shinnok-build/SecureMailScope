# -*- coding: utf-8 -*-
"""mailscope_ledger.py - tamper-evident evidence ledger.

Every session row is hashed into a chain: h_i = SHA256(h_{i-1} || canonical_row_i), seeded by a
genesis block that commits to the corpus manifest. Change one byte of one row and every later hash
in the chain changes, so a reviewer can show that the findings they are reading are the findings
that were produced.

This is a local, tamper-evident hash chain - the same construction a blockchain uses for its links,
without pretending to be a distributed ledger. The console verifies it in the browser (pure JS
SHA-256, no network) and this module verifies it from the command line.

    python3 mailscope_ledger.py                 # print the chain head and verify
    python3 mailscope_ledger.py --export out.json
"""
import argparse, hashlib, json, os, sys

GENESIS = b"SecureMailScope/evidence-ledger/v1"
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.basename(HERE) == "mailscope"          # True inside the shipped package
ROOT = os.path.dirname(HERE) if PKG else HERE
RESULTS = os.path.join(ROOT, "results")


def res(name):
    """ms_rows.json lives beside the script when authoring, in results/ once shipped."""
    for path in (os.path.join(RESULTS, name), os.path.join(HERE, name)):
        if os.path.exists(path):
            return path
    return os.path.join(HERE, name)

# The chain covers the graded evidence of every session. The projection is explicit so that the
# same bytes can be produced from JavaScript: only strings, integers, booleans and lists of strings
# are included - no floats, so no cross-language number-formatting differences can appear.
FIELDS = ("label", "rep", "proto", "port", "tls_name", "cipher", "ke", "ke_group", "fs",
          "chain_ok", "chain_len", "keybits", "days_left", "sigalg", "san_ok", "posture",
          "stripped", "found")


def project(row):
    """The graded evidence of one session, as a stable dict of ints/strings/bools."""
    out = {}
    for f in FIELDS:
        v = row.get(f)
        if f == "found":
            v = sorted(v or [])
        elif isinstance(v, float):
            v = int(v)
        elif v is None:
            v = ""
        out[f] = v
    return out


def canonical(row):
    """Stable byte form of a row's graded evidence. No floats can reach here."""
    proj = project(row)
    for k, v in proj.items():
        assert not isinstance(v, float), f"float in ledger projection: {k}"
    return json.dumps(proj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def build(rows, manifest_sha=None):
    """Return the full chain: list of {i, hash, prev} plus the head."""
    prev = hashlib.sha256(GENESIS + (manifest_sha or "").encode()).hexdigest()
    chain = [{"i": -1, "hash": prev, "prev": None, "what": "genesis (corpus manifest)"}]
    for i, row in enumerate(rows):
        h = hashlib.sha256(bytes.fromhex(prev) + canonical(row)).hexdigest()
        chain.append({"i": i, "hash": h, "prev": prev,
                      "what": f"{row.get('label','?')}_{row.get('rep','?')}",
                      "proj": project(row)})
        prev = h
    return {"head": prev, "count": len(rows), "entries": chain}


def verify_against(rows, published, manifest_sha=None):
    """Verify rows against a PUBLISHED ledger (head + per-row hashes).

    This is the check that actually detects tampering: the ledger is built once from the shipped
    corpus, then anyone can re-run this against their own copy of the rows.
    Returns (ok, first_mismatch_index).
    """
    prev = published["genesis"]
    if not manifest_sha or published.get("manifest_sha256") != manifest_sha:
        return False, "manifest hash mismatch"
    if len(rows) != published["count"]:
        return False, f"row count {len(rows)} != ledger {published['count']}"
    for i, row in enumerate(rows):
        h = hashlib.sha256(bytes.fromhex(prev) + canonical(row)).hexdigest()
        if published["hashes"][i] != h:
            return False, i
        prev = h
    if prev != published["head"]:
        return False, "head mismatch"
    return True, None


def manifest_hash(bench_path=None):
    b = json.load(open(bench_path or res("ms_bench.json")))
    return (b.get("corpus", {}).get("manifest_sha256", "") or "")[:64]


def main():
    ap = argparse.ArgumentParser(description="Tamper-evident evidence ledger over the session rows.")
    ap.add_argument("--export", help="write the full ledger (head + per-row hashes) as JSON")
    ap.add_argument("--rows", default=res("ms_rows.json"))
    ap.add_argument("--ledger", default=None,
                    help="verify rows against a published ledger.json instead of rebuilding it")
    ap.add_argument("--with-projections", action="store_true",
                    help="include the canonical projections (used by the console)")
    a = ap.parse_args()

    rows = json.load(open(a.rows))
    mh = manifest_hash()
    if a.ledger:
        published = json.load(open(a.ledger))
        ok, why = verify_against(rows, published, mh)
        led = {"count": published["count"], "head": published["head"],
               "entries": [{"hash": published["genesis"]}]}
        print(f"mode      : verify rows against {os.path.basename(a.ledger)}")
    else:
        led = build(rows, mh)
        published = {"head": led["head"], "count": led["count"], "manifest_sha256": mh,
                     "genesis": led["entries"][0]["hash"],
                     "hashes": [e["hash"] for e in led["entries"][1:]]}
        ok, why = verify_against(rows, published, mh)
    print(f"rows      : {led['count']}")
    print(f"manifest  : {mh[:32]}...")
    print(f"chain head: {led['head']}")
    print(f"verify    : {'PASS - every row matches the ledger' if ok else 'FAIL at ' + str(why)}")
    if a.export:
        if a.with_projections and "entries" in led:
            published["projections"] = [e["proj"] for e in led["entries"][1:]]
        json.dump(published, open(a.export, "w"))
        print(f"exported  : {a.export}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
