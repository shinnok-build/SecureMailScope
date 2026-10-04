# -*- coding: utf-8 -*-
"""mailscope_analyze.py - grade your own capture with the same core as the corpus run.

    python3 mailscope_analyze.py capture.pcap                 # one file
    python3 mailscope_analyze.py captures/ --json out.json    # a directory, plus a JSON export
    python3 mailscope_analyze.py live.pcap --port 993         # implicit TLS on 993

Every session in the capture is parsed with the shipped engine (RFC 9293 sequence reassembly, TLS
record parsing with cross-record defragmentation, X.509 checks, the 15-rule policy library), so a
finding here is produced by exactly the code that produced the corpus results - no separate path.

Exit status: 0 = nothing above the severity threshold, 1 = findings at or above it (useful in CI).
"""
import argparse, glob, json, os, re, sys, warnings

warnings.filterwarnings("ignore", module=r"scapy\..*")   # cryptography deprecation notices
warnings.filterwarnings("ignore", category=DeprecationWarning)

_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(_HERE, "mailscope_bench.py")):        # authoring layout
    from mailscope_bench import read_pcap_native, analyse, POLICY
    from mailscope_guidance import REMEDIATION
else:                                                               # package layout (repo)
    from .engine import read_pcap_native, analyse, POLICY
    from .guidance import REMEDIATION

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
KNOWN_PORTS = (25, 110, 143, 465, 587, 993, 995)
TLS_NAMES = {769: "TLS 1.0", 770: "TLS 1.1", 771: "TLS 1.2", 772: "TLS 1.3"}


def port_from_name(path, fallback=25):
    """Captures are usually named after the endpoint (imaps-gmail-993.pcap) - use that first."""
    for p in re.findall(r"(\d{2,5})", os.path.basename(path)):
        if int(p) in KNOWN_PORTS:
            return int(p)
    return fallback


def grade(path, port):
    """Parse one capture and grade every mail session in it with the shipped engine."""
    segs = read_pcap_native(path)
    c2s = [(s, d) for (dirn, s, d) in segs if dirn]
    s2c = [(s, d) for (dirn, s, d) in segs if not dirn]
    if not c2s and not s2c:
        return None
    sess = analyse(c2s, s2c, dict(port=port))
    feats = sess.get("feats", {}) or {}
    out = {
        "file": os.path.basename(path),
        "port": port,
        "protocol": sess.get("proto", "?"),
        "tls": TLS_NAMES.get(feats.get("tls_version") or feats.get("ver") or sess.get("tls_version"),
                             feats.get("tls_version") or feats.get("ver") or sess.get("tls_version") or ""),
        "cipher": feats.get("cipher") or sess.get("cipher") or "",
        "chain_ok": feats.get("chain_ok"),
        "posture": sess.get("posture"),
        "findings": [],
    }
    for f in sess.get("findings", []):
        fid = f.fid
        out["findings"].append({
            "rule": fid,
            "severity": f.sev,
            "cvss": f.cvss,
            "title": f.title,
            "standard": POLICY.get(fid, ("", 0, "", ""))[3],
            "evidence": f.ev,
            "remediation": REMEDIATION.get(fid, ""),
        })
    out["findings"].sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    return out


def main():
    ap = argparse.ArgumentParser(description="Grade a mail capture with the SecureMailScope core.")
    ap.add_argument("path", help="a .pcap file or a directory of them")
    ap.add_argument("--port", type=int, default=None,
                    help="server port (25/110/143/465/587/993/995); default: read from the file name")
    ap.add_argument("--json", dest="json_out", help="write the full result as JSON to this path")
    ap.add_argument("--fail-on", default="HIGH", choices=["NONE", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    help="exit 1 when a finding at or above this severity is present (default HIGH)")
    a = ap.parse_args()

    files = ([a.path] if os.path.isfile(a.path)
             else sorted(glob.glob(os.path.join(a.path, "*.pcap")) + glob.glob(os.path.join(a.path, "*.pcapng"))))
    if not files:
        sys.exit(f"no captures found at {a.path}")

    results, worst = [], 4
    for path in files:
        port = a.port or port_from_name(path)
        r = grade(path, port)
        if r is None:
            continue
        results.append(r)
        for f in r["findings"]:
            worst = min(worst, SEV_ORDER.get(f["severity"], 9))

    print(f"{'file':38s} {'proto':6s} {'tls':8s} {'cipher':28s} {'chain':6s} {'posture':8s} findings")
    print("-" * 112)
    for r in results:
        chain = "ok" if r["chain_ok"] else ("no" if r["chain_ok"] is False else "-")
        print(f"{r['file'][:37]:38s} {str(r['protocol'])[:6]:6s} {str(r['tls'])[:8]:8s} "
              f"{str(r['cipher'])[:28]:28s} {chain:6s} {str(r['posture']):8s} "
              f"{len(r['findings'])}")
    print()
    for r in results:
        if not r["findings"]:
            continue
        print(f"{r['file']}  (posture {r['posture']})")
        for f in r["findings"]:
            print(f"  [{f['severity']:8s}] {f['rule']:3s} CVSS {f['cvss']}  {f['title']}")
            if f["standard"]:
                print(f"              standard: {f['standard']}")
            if f["evidence"]:
                print(f"              evidence: {f['evidence']}")
            if f["remediation"]:
                print(f"              fix:      {f['remediation']}")
        print()

    total = sum(len(r["findings"]) for r in results)
    print(f"{len(results)} session(s), {total} finding(s)")
    if a.json_out:
        json.dump({"sessions": results}, open(a.json_out, "w"), indent=1)
        print(f"JSON written to {a.json_out}")
    if a.fail_on != "NONE":
        limit = SEV_ORDER[a.fail_on]
        if any(SEV_ORDER.get(f["severity"], 9) <= limit for r in results for f in r["findings"]):
            sys.exit(1)


if __name__ == "__main__":
    main()
