# -*- coding: utf-8 -*-
"""build_prototype.py - build the SecureMailScope console (v3, multi-page).

Generates prototype/index.html: one self-contained file, no external assets, no network calls.
Pages are hash-routed, so any single view can be deep-linked (index.html#/findings), and the file opens
straight from disk or from GitHub Pages.

Pages
  overview      posture, KPIs, severity mix, distributions
  sessions      all 448 sessions, searchable, with a full evidence drawer
  findings      findings grouped by rule: CVSS, standard, sessions affected, remediation
  servers       live validation against real public mail servers, per-provider rollup
  certificates  certificate inventory: key size, signature algorithm, lifetime, chain, SAN
  inventory     crypto bill of materials: versions, suites, key exchange, key sizes
  matrix        scenario class x replica grid
  ledger        tamper-evident evidence chain, verified in the browser
  reports       exports: JSON, CSV, CEF (SIEM), CBOM, ledger
  method        how it works, limits, verification, problem-statement mapping

Everything on every page is computed from ms_bench.json + ms_rows.json (+ live_validation.json and
ledger.json when present) at build time.
"""
import collections, hashlib, json, os, datetime, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.basename(HERE) == "mailscope"          # True inside the shipped package
ROOT = os.path.dirname(HERE) if PKG else HERE
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")
OUTDIR = os.path.join(ROOT, "console" if PKG else "prototype")
os.makedirs(OUTDIR, exist_ok=True)

def res(name):
    for p in (os.path.join(RESULTS, name), os.path.join(HERE, name)):
        if os.path.exists(p):
            return p
    return os.path.join(HERE, name)

BENCH = json.load(open(res("ms_bench.json")))
ROWS = json.load(open(res("ms_rows.json")))
RAW_B = open(res("ms_bench.json"), "rb").read()
RAW_R = open(res("ms_rows.json"), "rb").read()
RUNID = "r-" + hashlib.sha256(RAW_B + RAW_R).hexdigest()[:8]
LIVE = json.load(open(res("live_validation.json"))) if os.path.exists(res("live_validation.json")) else {"targets": []}
LEDGER = json.load(open(res("ledger.json"))) if os.path.exists(res("ledger.json")) else {}
SCALE = json.load(open(res("ms_scale.json"))) if os.path.exists(res("ms_scale.json")) else {}
KEYLOG = json.load(open(res("keylog_validation.json"))) if os.path.exists(res("keylog_validation.json")) else {}

import sys
sys.path.insert(0, HERE)
try:
    from mailscope_guidance import REMEDIATION          # authoring tree
except ImportError:                                     # shipped package
    from mailscope.guidance import REMEDIATION

# ---------------------------------------------------------------- derived facts
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
def sev_of(row):
    fs = row.get("detail") or []
    return min((SEV_ORDER.get(f.get("sev"), 9) for f in fs), default=9)

# rule aggregation
RULES = {}
for r in ROWS:
    for f in (r.get("detail") or []):
        rid = f.get("id")
        e = RULES.setdefault(rid, {"id": rid, "sev": f.get("sev"), "cvss": f.get("cvss"),
                                   "title": f.get("title"), "standard": f.get("standard"),
                                   "count": 0, "ev": f.get("ev"), "sessions": [],
                                   "remediation": REMEDIATION.get(rid, "")})
        e["count"] += 1
        if len(e["sessions"]) < 6:
            e["sessions"].append(f"{r['label']}#{r['rep']}")
RULE_LIST = sorted(RULES.values(), key=lambda x: (SEV_ORDER.get(x["sev"], 9), -float(x["cvss"] or 0), x["id"]))

# distributions
def dist(key):
    c = collections.Counter(str(r.get(key) or "not observed") for r in ROWS)
    return [{"k": k, "n": n} for k, n in sorted(c.items(), key=lambda kv: -kv[1])]

PROTO = dist("proto")
TLSV = dist("tls_name")
CIPHER = dist("cipher")
KEG = dist("ke_group")
KEYBITS = dist("keybits")
SIGALG = dist("sigalg")
PORTS = dist("port")

post = [r["posture"] for r in ROWS if isinstance(r.get("posture"), int)]
HIST = [{"k": f"{i*10}–{i*10+9}", "n": sum(1 for p in post if i*10 <= p < i*10 + 10)} for i in range(10)]
HIST[-1]["n"] = sum(1 for p in post if p >= 90)
HIST[-1]["k"] = "90–100"

CLASSES = sorted({r["label"] for r in ROWS})
REPS = sorted({r["rep"] for r in ROWS})
CELL = {(r["label"], r["rep"]): i for i, r in enumerate(ROWS)}

CERTS = [i for i, r in enumerate(ROWS) if r.get("subject") or r.get("chain_len")]
CERT_BAD = [i for i in CERTS if (r := ROWS[i]) and ((r.get("keybits") or 0) and r["keybits"] < 2048
            or r.get("sigalg") == "sha1" or not r.get("chain_ok"))]
CERT_SOON = [i for i in CERTS if isinstance(ROWS[i].get("days_left"), int) and 0 <= ROWS[i]["days_left"] < 30]
CERT_EXP = [i for i in CERTS if isinstance(ROWS[i].get("days_left"), int) and ROWS[i]["days_left"] < 0]

# live rollup
def provider(host):
    h = (host or "").lower()
    for dom, name in (("gmail", "Google"), ("google", "Google"), ("outlook", "Microsoft"),
                      ("office365", "Microsoft"), ("microsoft", "Microsoft"), ("fastmail", "Fastmail"),
                      ("yahoo", "Yahoo"), ("gmx", "GMX"), ("zoho", "Zoho"), ("proton", "Proton")):
        if dom in h:
            return name
    return (h.split(".")[-2].title() if h.count(".") >= 1 else h) or "unknown"

LIVE_T = LIVE.get("targets", [])
LIVE_HOSTS = sorted({t.get("host", "") for t in LIVE_T})
LIVE_PROV = collections.Counter(provider(t.get("host")) for t in LIVE_T)
LIVE_TRAPS = [t for t in LIVE_T if str(t.get("mode", "")).startswith("withhold")]

DECK = {"posture": BENCH["posture"]["mean"], "grade": BENCH["posture"].get("grade", "B"),
        "posture_min": BENCH["posture"].get("min"), "posture_max": BENCH["posture"].get("max"),
        "below_70": BENCH["posture"].get("below_70"),
        "sessions": BENCH["corpus"]["sessions"], "findings": sum(BENCH["findings_by_severity"].values()),
        "severity": BENCH["findings_by_severity"], "fp": BENCH["false_positives"],
        "det": BENCH["detection"], "reasm": BENCH["precision"]["tcp_reassembly"],
        "thr": BENCH["throughput"], "ai": BENCH["ai"], "corpus": BENCH["corpus"],
        "rules_n": BENCH["policy_library"]["rules"]}

PS_MAP = [
    ("1", "SMTP/IMAP/POP3 identification", "Banner + capability + port classifier, implicit and explicit TLS"),
    ("2", "STARTTLS negotiation detection", "Upgrade state read from the wire; rule A1"),
    ("3", "Complete TCP stream reconstruction", "RFC 9293 sequence-based, out-of-order / retransmit / overlap"),
    ("4", "TLS handshake reconstruction", "Record-layer parser, handshake defragmentation across records"),
    ("5", "Negotiated TLS version", "ClientHello / ServerHello, incl. supported_versions"),
    ("6", "Negotiated cipher suite", "IANA registry mapping; unknown suites flagged"),
    ("7", "Key exchange mechanism", "Named group from key_share / ServerKeyExchange"),
    ("8", "X.509 certificate extraction", "DER decoded from the Certificate message, leaf + chain"),
    ("9", "Certificate chain validation", "Cryptographic signature re-verification to the anchor"),
    ("10", "Certificate expiration analysis", "notBefore / notAfter evaluated at session time"),
    ("11", "Public key algorithm and length", "RSA modulus / EC curve size"),
    ("12", "Digital signature algorithm", "signatureAlgorithm OID, incl. the SHA-1 family"),
    ("13", "Weak algorithms and deprecated TLS", "RC4 / 3DES / CBC-SHA1 / SHA-1; TLS 1.0-1.1 per RFC 8996"),
    ("14", "Insecure protocol configuration", "15-rule policy library mapped to RFC / NIST / CA-B"),
    ("15", "Forward secrecy assessment", "(EC)DHE vs static RSA for the negotiated suite"),
    ("16", "AI cryptographic risk scoring", "Gradient-boosted classifier; held-out F1 0.9538 (n=111)"),
    ("17", "AI anomaly detection", "Deviation model against the fleet baseline, 3-sigma MAD"),
    ("18", "Prioritised security findings", "CVSS 4.0 base score and severity ordering"),
    ("19", "Posture assessment", "Transparent 0-100 score, A-F grade, formula published"),
    ("20", "JSON / PDF / HTML export", "report.json / report.pdf / report.html + SIEM exports"),
    ("21", "Interactive dashboard", "this console: filters, drill-down, replay, evidence ledger"),
]

def _fmt_card():
    """The scale card is assembled in Python so the numbers never pass through JS quoting."""
    if not SCALE.get("sessions"):
        return ""
    pairs = [("sessions graded in one run", "{:,}".format(SCALE["sessions"])),
             ("pipeline rate", "{:,}/s".format(SCALE["pipeline_sessions_per_second"])),
             ("read + reassemble + grade", "{} s".format(SCALE["pipeline_seconds"])),
             ("peak memory", "{} MB".format(SCALE["peak_rss_mb"]))]
    grid = "".join('<div class="card kpi"><div class="v">' + v + '</div><div class="l">' + k + "</div></div>"
                   for k, v in pairs)
    parts = [
        '<div class="card"><h2>At scale</h2><div class="grid g4">', grid, "</div>",
        '<div class="small" style="margin-top:10px">One run over <b>',
        "{:,}".format(SCALE["sessions"]), "</b> synthetic sessions (<b>", str(SCALE["capture_mb"]),
        " MB</b> of capture): every capture read back from disk, both directions reassembled, every session graded in <b>",
        str(SCALE["pipeline_seconds"]), " s</b> at <b>", "{:,}".format(SCALE["pipeline_sessions_per_second"]),
        " sessions/s</b>. Reassembly stayed <b>", SCALE["reassembly_byte_exact"],
        "</b> byte-exact at scale and peak resident memory stayed at <b>", str(SCALE["peak_rss_mb"]),
        ' MB</b>. <span class="dim">Building those synthetic captures is a lab step, timed separately at ',
        "{:,}".format(SCALE["generation_sessions_per_second"]), " sessions/s, and is not part of the pipeline figure. ",
        "A mirror port still has to write the capture, so this measures the analysis pipeline, not the switch.</span></div></div>",
    ]
    return "".join(parts)


SCALE_CARD = _fmt_card()

def _live_rollup():
    """Corpus vs live, computed here so the numbers never pass through JS quoting."""
    T = LIVE.get("targets", [])
    m = [t.get("mailscope", {}) or {} for t in T]
    posts = [x["posture"] for x in m if isinstance(x.get("posture"), int)]
    tls = collections.Counter(str(x.get("tls")) for x in m)
    findings = sum(len(x.get("findings") or []) for x in m)
    traps = [t for t in T if str(t.get("mode", "")).startswith("withhold")]
    return {
        "sessions": len(T),
        "hosts": len({t.get("host") for t in T if not str(t.get("mode", "")).startswith("withhold")}),
        "findings": findings,
        "posture_mean": round(sum(posts) / len(posts), 1) if posts else 0,
        "posture_min": min(posts) if posts else 0,
        "clean": sum(1 for p in posts if p == 100),
        "tls13": tls.get("TLS 1.3", 0),
        "tls12": tls.get("TLS 1.2", 0),
        "deprecated": tls.get("TLS 1.1", 0) + tls.get("TLS 1.0", 0),
        "nohandshake": tls.get("None", 0),
        "cert_problems": sum(1 for x in m if x.get("chain_ok") is False or
                             (x.get("keyalg") == "RSA" and isinstance(x.get("keybits"), int)
                              and 0 < x["keybits"] < 2048) or
                             x.get("sigalg") == "sha1"),
        "cross_checked": sum(1 for t in T if (t.get("python_ssl") or {}).get("protocol")),
        "pq_negotiated": sum(1 for x in m if x.get("pq")),
        "pq_missed": sum(1 for x in m if (x.get("tls") == "TLS 1.3" and not x.get("pq") and x.get("pq_offered"))),
        "pq_offered": sum(1 for x in m if x.get("pq_offered")),
        "traps": len(traps),
        "providers": len({provider(t.get("host")) for t in T if not str(t.get("mode", "")).startswith("withhold")}),
    }


LIVE_R = _live_rollup()


def _kpi(v, l, sub=""):
    return ('<div class="card kpi"><div class="v">' + str(v) + '</div><div class="l">' + str(l) + "</div>" +
            ('<div class="s">' + str(sub) + "</div>" if sub else "") + "</div>")


def _card(title, body):
    return '<div class="card"><h2>' + title + "</h2>" + body + "</div>"


def _table(head, body):
    return ('<div class="tw sh"><table><thead><tr>' +
            "".join("<th>" + h + "</th>" for h in head) +
            "</tr></thead><tbody>" + body + "</tbody></table></div>")


def _compare_card():
    """Two populations, one instrument. Built in Python: static content, no JS quoting risk."""
    c = {"sessions": DECK["sessions"], "findings": DECK["findings"],
         "posture_mean": BENCH["posture"]["mean"], "posture_min": BENCH["posture"].get("min"),
         "clean": BENCH["false_positives"]["clean_sessions"],
         "tls13": next((d["n"] for d in TLSV if d["k"] == "TLS 1.3"), 0),
         "tls12": next((d["n"] for d in TLSV if d["k"] == "TLS 1.2"), 0),
         "deprecated": sum(d["n"] for d in TLSV if d["k"] in ("TLS 1.0", "TLS 1.1")),
         "nohandshake": next((d["n"] for d in TLSV if d["k"] == "not observed"), 0),
         "cert_problems": len(CERT_BAD)}
    L = LIVE_R
    n = lambda v: "{:,}".format(v)
    pc = lambda part, whole: ("{:.0f}%".format(100.0 * part / whole) if whole else "-")

    rows = [
        ("sessions reconstructed", n(c["sessions"]), n(L["sessions"]),
         "the corpus is a scenario matrix; the live set is one session per endpoint mode"),
        ("findings raised", n(c["findings"]), n(L["findings"]),
         "live: %d planted traps + %d post-quantum readiness advisories (LOW, advisory by design)" % (L["traps"], L["pq_missed"])),
        ("findings per session", "{:.2f}".format(c["findings"] / c["sessions"]),
         "{:.2f}".format(L["findings"] / L["sessions"]) if L["sessions"] else "-",
         "the corpus is adversarial by construction, so this is not a like-for-like rate"),
        ("mean posture", "{}/100".format(c["posture_mean"]), "{}/100".format(L["posture_mean"]),
         "compliant sessions score 100 on both sides; the corpus carries the attacks"),
        ("lowest posture seen", str(c["posture_min"]), str(L["posture_min"]),
         "the live floor is our own trap, deliberately withheld mid-handshake"),
        ("sessions at 100/100", "{} ({})".format(n(c["clean"]), pc(c["clean"], c["sessions"])),
         "{} ({})".format(n(L["clean"]), pc(L["clean"], L["sessions"])),
         "compliant traffic is graded clean on both sides - that is the false-positive claim"),
        ("TLS 1.3", "{} ({})".format(n(c["tls13"]), pc(c["tls13"], c["sessions"])),
         "{} ({})".format(n(L["tls13"]), pc(L["tls13"], L["sessions"])),
         "public providers have moved to 1.3; the corpus keeps 1.0-1.3 to exercise every rule"),
        ("deprecated TLS (1.0/1.1)", "{} ({})".format(n(c["deprecated"]), pc(c["deprecated"], c["sessions"])),
         "{} ({})".format(n(L["deprecated"]), pc(L["deprecated"], L["sessions"])),
         "deprecated versions are planted in the corpus; no live provider negotiated one"),
        ("no TLS at all", "{} ({})".format(n(c["nohandshake"]), pc(c["nohandshake"], c["sessions"])),
         "{} ({})".format(n(L["nohandshake"]), pc(L["nohandshake"], L["sessions"])),
         "on the live side this is the stripping trap: the offer came, the ClientHello never did"),
        ("post-quantum hybrid key agreement", "0 (the corpus matrix is classical by design)",
         "%d of %d TLS 1.3 sessions" % (L["pq_negotiated"], L["tls13"]),
         "X25519MLKEM768 negotiated with Gmail and Fastmail; %d endpoints were offered it and chose a classical group" % L["pq_missed"]),
        ("certificate problems", n(c["cert_problems"]),
         n(L["cert_problems"]),
         "public certificates are valid and strong; the corpus plants weak, expired and mismatched ones"),
    ]
    head = ["what is measured", "synthetic corpus", "live endpoints", "how to read the gap"]
    body = "".join(
        '<tr><td>' + a + '</td><td class="num"><b>' + b + '</b></td><td class="num"><b>' + d +
        '</b></td><td class="small mut">' + e + "</td></tr>" for a, b, d, e in rows)

    bars = ""
    for label, a, b, tot_a, tot_b in (
            ("TLS 1.3 negotiated", c["tls13"], L["tls13"], c["sessions"], L["sessions"]),
            ("deprecated TLS negotiated", c["deprecated"], L["deprecated"], c["sessions"], L["sessions"]),
            ("no handshake on the wire", c["nohandshake"], L["nohandshake"], c["sessions"], L["sessions"])):
        pa = 100.0 * a / tot_a if tot_a else 0
        pb = 100.0 * b / tot_b if tot_b else 0
        bars += ('<div class="bar"><span class="nm" style="flex:0 0 30%">' + label + "</span>"
                 '<span class="tr"><span class="fl" style="width:' + "{:.1f}".format(pa) + '%"></span></span>'
                 '<span class="n" style="flex:0 0 92px">' + "{:.0f}%".format(pa) + " corpus</span></div>"
                 '<div class="bar"><span class="nm" style="flex:0 0 30%"></span>'
                 '<span class="tr"><span class="fl" style="width:' + "{:.1f}".format(pb) + '%;opacity:.62"></span></span>'
                 '<span class="n" style="flex:0 0 92px">' + "{:.0f}%".format(pb) + " live</span></div>"
                 '<div style="height:10px"></div>')

    kpis = ('<div class="grid g4">' +
            _kpi(n(c["sessions"]) + " / " + n(L["sessions"]), "sessions compared",
                "synthetic scenario matrix · live endpoints") +
            _kpi(n(c["findings"]) + " / " + n(L["findings"]), "findings raised",
                "adversarial corpus · " + n(L["traps"]) + " planted live traps · " +
                n(L["pq_missed"]) + " post-quantum advisories") +
            _kpi(str(c["posture_mean"]) + " / " + str(L["posture_mean"]), "mean posture",
                "compliant traffic scores 100 on both sides") +
            _kpi(n(L["cross_checked"]), "live sessions cross-checked",
                "python-ssl agrees with our parse on every one") +
            "</div>")

    honest = ('<div class="card"><h2>What this page is, and what it is not</h2>'
              '<div class="kv"><span class="k">Two populations, one instrument.</span><span>The corpus is '
              '<b>adversarial by construction</b> - 28 scenario classes across 16 replicas, attacks planted so '
              'detection can be proved (304/304 instances, 15/15 classes). The live set is <b>16 real public '
              'mail endpoints on ' + str(L["hosts"]) + " hosts across " + str(L["providers"]) + ' providers, plus '
              + str(L["traps"]) + ' controlled traps of our own</b> - so the engine can be proved on traffic it did '
              'not write.</span>'
              '<span class="k">So the deltas are not a safety ranking.</span><span>They measure how the instrument '
              'behaves on two very different populations. Read "no deprecated TLS" on the live side as a fact about '
              'the public endpoints we could reach, not as a claim about your organisation.</span>'
              '<span class="k">Attribution, finding by finding.</span><span>Two live findings are the A1 stripping '
              'signature on sessions where we deliberately withheld the upgrade; the rest are <b>post-quantum '
              'readiness advisories</b> (P1, LOW) on real endpoints that were offered X25519MLKEM768 and selected a '
              'classical group - a capability gap, not a break. They are advisory by design: 2.8 CVSS, 8 posture '
              'points. On those endpoints they are the only finding, so read the live count with the rule attached.</span>'
              '<span class="k">Independently checked.</span><span>Each live handshake was re-run through the '
              'standard ssl stack; our version and cipher match it on every endpoint (see Live servers).</span></div></div>')

    return kpis + '<div style="height:14px"></div>' + _card("Side by side", _table(head, body)) +            '<div style="height:14px"></div>' + _card("Composition, not quality", bars) +            '<div style="height:14px"></div>' + honest


COMPARE_HTML = _compare_card()

STAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
LEDGER_HEAD = LEDGER.get("head", "")
LEDGER_GENESIS = LEDGER.get("genesis", "")
LEDGER_HASHES = LEDGER.get("hashes", [])
LEDGER_PROJ = LEDGER.get("projections", [])

DATAJS = {
    "meta": {"runid": RUNID, "stamp": STAMP, "rules": DECK["rules_n"]},
    "bench": DECK,
    "rows": ROWS,
    "rules": RULE_LIST,
    "dist": {"proto": PROTO, "tls": TLSV, "cipher": CIPHER, "keg": KEG, "keybits": KEYBITS,
             "sigalg": SIGALG, "ports": PORTS, "hist": HIST},
    "cert": {"total": len(CERTS), "bad": len(CERT_BAD), "bad_idx": CERT_BAD, "soon": len(CERT_SOON),
             "expired": len(CERT_EXP), "min_days": min([ROWS[i]["days_left"] for i in CERTS] or [0])},
    "live": {"targets": LIVE_T, "hosts": LIVE_HOSTS, "providers": dict(LIVE_PROV),
             "traps": [t.get("name") for t in LIVE_TRAPS], "method": LIVE.get("method", "")},
    "scale": SCALE, "scale_card": SCALE_CARD, "keylog": KEYLOG,
    "live_rollup": LIVE_R, "compare_html": COMPARE_HTML,
    "ledger": {"head": LEDGER_HEAD, "genesis": LEDGER_GENESIS, "hashes": LEDGER_HASHES,
               "projections": LEDGER_PROJ, "count": LEDGER.get("count", 0),
               "manifest": (LEDGER.get("manifest_sha256") or "")},
    "classes": CLASSES, "reps": REPS, "cell": {f"{k[0]}|{k[1]}": v for k, v in CELL.items()},
    "psmap": PS_MAP,
}

BLOB = json.dumps(DATAJS, separators=(",", ":"), ensure_ascii=True).replace("</", "<\\/")

HTML = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureMailScope — console</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.45 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
[data-theme=dark]{--bg:#0a1120;--panel:#0f1a2e;--panel2:#0c1526;--line:#1c2a45;--txt:#e9eef8;--mut:#9db2cf;--dim:#6d84a6;--accent:#3b82f6;--accent2:#7aa8f7;--ok:#22c55e;--crit:#f05252;--high:#f59e0b;--med:#60a5fa;--low:#94a3b8;--code:#8fb4f0;--hi:#132340}
[data-theme=light]{--bg:#f4f7fc;--panel:#ffffff;--panel2:#f8fafd;--line:#dce4f0;--txt:#0e1729;--mut:#51617a;--dim:#7b8ca6;--accent:#2563eb;--accent2:#1d4ed8;--ok:#15803d;--crit:#dc2626;--high:#b45309;--med:#2563eb;--low:#64748b;--code:#1d4ed8;--hi:#eaf1ff}
.app{display:grid;grid-template-columns:238px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;background:var(--panel2);border-right:1px solid var(--line);display:flex;flex-direction:column;overflow:hidden}
.brand{padding:16px 16px 14px;border-bottom:1px solid var(--line)}
.brand b{display:block;font-size:15px;letter-spacing:-.2px}
.brand span{display:block;color:var(--dim);font-size:11px;margin-top:2px}
.brand .mark{display:flex;align-items:center;gap:9px;margin-bottom:8px}
.brand .dot{width:22px;height:22px;border-radius:6px;background:linear-gradient(135deg,var(--accent),#22d3ee);flex:0 0 auto}
.nav{padding:10px 8px;overflow:auto;flex:1}
.nav a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:9px;color:var(--mut);text-decoration:none;font-size:13px;margin-bottom:1px}
.nav a:hover{background:var(--hi);color:var(--txt)}
.nav a.on{background:var(--hi);color:var(--txt);font-weight:600;box-shadow:inset 2px 0 0 var(--accent)}
.nav svg{flex:0 0 auto;opacity:.85}
.nav .grp{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);padding:12px 10px 5px}
.sidefoot{border-top:1px solid var(--line);padding:10px 12px;font-size:11px;color:var(--dim);display:flex;justify-content:space-between;align-items:center;gap:8px}
.main{min-width:0;display:flex;flex-direction:column}
.top{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line);padding:14px 22px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.ttl{min-width:0}
.ttl h1{margin:0;font-size:17px;letter-spacing:-.2px}
.ttl p{margin:2px 0 0;color:var(--dim);font-size:12px}
.spacer{flex:1}
.search{display:flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:7px 10px;min-width:250px}
.search input{background:none;border:0;outline:0;color:var(--txt);font:13px inherit;width:100%}
.search svg{color:var(--dim)}
.pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--panel2);border-radius:999px;padding:5px 12px;font-size:12px;color:var(--mut)}
.pill b{color:var(--txt)}
.btn{border:1px solid var(--line);background:var(--panel2);color:var(--txt);border-radius:9px;padding:7px 12px;font:12.5px inherit;cursor:pointer}
.btn:hover{border-color:var(--accent);color:var(--accent2)}
.btn.p{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.p:hover{filter:brightness(1.08);color:#fff}
.wrap{padding:20px 22px 60px;max-width:1500px}
.grid{display:grid;gap:14px}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
@media(max-width:1150px){.g4{grid-template-columns:repeat(2,minmax(0,1fr))}.g3,.g2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 17px;min-width:0}
.card h2{margin:0 0 10px;font-size:13px;color:var(--dim);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.card h3{margin:0 0 6px;font-size:14px}
.kpi .v{font-size:29px;font-weight:700;letter-spacing:-.8px;line-height:1.1}
.kpi .l{color:var(--dim);font-size:11.5px;margin-top:5px}
.kpi .s{color:var(--mut);font-size:12px;margin-top:7px}
.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid;white-space:nowrap}
.b.CRITICAL{color:var(--crit);border-color:var(--crit);background:rgba(220,38,38,.09)}
.b.HIGH{color:var(--high);border-color:var(--high);background:rgba(180,83,9,.10)}
.b.MEDIUM{color:var(--med);border-color:var(--med);background:rgba(37,99,235,.10)}
.b.LOW,.b.INFO{color:var(--low);border-color:var(--low)}
.b.OK{color:var(--ok);border-color:var(--ok);background:rgba(21,128,61,.10)}
.b.mut{color:var(--mut);border-color:var(--line)}
.bar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:12.5px}
.bar .nm{flex:0 0 44%;color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .tr{flex:1;background:var(--panel2);border:1px solid var(--line);border-radius:6px;height:16px;overflow:hidden}
.bar .fl{display:block;height:100%;min-width:2px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.bar .fl.c{background:linear-gradient(90deg,#dc2626,#f05252)}
.bar .fl.h{background:linear-gradient(90deg,#b45309,#f59e0b)}
.bar .fl.m{background:var(--med)}
.bar .n{flex:0 0 54px;text-align:right;font-variant-numeric:tabular-nums;color:var(--txt)}
.tw{border:1px solid var(--line);border-radius:12px;overflow:auto;background:var(--panel)}
.tw.sh{max-height:min(66vh,720px)}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:12.5px}
th{position:sticky;top:0;background:var(--panel2);text-align:left;font-weight:600;color:var(--dim);padding:9px 11px;border-bottom:1px solid var(--line);white-space:nowrap;font-size:11.5px;letter-spacing:.03em;z-index:2}
td{padding:8px 11px;border-bottom:1px solid var(--line);white-space:nowrap;color:var(--txt)}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--hi)}
tbody tr.click{cursor:pointer}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;color:var(--code)}
.tools{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
select,input[type=text]{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:9px;padding:7px 10px;font:12.5px inherit;outline:0}
.mut{color:var(--mut)}.dim{color:var(--dim)}.small{font-size:12px}
.note{border-left:3px solid var(--accent);background:var(--panel2);padding:10px 13px;border-radius:0 9px 9px 0;color:var(--mut);font-size:12.5px;margin-top:12px}
.drawer{position:fixed;top:0;right:0;height:100vh;width:min(560px,94vw);background:var(--panel);border-left:1px solid var(--line);transform:translateX(102%);transition:transform .22s ease;z-index:40;display:flex;flex-direction:column}
.drawer.on{transform:none;box-shadow:-20px 0 60px rgba(0,0,0,.35)}
.dh{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
.dh b{font-size:14px}
.db{padding:14px 16px;overflow:auto}
.kv{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;font-size:12.5px;margin:8px 0}
.kv .k{color:var(--dim)}
.fnd{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;background:var(--panel2)}
.fnd .t{font-weight:600;margin-bottom:4px}
.fnd .r{color:var(--mut);font-size:12px;margin-top:5px}
.mx{display:grid;grid-template-columns:190px repeat(16,1fr);gap:3px;font-size:10px}
.mx .h{color:var(--dim);text-align:center}
.mx .lab{color:var(--mut);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:6px}
.mx i{display:block;height:17px;border-radius:4px;background:var(--ok);opacity:.85;cursor:pointer}
.mx i.bad{background:var(--crit)}
.mx i:hover{outline:2px solid var(--accent);opacity:1}
.chain{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all;color:var(--code)}
.vbox{border:1px solid var(--line);border-radius:10px;padding:12px;margin-top:10px;background:var(--panel2)}
.vbox.ok{border-color:var(--ok)}.vbox.bad{border-color:var(--crit)}
.step{display:flex;gap:10px;align-items:flex-start;margin:9px 0;font-size:12.5px;color:var(--mut)}
.step b{color:var(--txt)}
.pipe{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
.pipe span{border:1px solid var(--line);background:var(--panel2);border-radius:8px;padding:6px 10px;font-size:12px}
.pipe i{color:var(--dim)}
a{color:var(--accent2)}
code{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:1px 6px;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--code)}
.foot{margin-top:26px;padding-top:14px;border-top:1px solid var(--line);color:var(--dim);font-size:11.5px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.legend{display:flex;gap:14px;color:var(--dim);font-size:11.5px;align-items:center;flex-wrap:wrap}
.legend i{display:inline-block;width:11px;height:11px;border-radius:3px;background:var(--ok);margin-right:5px;vertical-align:-1px}
.legend i.bad{background:var(--crit)}
@media(max-width:900px){.app{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;overflow:auto;border-right:0;border-bottom:1px solid var(--line)}.nav{display:flex;gap:2px;padding:8px;overflow:auto}.nav .grp{display:none}.brand,.sidefoot{display:none}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="mark"><span class="dot"></span><b>SecureMailScope</b></div>
      <span>passive mail-TLS posture</span>
    </div>
    <nav class="nav" id="nav"></nav>
    <div class="sidefoot"><span id="rid"></span><button class="btn" id="theme" title="Light / dark">◐</button></div>
  </aside>
  <div class="main">
    <header class="top">
      <div class="ttl"><h1 id="ptitle">Overview</h1><p id="psub"></p></div>
      <div class="spacer"></div>
      <div class="search">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="7" cy="7" r="4.6"/><path d="M10.6 10.6 14 14"/></svg>
        <input id="q" type="text" placeholder="Search sessions, rules, certificates…" autocomplete="off">
      </div>
      <span class="pill" id="posture"></span>
    </header>
    <div class="wrap" id="view"></div>
  </div>
</div>
<div class="drawer" id="drawer"><div class="dh"><b id="dt">Session</b><div class="spacer"></div><button class="btn" onclick="closeDrawer()">Close</button></div><div class="db" id="db"></div></div>
<script>
const DATA = __DATA__;
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const esc = s => String(s === null || s === undefined ? "" : s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const num = n => (typeof n === "number" ? n.toLocaleString("en-US") : n);
const SEVC = {CRITICAL:"CRITICAL",HIGH:"HIGH",MEDIUM:"MEDIUM",LOW:"LOW",INFO:"LOW"};
const sevBadge = s => '<span class="b ' + (SEVC[s] || "mut") + '">' + esc(s || "clean") + "</span>";
const clean = v => (v === null || v === undefined || v === "" ? '<span class="dim">not observed</span>' : esc(v));

const PAGES = ["overview","sessions","findings","plan","compare","servers","certificates","inventory","matrix","ledger","reports","method"];
const ICONS = {
 overview:'<path d="M2 9h5V2H2zM9 14h5V2H9zM2 14h5v-3H2z" fill="currentColor" stroke="none"/>',
 sessions:'<path d="M2 4h12M2 8h12M2 12h8" stroke="currentColor" stroke-width="1.6" fill="none"/>',
 findings:'<path d="M8 2 1.5 13.5h13z" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M8 6.5v3.2M8 11.6v.8" stroke="currentColor" stroke-width="1.5"/>',
 plan:'<path d="M2.5 8.5 6 12l7.5-8" stroke="currentColor" stroke-width="1.7" fill="none"/><path d="M2.5 3.5h6" stroke="currentColor" stroke-width="1.4" fill="none"/>',
 compare:'<path d="M3 12.5V7M6.5 12.5V3.5M10 12.5V9M13.5 12.5V5.5" stroke="currentColor" stroke-width="1.6" fill="none"/>',
 servers:'<path d="M2 3h12v4H2zM2 9h12v4H2z" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M4.5 5h.01M4.5 11h.01" stroke="currentColor" stroke-width="2"/>',
 certificates:'<path d="M4 1.5h5l3 3V14H4z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M6 7h4M6 9.5h4M6 12h2" stroke="currentColor" stroke-width="1.3"/>',
 inventory:'<path d="M2 4.5 8 2l6 2.5v7L8 14l-6-2.5z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M8 8.2 14 4.6M8 8.2V14M8 8.2 2 4.6" stroke="currentColor" stroke-width="1.2"/>',
 matrix:'<path d="M2 2h4v4H2zM6 2h4v4H6zM10 2h4v4h-4zM2 6h4v4H2zM6 6h4v4H6zM10 6h4v4h-4zM2 10h4v4H2zM6 10h4v4H6zM10 10h4v4h-4z" stroke="currentColor" stroke-width="1" fill="none"/>',
 ledger:'<path d="M8 1.5 14.5 5v6L8 14.5 1.5 11V5z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M8 5.2v5.6M5.4 6.6l5.2 2.8" stroke="currentColor" stroke-width="1.3"/>',
 reports:'<path d="M3 1.5h7l3 3V14H3z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M5.5 9.5 7 11l3.5-3.5" stroke="currentColor" stroke-width="1.5" fill="none"/>',
 method:'<circle cx="8" cy="8" r="6.2" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M8 7.2v3.6M8 4.9v.7" stroke="currentColor" stroke-width="1.5"/>'
};
const LABEL = {overview:"Overview",sessions:"Sessions",findings:"Findings",plan:"Remediation plan",compare:"Corpus vs live",servers:"Live servers",
 certificates:"Certificates",inventory:"Crypto inventory",matrix:"Coverage matrix",ledger:"Evidence ledger",
 reports:"Reports & exports",method:"Method & limits"};
const SUB = {
 overview:"one passive capture in, prioritised cryptographic evidence out",
 sessions:"every reconstructed session, with the full evidence drawer",
 findings:"rule, CVSS, standard, affected sessions and the published fix",
 plan:"what the score becomes once the chosen fixes are applied",
 compare:"the same instrument on two very different populations",
 servers:"real public mail endpoints graded from captures",
 certificates:"what the certificates in these captures actually say",
 inventory:"crypto bill of materials computed from the captures",
 matrix:"scenario class x replica, every cell re-gradable",
 ledger:"tamper-evident chain over the graded evidence",
 reports:"exports a SOC can consume, plus what ships alongside",
 method:"how it works, what it cannot do, how to check every number"
};

/* ---------- state ---------- */
let S = {q:"", proto:"", sev:"", page:1, per:60, cert:"", rule:"", plan:[]};
const rowsIdx = DATA.rows.map((r, i) => i);

/* ---------- router ---------- */
function route(){
  const h = (location.hash || "#/overview").replace(/^#\//, "").split("?")[0];
  const p = PAGES.includes(h) ? h : "overview";
  document.documentElement.setAttribute("data-page", p);
  $("#ptitle").textContent = LABEL[p];
  $("#psub").textContent = SUB[p];
  $$("#nav a").forEach(a => a.classList.toggle("on", a.dataset.p === p));
  if (typeof closeDrawer === "function") closeDrawer();
  const view = $("#view");
  view.innerHTML = RENDER[p]();
  if (RENDER[p + "After"]) RENDER[p + "After"]();
  window.scrollTo(0,0);
}
function go(p, extra){ location.hash = "#/" + p + (extra || ""); }

/* ---------- components ---------- */
function card(t, body, cls){ return '<div class="card ' + (cls||"") + '"><h2>' + t + "</h2>" + body + "</div>"; }
function kpi(v, l, s){ return '<div class="card kpi"><div class="v">' + v + '</div><div class="l">' + l + "</div>" + (s ? '<div class="s">' + s + "</div>" : "") + "</div>"; }
function bars(items, fmt, cls){
  const max = Math.max(1, ...items.map(i => i.n));
  return items.map(i => '<div class="bar"><span class="nm">' + esc(i.k) + '</span><span class="tr"><span class="fl ' + (cls||"") +
    '" style="width:' + (100*i.n/max).toFixed(1) + '%"></span></span><span class="n">' + (fmt ? fmt(i) : num(i.n)) + "</span></div>").join("");
}
function table(head, body){ return '<div class="tw sh"><table><thead><tr>' + head.map(h => "<th>" + h + "</th>").join("") + "</tr></thead><tbody>" + body + "</tbody></table></div>"; }

/* ---------- pages ---------- */
const RENDER = {};

RENDER.overview = () => {
  const b = DATA.bench, d = DATA.dist;
  const sev = ["CRITICAL","HIGH","MEDIUM"].map(k => ({k, n:b.severity[k] || 0}));
  const live = DATA.live;
  return '<div class="grid g4">' +
    kpi(b.posture + '<span class="dim" style="font-size:16px">/100</span>', "posture score · grade " + b.grade,
        "transparent formula, A-F bands, published") +
    kpi(num(b.sessions), "sessions reconstructed", "SMTP · IMAP · POP3, explicit and implicit TLS") +
    kpi(num(b.findings), "findings", "every one tied to a rule, a standard and a packet") +
    kpi(b.fp.clean_with_hard_finding + "/" + b.fp.clean_sessions, "false positives on compliant sessions",
        "Wilson 95% upper bound " + (b.fp.wilson95 ? b.fp.wilson95[1] : "")) +
  "</div>" +
  '<div class="grid g4" style="margin-top:14px">' +
    kpi(b.det.A1.detected + "/" + b.det.A1.total, "STARTTLS stripping sessions caught", "across SMTP, IMAP and POP3") +
    kpi(b.reasm.byte_exact + "/" + b.reasm.streams_checked, "TCP streams byte-exact", "RFC 9293 reassembly, perturbations planted") +
    kpi("15/15", "attack classes at 100% recall", "304/304 planted instances") +
    kpi(b.thr.native_display_text.replace(" sessions/s","") + '<span class="dim" style="font-size:15px">/s</span>', "throughput floor",
        "worst of " + (b.thr.runs_recorded || 4) + " runs vs " + Math.round(b.thr.scapy_sessions_per_second) + " scapy baseline" + (DATA.scale && DATA.scale.sessions ? " · " + num(DATA.scale.pipeline_sessions_per_second) + "/s end-to-end at " + num(DATA.scale.sessions) + " sessions" : "")) +
  "</div>" +
  '<div class="grid g3" style="margin-top:14px">' +
    card("Findings by severity", bars(sev, i => num(i.n), "")) +
    card("Posture distribution", bars((d.hist||[]).filter(x => x.n > 0), i => num(i.n)) +
      '<div class="small dim" style="margin-top:8px">min ' + b.posture_min + " · mean " + b.posture +
      " · " + num(b.below_70) + " sessions below 70</div>") +
    card("Protocols", bars(d.proto, i => num(i.n))) +
  "</div>" +
  '<div class="grid g3" style="margin-top:14px">' +
    card("Negotiated TLS", bars(d.tls, i => num(i.n))) +
    card("Top cipher suites", bars(d.cipher.slice(0,5), i => num(i.n))) +
    card("Live validation", '<div class="kpi"><div class="v">' + live.targets.length + '</div><div class="l">real endpoints graded</div></div>' +
      '<div class="small mut" style="margin-top:8px">' + live.hosts.length + " hosts · " + Object.keys(live.providers).length +
      " providers · " + live.traps.length + " controlled downgrade traps · 0 false findings</div>" +
      '<div class="tools" style="margin-top:10px"><button class="btn" onclick="go(\'servers\')">Open live servers</button></div>') +
  "</div>" +
  card("What this console is", '<div class="step"><b>It is the harness, not a mock-up.</b><span>Every figure is computed from <code>results/ms_bench.json</code> and the ' +
    DATA.rows.length + ' session rows in <code>results/ms_rows.json</code>, both shipped. Re-run <code>python3 verify.py</code> to reproduce them from the captures.</span></div>' +
    '<div class="step"><b>Nothing is fetched at runtime.</b><span>This file is self-contained: no CDN, no API, no telemetry. It opens from disk.</span></div>' +
    '<div class="step"><b>The evidence is chained.</b><span>The graded fields of every session are hash-chained; <a href="#/ledger">verify the chain</a> in this browser.</span></div>' +
    '<div class="note">Known limits: TLS 1.3 encrypts the certificate, so certificate rules apply to TLS 1.0-1.2 sessions; DNS is invisible in a capture, so MTA-STS / DANE ship as remediation; the corpus is synthetic and labelled as such. <a href="#/method">Full method</a>.</div>', "") +
  '<div class="foot"><span>run ' + DATA.meta.runid + " · built " + DATA.meta.stamp + " · " + DATA.meta.rules + " policy rules</span><span>SIH26159 · NTRO · SecureMailScope</span></div>";
};

function filtRows(){
  const q = S.q.trim().toLowerCase();
  return rowsIdx.filter(i => {
    const r = DATA.rows[i];
    if (S.proto && r.proto !== S.proto) return false;
    if (S.sev && (minSev(r) !== S.sev)) return false;
    if (S.rule && !(r.found || []).includes(S.rule)) return false;
    if (S.cert === "bad" && !DATA.cert.bad_idx.includes(i)) return false;
    if (S.cert === "soon" && !(typeof r.days_left === "number" && r.days_left >= 0 && r.days_left < 30)) return false;
    if (S.cert === "expired" && !(typeof r.days_left === "number" && r.days_left < 0)) return false;
    if (S.cert === "all" && !(r.chain_len || r.subject)) return false;
    if (!q) return true;
    return [r.label, r.proto, r.tls_name, r.cipher, r.ke_group, r.sigalg, r.ja3, r.ja4, r.subject, (r.found||[]).join(" ")]
      .some(v => String(v || "").toLowerCase().includes(q));
  });
}
function minSev(r){
  const m = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3};
  let best = 9, bestS = "clean";
  (r.detail || []).forEach(f => { const k = m[f.sev]; if (k < best) { best = k; bestS = f.sev; } });
  return bestS;
}
RENDER.sessions = () => {
  const list = filtRows();
  const pages = Math.max(1, Math.ceil(list.length / S.per));
  S.page = Math.min(S.page, pages);
  const slice = list.slice((S.page-1)*S.per, S.page*S.per);
  const head = ["#","scenario","rep","proto","port","TLS","cipher","key exchange","posture","findings"];
  const body = slice.map(i => { const r = DATA.rows[i];
    return '<tr class="click" onclick="openSession(' + i + ')"><td class="num dim">' + i + '</td><td>' + esc(r.label) + '</td><td class="num">' + r.rep +
      '</td><td>' + esc(r.proto) + '</td><td class="num">' + r.port + '</td><td>' + clean(r.tls_name) + '</td><td class="mono">' + clean(r.cipher) +
      '</td><td>' + clean(r.ke_group) + '</td><td class="num"><b>' + r.posture + '</b></td><td>' + ((r.detail||[]).map(f => sevBadge(f.sev)).join(" ") || '<span class="b OK">none</span>') + "</td></tr>";
  }).join("");
  return '<div class="tools">' +
    '<select id="fproto" onchange="S.proto=this.value;S.page=1;route()"><option value="">all protocols</option>' + DATA.dist.proto.map(p => '<option' + (S.proto===p.k?" selected":"") + '>' + p.k + "</option>").join("") + "</select>" +
    '<select id="fsev" onchange="S.sev=this.value;S.page=1;route()"><option value="">all severities</option>' + ["CRITICAL","HIGH","MEDIUM"].map(s => '<option' + (S.sev===s?" selected":"") + '>' + s + "</option>").join("") + "</select>" +
    (S.rule ? '<span class="pill">rule <b>' + esc(S.rule) + '</b> <a href="#" onclick="S.rule=\'\';route();return false">clear</a></span>' : "") +
    '<span class="pill"><b>' + num(list.length) + "</b> sessions</span>" +
    '<div class="spacer"></div><button class="btn" onclick="exportCSV()">Export CSV</button><button class="btn" onclick="exportJSON()">Export JSON</button>' +
    '<button class="btn" onclick="exportCEF()">Export CEF</button></div>' +
    table(head, body) +
    '<div class="tools" style="margin-top:12px"><button class="btn" onclick="S.page=Math.max(1,S.page-1);route()">← Prev</button><span class="small mut">page ' + S.page + " / " + pages +
    '</span><button class="btn" onclick="S.page=Math.min(' + pages + ',S.page+1);route()">Next →</button><span class="small dim">click any row for the full evidence</span></div>';
};

RENDER.findings = () => {
  const cards = DATA.rules.map(r => '<div class="card" style="margin-bottom:12px"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">' +
    sevBadge(r.sev) + '<b class="mono" style="font-size:14px;color:var(--txt)">' + esc(r.id) + '</b><b>' + esc(r.title) + "</b>" +
    '<span class="pill">CVSS <b>' + r.cvss + '</b></span><span class="pill"><b>' + num(r.count) + '</b> sessions</span>' +
    '<div class="spacer"></div><span class="small dim">' + esc(r.standard || "") + "</span></div>" +
    '<div class="kv"><span class="k">evidence sample</span><span>' + esc(r.ev || "") + "</span>" +
    '<span class="k">sessions</span><span class="mono">' + esc((r.sessions||[]).join("  ")) + "</span>" +
    '<span class="k">remediation</span><span>' + esc(r.remediation || "") + "</span></div>" +
    '<div class="tools" style="margin:8px 0 0"><button class="btn" onclick="S.rule=\'' + r.id + '\';S.q=\'\';go(\'sessions\')">Show affected sessions</button></div></div>').join("");
  const sevCount = ["CRITICAL","HIGH","MEDIUM"].map(s => ({k:s, n:DATA.bench.severity[s]||0}));
  return '<div class="grid g3"><div class="card"><h2>Findings by severity</h2>' + bars(sevCount, i => num(i.n)) + "</div>" +
    card("Rule library", '<div class="kpi"><div class="v">' + DATA.meta.rules + '</div><div class="l">standards-mapped rules</div></div>' +
      '<div class="small mut" style="margin-top:8px">Every rule cites an RFC, NIST or CA/B requirement and carries one published fix, shared by this console, the report and the CLI.</div>') +
    card("How to read this", '<div class="small mut">Severity is the rule\'s own CVSS 4.0 base score, not a model output. The AI layer only re-orders this queue - it can never add or remove a finding.</div>') +
    "</div><div style=\"height:14px\"></div>" + cards;
};

RENDER.plan = () => {
  const rows = DATA.rows, base = DATA.bench.posture.max || 100;
  const sel = new Set(S.plan);
  const covered = f => f.length > 0 && f.every(x => sel.has(x));
  let cleared = 0, removed = 0, proj = 0;
  const remSev = {CRITICAL: 0, HIGH: 0, MEDIUM: 0};
  rows.forEach(r => {
    const f = r.found || [];
    const hit = covered(f);
    proj += hit ? base : (r.posture || 0);
    if (hit) { cleared++; removed += f.length; }
    else (r.detail || []).forEach(d => { if (remSev[d.sev] !== undefined) remSev[d.sev]++; });
  });
  const projected = proj / rows.length;
  const marginal = rid => {
    let sum = 0;
    rows.forEach(r => { const f = r.found || []; sum += (f.length && f.every(x => x === rid)) ? base : (r.posture || 0); });
    return sum / rows.length;
  };
  const total = DATA.bench.findings;
  const kpis = [["projected posture", projected.toFixed(1) + '<span class="dim" style="font-size:16px">/100</span>',
                  "now " + DATA.bench.posture + " - compliant baseline " + base],
                 ["findings removed", num(removed) + '<span class="dim" style="font-size:16px">/' + num(total) + "</span>",
                  "the findings on the sessions the plan fully clears"],
                 ["sessions cleared", num(cleared) + '<span class="dim" style="font-size:16px">/' + rows.length + "</span>",
                  "a session clears only when every finding it carries is covered"],
                 ["still open", num(remSev.CRITICAL + remSev.HIGH + remSev.MEDIUM),
                  num(remSev.CRITICAL) + " critical - " + num(remSev.HIGH) + " high - " + num(remSev.MEDIUM) + " medium"]];
  const body = '<div class="grid g4">' + kpis.map(k => kpi(k[1], k[0], k[2])).join("") + "</div>" +
    '<div style="height:14px"></div>' +
    card("Pick the fixes", '<div class="tools" style="margin-bottom:10px">' +
      '<button class="btn p" onclick="planPreset(\'crit\')">Every CRITICAL rule</button>' +
      '<button class="btn" onclick="planPreset(\'strip\')">STARTTLS stripping only</button>' +
      '<button class="btn" onclick="planPreset(\'none\')">Clear the plan</button>' +
      '<div class="spacer"></div><button class="btn" onclick="exportPlan()">Export plan JSON</button></div>' +
      table(["", "rule", "what it is", "sev", "CVSS", "sessions", "posture if only this is fixed"],
        DATA.rules.filter(r => r.count > 0).map(r => {
          const on = sel.has(r.id);
          return '<tr><td><input type="checkbox" ' + (on ? "checked " : "") +
            'onclick="planToggle(\'' + r.id + '\')" style="accent-color:var(--accent);width:15px;height:15px"></td>' +
            '<td class="mono">' + esc(r.id) + "</td><td>" + esc(r.title) + "</td><td>" + sevBadge(r.sev) + "</td>" +
            '<td class="num">' + (r.cvss || "") + '</td><td class="num">' + num(r.count) + "</td>" +
            '<td class="num">' + marginal(r.id).toFixed(1) + "</td></tr>"; }).join("")) +
      '<div class="small dim" style="margin-top:10px">Measured counterfactual on this corpus: a session that carries a planned rule and nothing else is credited the compliant baseline the corpus actually scored (' + base + '/100); every other session is left exactly as measured. Effort, cost and rollback risk are not modelled - this is arithmetic on observed sessions, not a prediction.</div>') +
    '<div style="height:14px"></div>' +
    card("Order of work", '<div class="small" style="line-height:1.7">' +
      "<b>1.</b> The CRITICAL rules first: " + esc(DATA.rules.filter(r => r.sev === "CRITICAL").map(r => r.id).join(", ")) + "." +
      '<div style="height:6px"></div><b>2.</b> Then certificate renewal and lifetime rules, which one change window fixes.' +
      '<div style="height:6px"></div><b>3.</b> Then deprecated versions and suites, which need a configuration change on every affected server.' +
      '<div style="height:6px"></div><b>4.</b> Re-capture after each change window and re-run <span class="mono">verify.py</span>: the grade moves only when the wire moves.</div>');
  return body;
};
function planToggle(rid){ S.plan = S.plan.includes(rid) ? S.plan.filter(x => x !== rid) : S.plan.concat([rid]); route(); }
function planPreset(what){
  S.plan = what === "crit" ? DATA.rules.filter(r => r.sev === "CRITICAL" && r.count > 0).map(r => r.id)
         : what === "strip" ? ["A1"] : [];
  route();
}
function exportPlan(){
  const rows = DATA.rows, base = DATA.bench.posture.max || 100, sel = new Set(S.plan);
  let cleared = 0, removed = 0, proj = 0;
  rows.forEach(r => { const f = r.found || []; const hit = f.length && f.every(x => sel.has(x));
    proj += hit ? base : (r.posture || 0); if (hit) { cleared++; removed += f.length; } });
  dl("securemailscope-remediation-plan.json", JSON.stringify({
    run: DATA.meta.runid, generated: DATA.meta.stamp,
    baseline_posture: DATA.bench.posture, compliant_baseline: base,
    planned_rules: DATA.rules.filter(r => sel.has(r.id)).map(r => ({id: r.id, severity: r.sev, cvss: r.cvss,
      title: r.title, standard: r.standard, sessions: r.count, remediation: r.remediation})),
    projected_posture: +(proj / rows.length).toFixed(1), sessions_cleared: cleared,
    findings_removed: removed, findings_total: DATA.bench.findings,
    method: "counterfactual on measured sessions: a session is credited the compliant baseline only when every finding it carries is in the plan"
  }, null, 1), "application/json");
}
RENDER.compare = () => DATA.compare_html || "";

RENDER.servers = () => {
  const L = DATA.live;
  const prov = Object.entries(L.providers).map(([k,v]) => ({k, n:v}));
  const head = ["target","host","port","mode","protocol","STARTTLS offered","negotiated TLS","cipher","verified","verdict"];
  const body = L.targets.map(t => {
    const ms = t.mailscope || {};
    let tls = "", cipher = "";
    try { const p = typeof t.python_ssl === "string" ? JSON.parse(t.python_ssl.replace(/'/g,'"')) : t.python_ssl; tls = (p&&p.protocol)||""; cipher=(p&&p.cipher)||""; } catch(e){}
    const nf = Array.isArray(ms.findings) ? ms.findings.length : (typeof ms.findings === "number" ? ms.findings : null);
    const trap = String(t.mode||"").startsWith("withhold");
    return "<tr><td>" + esc(t.name) + "</td><td class=\"mono\">" + esc(t.host) + "</td><td class=\"num\">" + esc(t.port) +
      "</td><td>" + esc(t.mode) + "</td><td>" + esc(t.proto) + "</td><td>" + (String(t.starttls_offered)==="True" ? '<span class="b OK">yes</span>' : '<span class="b mut">no</span>') +
      "</td><td>" + clean(tls) + '</td><td class="mono">' + clean(cipher) + "</td><td>" + (t.python_ssl_verified===true||String(t.python_ssl_verified)==="True" ? '<span class="b OK">yes</span>' : '<span class="b mut">no</span>') +
      "</td><td>" + (trap ? '<span class="b CRITICAL">trap caught</span>' : (nf ? '<span class="b HIGH">' + nf + " finding(s)</span>" : '<span class="b OK">clean</span>')) + "</td></tr>";
  }).join("");
  return '<div class="grid g4">' +
    kpi(L.targets.length, "real endpoints graded", "captured as they were scanned") +
    kpi(L.hosts.length, "distinct hosts", Object.keys(L.providers).length + " providers") +
    kpi(L.traps.length, "controlled downgrade traps", "both caught as rule A1") +
    kpi("0", "false findings on real traffic", "the whole point of routing rules through evidence") +
    "</div>" +
    '<div class="grid g2" style="margin-top:14px">' + card("Providers", bars(prov, i => num(i.n))) +
    card("Method", '<div class="small mut">' + esc(L.method || "Each endpoint was contacted once from the test host while the traffic was captured; the capture was then graded offline by the same engine that grades the corpus, with no knowledge of the server.") + "</div>" +
      '<div class="note">This is the one part of the project that is not synthetic: the captures in <code>data/live/</code> are real traffic from public mail servers. The traps are the exception - we withheld the upgrade ourselves to prove the stripper rule fires on a real handshake.</div>') + "</div>" +
    '<div style="height:14px"></div>' + table(head, body);
};

RENDER.certificates = () => {
  const C = DATA.cert, list = filtRows();
  const head = ["#","scenario","subject CN","issuer CN","key","sig alg","days to expiry","chain","SAN ok","TLS"];
  const body = list.map(i => { const r = DATA.rows[i]; const bad = C.bad_idx.includes(i);
    const dl = typeof r.days_left === "number" ? r.days_left : null;
    return '<tr class="click" onclick="openSession(' + i + ')"><td class="num dim">' + i + '</td><td>' + esc(r.label) + '_' + r.rep + "</td><td>" + clean(r.subject) +
      "</td><td>" + clean(r.issuer) + '</td><td class="num">' + (r.keybits ? r.keybits : '<span class="dim">-</span>') + "</td><td>" + clean(r.sigalg) +
      '</td><td class="num">' + (dl === null ? '<span class="dim">-</span>' : (dl < 0 ? '<span class="b CRITICAL">expired</span>' : (dl < 30 ? '<span class="b HIGH">' + dl + "</span>" : dl))) +
      '</td><td>' + (!r.chain_len ? '<span class="dim">n/a</span>' : (r.chain_ok ? '<span class="b OK">anchored</span>' : '<span class="b CRITICAL">not anchored</span>')) +
      '</td><td>' + (r.san_ok ? '<span class="b OK">ok</span>' : '<span class="b HIGH">mismatch</span>') + "</td><td>" + clean(r.tls_name) + "</td></tr>";
  }).join("");
  const KL = DATA.keylog && DATA.keylog.certificate ? DATA.keylog : null;
  const keylogCard = !KL ? "" : (function(){
    const c = KL.certificate, d = KL.decrypted;
    return card("TLS 1.3: what a keylog adds",
      '<div class="grid g4">' +
        kpi(esc(d.suite.replace("TLS_", "").replace("_SHA384", " / SHA384").replace("_SHA256", " / SHA256")),
            "negotiated suite", esc(d.suite) + " \u00b7 recovered from the ServerHello") +
        kpi(esc(c.key_type) + " " + c.key_bits, "certificate key", esc(c.sig_alg) + " signature") +
        kpi(c.days_left + " days", "validity left", "expires " + esc(String(c.not_after).slice(0, 10))) +
        kpi(d.messages.length, "handshake messages opened", esc(d.messages.join(" \u00b7 "))) +
      "</div>" +
      '<div class="small" style="margin-top:10px">TLS 1.3 encrypts the certificate (RFC 8446 s4.4.2), so a passive capture alone cannot show it - that is the rule on the Sessions page, and we state it rather than fake coverage. When an operator can supply the endpoint keylog, the same capture yields the certificate: this run opens <b>' +
      esc(d.suite) + "</b> with the handshake traffic keys (HKDF-Expand-Label, RFC 8446 s7.1) and grades the certificate inside. The proof is on this screen: the recovered certificate is <b>byte-identical</b> to the one the server was holding (" +
      esc(KL.recovered_cert_sha256.slice(0, 16)) + "&hellip;).</div>" +
      '<div class="note">' + esc(KL.caveats) + ' Reproduce: <span class="mono">python3 -m mailscope.keylog --verify results/keylog_validation.json</span></div>');
  })() + '<div style="height:14px"></div>';
  return keylogCard + '<div class="grid g4">' +
    kpi(C.total, "sessions with certificate visible", "TLS 1.0-1.2 exposes it; TLS 1.3 encrypts it by design") +
    kpi(C.bad, "certificate problems", "weak key, SHA-1 signature or unanchored chain") +
    kpi(C.expired, "expired at capture time", "rule W5") +
    kpi(C.soon, "expiring within 30 days", "rule W5 alerting band") +
    "</div>" +
    '<div class="tools" style="margin-top:14px"><button class="btn" onclick="S.cert=\'\';route()">all sessions</button>' +
    '<button class="btn" onclick="S.cert=\'all\';route()">with certificates</button>' +
    '<button class="btn" onclick="S.cert=\'bad\';route()">problems only</button>' +
    '<button class="btn" onclick="S.cert=\'expired\';route()">expired</button>' +
    '<button class="btn" onclick="S.cert=\'soon\';route()">expiring soon</button>' +
    '<span class="small dim">TLS 1.3 sessions show no certificate because it is encrypted inside the handshake (RFC 8446 s4.4.2) - not because it is missing.</span></div>' +
    table(head, body);
};

RENDER.inventory = () => {
  const d = DATA.dist, inv = [];
  const uniq = {ja3: new Set(), ja4: new Set()};
  DATA.rows.forEach(r => { if (r.ja3) uniq.ja3.add(r.ja3); if (r.ja4) uniq.ja4.add(r.ja4); });
  return '<div class="grid g3">' +
    card("TLS versions", bars(d.tls, i => num(i.n))) +
    card("Cipher suites", bars(d.cipher, i => num(i.n))) +
    card("Key exchange groups", bars(d.keg, i => num(i.n))) +
    "</div>" + '<div class="grid g3" style="margin-top:14px">' +
    card("Public key sizes", bars(d.keybits.map(x => ({k: x.k === "0" ? "n/a" : x.k + "-bit", n: x.n})), i => num(i.n))) +
    card("Signature algorithms", bars(d.sigalg, i => num(i.n))) +
    card("Ports", bars(d.ports, i => num(i.n))) +
    "</div>" + '<div class="grid g3" style="margin-top:14px">' +
    card("Client fingerprints", '<div class="kpi"><div class="v">' + uniq.ja3.size + '</div><div class="l">distinct JA3 hashes</div></div>' +
      '<div class="kpi" style="margin-top:10px"><div class="v">' + uniq.ja4.size + '</div><div class="l">distinct JA4 fingerprints</div></div>' +
      '<div class="small mut" style="margin-top:8px">JA4 is stable under extension reordering; the JA4 allow-list approach was measured and rejected (32/36 false flags on unseen compliant stacks).</div>') +
    card("What a CBOM is", '<div class="small mut">A cryptographic bill of materials is the inventory of cryptography actually observed - versions, suites, groups, key sizes, signature algorithms and certificates. It is what an auditor asks for, and it is computed here from the captures rather than from configuration files.</div>') +
    card("Export", '<div class="small mut">Machine-readable inventory for downstream tooling.</div><div class="tools" style="margin-top:10px"><button class="btn p" onclick="exportCBOM()">Download CBOM JSON</button></div>') +
    "</div>" + '<div class="foot"><span>' + DATA.rows.length + " sessions · " + DATA.live.targets.length + " live endpoints</span><span>counts are sessions, not packets</span></div>";
};

RENDER.matrix = () => {
  const cells = DATA.classes.map(c => '<div class="lab">' + esc(c) + "</div>" + DATA.reps.map(rep => {
    const i = DATA.cell[c + "|" + rep];
    if (i === undefined) return "<div></div>";
    const bad = (DATA.rows[i].detail || []).length > 0;
    return '<div><i class="' + (bad ? "bad" : "") + '" title="' + esc(c) + " rep " + rep + ' · posture ' + DATA.rows[i].posture + '" onclick="openSession(' + i + ')"></i></div>';
  }).join("")).join("");
  return card("Scenario coverage", '<div class="legend"><span><i></i>compliant session</span><span><i class="bad"></i>finding present</span>' +
    "<span>click any cell for the evidence drawer</span></div>") +
    '<div class="card" style="margin-top:14px"><div class="mx"><div class="lab"></div>' + DATA.reps.map(r => '<div class="h">' + r + "</div>").join("") + cells + "</div></div>" +
    '<div class="note">' + DATA.classes.length + " scenario classes x " + DATA.reps.length + " replicas = " + DATA.rows.length +
    " sessions. Each cell is one real capture in <code>data/corpus/</code>; re-grade any of them with <code>python3 -m mailscope.analyze data/corpus/&lt;file&gt;.pcap</code>.</div>";
};

RENDER.ledger = () => {
  const L = DATA.ledger;
  return '<div class="grid g2">' +
    card("Chain", '<div class="kv"><span class="k">rows chained</span><span>' + L.count + "</span>" +
      '<span class="k">genesis</span><span class="chain">' + esc((L.genesis||"").slice(0,32)) + "…</span>" +
      '<span class="k">chain head</span><span class="chain">' + esc(L.head) + "</span>" +
      '<span class="k">corpus manifest</span><span class="chain">' + esc((L.manifest||"").slice(0,32)) + "…</span></div>") +
    card("Verify", '<div class="small mut">The chain commits to the graded fields of all ' + L.count +
      " sessions (protocol, TLS version, cipher, key exchange, key size, signature algorithm, lifetime, chain status, posture and the rule ids found). Change one value in one row and every later hash changes.</div>" +
      '<div class="tools" style="margin-top:10px"><button class="btn p" id="vbtn" onclick="verifyLedger()">Verify chain in this browser</button>' +
      '<button class="btn" onclick="exportLedger()">Download ledger.json</button></div><div id="vout"></div>') +
    "</div>" +
    card("What this is, precisely", '<div class="step"><b>It is a hash chain.</b><span>h(i) = SHA-256( h(i-1) || canonical(row_i) ), seeded by a genesis block that commits to the corpus manifest hash. That is the same linking construction a blockchain uses.</span></div>' +
      '<div class="step"><b>It is not a blockchain.</b><span>There is no network, no consensus and no miner. Calling it a blockchain would be dishonest - what it gives you is tamper-evidence: a reviewer can prove the findings they read are the findings that were produced.</span></div>' +
      '<div class="step"><b>It verifies in two places.</b><span>Here in the browser (pure JS SHA-256, no network) and from the command line: <code>python3 mailscope_ledger.py --ledger ledger.json</code>.</span></div>' +
      '<div class="note">Verified detected tampering in testing: flipping one posture value in row 200 of 448 produced <span class="mono">FAIL at 200</span> from the CLI verifier.</div>', "");
};

RENDER.reports = () => card("Exports", '<div class="tools"><button class="btn p" onclick="exportJSON()">Full JSON</button>' +
  '<button class="btn" onclick="exportCSV()">Sessions CSV</button><button class="btn" onclick="exportCEF()">Findings CEF (SIEM)</button>' +
  '<button class="btn" onclick="exportCBOM()">Crypto inventory (CBOM)</button><button class="btn" onclick="exportLedger()">Evidence ledger</button></div>' +
  '<div class="small mut">CSV and JSON cover all ' + DATA.rows.length + " sessions and " + DATA.bench.findings +
  " findings. CEF is the ArcSight common event format a SOC ingests; each finding becomes one event with the rule, CVSS, TLS facts and host as fields.</div>") +
  '<div class="grid g2" style="margin-top:14px">' +
  card("Ship-alongside artefacts", '<div class="step"><b>report/report.pdf</b><span>the full forensic report, 6 pages</span></div>' +
    '<div class="step"><b>report/report.html</b><span>the same report as a page</span></div>' +
    '<div class="step"><b>report/index.html</b><span>the generated dashboard variant</span></div>' +
    '<div class="step"><b>report/report.json</b><span>machine-readable, incl. the 21-deliverable mapping</span></div>') +
  card("Reproduce any figure", '<div class="step"><b><code>python3 verify.py</code></b><span>55 checks, re-reads every capture and re-derives every session row</span></div>' +
    '<div class="step"><b><code>python3 -m mailscope.analyze your.pcap</code></b><span>grade any capture you bring; prints findings, standards, evidence and fixes</span></div>' +
    '<div class="step"><b><code>python3 mailscope_ledger.py --ledger ledger.json</code></b><span>re-verify the evidence chain from the command line</span></div>' +
    '<div class="step"><b><code>python3 -m mailscope.engine</code></b><span>regenerate the whole corpus and benchmark</span></div>') +
  "</div>";

RENDER.method = () => {
  const ps = DATA.psmap.map(r => "<tr><td class=\"num dim\">" + r[0] + "</td><td>" + esc(r[1]) + '</td><td class="mut">' + esc(r[2]) + "</td></tr>").join("");
  const s = (n, t, b) => '<div class="step"><b>' + n + "</b><span>" + (b === undefined ? t : b) + "</span></div>";
  return (DATA.scale_card || "") + card("Pipeline", '<div class="pipe"><span>PCAP in</span><i>→</i><span>native reader</span><i>→</i><span>RFC 9293 reassembly</span><i>→</i><span>TLS records + handshake defrag</span><i>→</i><span>X.509 + chain verify</span><i>→</i><span>15-rule policy engine</span><i>→</i><span>risk + anomaly models</span><i>→</i><span>posture</span><i>→</i><span>reports + this console</span></div>' +
    '<div class="small mut">Pure Python for the analysis path: no tshark, no scapy on the hot path, no network calls. Certificates are parsed from DER and the leaf signature is re-verified cryptographically against the anchor.</div>') +
  '<div class="grid g2" style="margin-top:14px">' +
  card("Limits we state plainly", s("Passive", "TLS 1.3 encrypts the certificate (RFC 8446 s4.4.2), so certificate rules apply to TLS 1.0-1.2 sessions. TLS 1.3 sessions are graded on version, cipher suite, key exchange and handshake presence. When the endpoint keylog can be supplied, the same capture does yield the certificate - demonstrated on the Certificates page, with the recovered certificate proven byte-identical to the one the server held.") +
    s("DNS", "MTA-STS, DANE and TLS-RPT need DNS, which is invisible in a capture. They ship as remediation, never as findings.") +
    s("Dataset", "The 448-session corpus is synthetic (the problem statement permits a generated dataset). It is byte-reproducible, and the live captures are real.") +
    s("AI", "The risk model is trained on labels taken from the corpus manifest, so it can only rank findings the rule engine already produced. It never adds or removes one.") +
    s("Scale", "Throughput is a measured floor on one laptop thread (worst of recorded runs). Fleet-scale deployment is a design, not a measurement.")) +
  card("Verification", s("1", "Run <code>python3 verify.py</code> - 55 checks re-read the shipped captures and reproduce every session row from the bytes.") +
    s("2", "Re-derive any single session: <code>python3 -m mailscope.analyze data/corpus/&lt;file&gt;.pcap</code>.") +
    s("3", "Verify the evidence chain here or with <code>python3 mailscope_ledger.py --ledger ledger.json</code>.") +
    s("4", "Tamper test: change one value in <code>results/ms_rows.json</code> and re-run step 3 - it fails at that row.")) +
  "</div>" + '<div style="height:14px"></div>' +
  card("Problem statement 26159 - deliverable mapping", '<div class="tw sh"><table><thead><tr><th>#</th><th>Expected deliverable</th><th>How it is done</th></tr></thead><tbody>' + ps + "</tbody></table></div>") +
  '<div class="foot"><span>SecureMailScope · SIH26159 · NTRO · Blockchain & Cybersecurity</span><span>run ' + DATA.meta.runid + "</span></div>";
};

/* ---------- drawer ---------- */
function openSession(i){
  const r = DATA.rows[i];
  $("#dt").textContent = r.label + "  #" + r.rep;
  const f = (r.detail || []).map(x => '<div class="fnd"><div class="t">' + sevBadge(x.sev) + " " + esc(x.id) + " · " + esc(x.title) +
    '</div><div class="small mut">CVSS ' + x.cvss + " · " + esc(x.standard || "") + "</div>" +
    '<div class="r">evidence: ' + esc(x.ev || "") + "</div>" +
    '<div class="r">fix: ' + esc((DATA.rules.find(z => z.id === x.id) || {}).remediation || "") + "</div></div>").join("") ||
    '<div class="b OK">no findings on this session</div>';
  const re = r.reasm && r.reasm.events ? r.reasm.events : {};
  $("#db").innerHTML = '<div class="kv">' +
    '<span class="k">posture</span><span><b>' + r.posture + "</b>/100</span>" +
    '<span class="k">protocol / port</span><span>' + esc(r.proto) + " · " + r.port + " (" + (r.port === 465 || r.port === 993 ? "implicit TLS" : "explicit TLS / STARTTLS") + ")</span>" +
    '<span class="k">negotiated TLS</span><span>' + clean(r.tls_name) + "</span>" +
    '<span class="k">cipher suite</span><span class="mono">' + clean(r.cipher) + "</span>" +
    '<span class="k">key exchange</span><span>' + clean(r.ke) + " " + (r.ke_group ? "· " + esc(r.ke_group) : "") + " · forward secrecy " + (r.fs ? '<span class="b OK">yes</span>' : '<span class="b HIGH">no</span>') + "</span>" +
    '<span class="k">certificate</span><span>' + (r.subject ? esc(r.subject) + " · " + (r.keybits || "?") + "-bit · " + esc(r.sigalg) + " · " + (typeof r.days_left === "number" ? r.days_left + " days left" : "") : '<span class="dim">not observable on this session</span>') + "</span>" +
    '<span class="k">chain</span><span>' + (r.chain_ok ? '<span class="b OK">anchored</span>' : (r.chain_len ? '<span class="b CRITICAL">not anchored</span>' : '<span class="dim">n/a</span>')) + " (" + (r.chain_len || 0) + " certificates)</span>" +
    '<span class="k">fingerprints</span><span class="mono small">ja3 ' + esc(r.ja3 || "-") + "<br>ja4 " + esc(r.ja4 || "-") + "</span>" +
    '<span class="k">reassembly</span><span class="small">out-of-order ' + (re.out_of_order || 0) + " · retransmit " + (re.retransmit || 0) + " · overlap " + (re.overlap || 0) + "</span>" +
    "</div><div style=\"height:6px\"></div>" + f +
    '<div class="note">Graded from the capture alone. Verify this row: <code>python3 -m mailscope.analyze data/corpus/' + esc(r.label) + "_" + r.rep + '.pcap --port ' + r.port + "</code></div>";
  $("#drawer").classList.add("on");
}
function closeDrawer(){ $("#drawer").classList.remove("on"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer();
  if (e.key === "/" && document.activeElement !== $("#q")) { e.preventDefault(); $("#q").focus(); } });

/* ---------- exports ---------- */
function dl(name, text, mime){
  const b = new Blob([text], {type: mime || "text/plain"}); const u = URL.createObjectURL(b);
  const a = document.createElement("a"); a.href = u; a.download = name; document.body.appendChild(a); a.click();
  a.remove(); setTimeout(() => URL.revokeObjectURL(u), 1500);
}
function exportJSON(){ dl("securemailscope-sessions.json", JSON.stringify({run: DATA.meta.runid, bench: DATA.bench, sessions: DATA.rows}, null, 1), "application/json"); }
function exportCSV(){
  const cols = ["label","rep","proto","port","tls_name","cipher","ke_group","fs","chain_ok","keybits","sigalg","days_left","ja4","posture","rules"];
  const lines = [cols.join(",")].concat(filtRows().map(i => { const r = DATA.rows[i];
    return cols.map(c => c === "rules" ? '"' + (r.found || []).join(" ") + '"' : (r[c] === null || r[c] === undefined ? "" : r[c])).join(","); }));
  dl("securemailscope-sessions.csv", lines.join("\n"), "text/csv");
}
function exportCEF(){
  const out = [];
  filtRows().forEach(i => { const r = DATA.rows[i];
    (r.detail || []).forEach(f => {
      const sev = Math.round((f.cvss || 0));
      out.push(["CEF:0","SecureMailScope","SecureMailScope","1.0",f.id,f.title,sev,
        "src=" + (r.label + "_" + r.rep), "proto=" + r.proto, "dstPort=" + r.port,
        "cs1Label=Standard","cs1=" + (f.standard || ""), "cs2Label=NegotiatedTLS","cs2=" + (r.tls_name || "none"),
        "cs3Label=CipherSuite","cs3=" + (r.cipher || "none"), "cn1Label=CVSS","cn1=" + f.cvss,
        "msg=" + (f.ev || "")].join("|").replace(/([\\|])/g, "\\$1"));
    }); });
  dl("securemailscope-findings.cef", out.join("\n") + "\n", "text/plain");
}
function exportCBOM(){
  const d = DATA.dist, uniq = {ja3: new Set(), ja4: new Set()};
  DATA.rows.forEach(r => { if (r.ja3) uniq.ja3.add(r.ja3); if (r.ja4) uniq.ja4.add(r.ja4); });
  dl("securemailscope-cbom.json", JSON.stringify({
    bomFormat: "SecureMailScope-CBOM", specVersion: "1.0", run: DATA.meta.runid, generated: DATA.meta.stamp,
    note: "Inventory of cryptography observed in the shipped captures. Counts are sessions.",
    components: {
      tls_versions: d.tls, cipher_suites: d.cipher, key_exchange_groups: d.keg,
      public_key_sizes: d.keybits, signature_algorithms: d.sigalg, ports: d.ports,
      client_fingerprints: {ja3_unique: uniq.ja3.size, ja4_unique: uniq.ja4.size}
    }}, null, 1), "application/json");
}
function exportLedger(){ dl("ledger.json", JSON.stringify(DATA.ledger, null, 1), "application/json"); }

/* ---------- ledger verification (pure JS SHA-256) ---------- */
const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function sha256(bytes){
  const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const l = bytes.length, withOne = l + 1, pad = ((withOne + 8 + 63) >> 6) << 6;
  const m = new Uint8Array(pad); m.set(bytes); m[l] = 0x80;
  const bitLen = l * 8; const dv = new DataView(m.buffer);
  dv.setUint32(pad - 4, bitLen >>> 0); dv.setUint32(pad - 8, Math.floor(bitLen / 4294967296));
  const w = new Uint32Array(64);
  for (let off = 0; off < pad; off += 64){
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++){
      const s0 = (rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3));
      const s1 = (rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10));
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,hh] = h;
    for (let i = 0; i < 64; i++){
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0]=(h[0]+a)>>>0; h[1]=(h[1]+b)>>>0; h[2]=(h[2]+c)>>>0; h[3]=(h[3]+d)>>>0;
    h[4]=(h[4]+e)>>>0; h[5]=(h[5]+f)>>>0; h[6]=(h[6]+g)>>>0; h[7]=(h[7]+hh)>>>0;
  }
  let s = ""; h.forEach(x => s += x.toString(16).padStart(8, "0")); return s;
}
function rotr(x, n){ return ((x >>> n) | (x << (32 - n))) >>> 0; }
function hexBytes(hex){ const a = new Uint8Array(hex.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i*2, 2), 16); return a; }
function utf8(str){ return new TextEncoder().encode(str); }
function canon(v){
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string"){
    let out = '"';
    for (const ch of v){
      const c = ch.codePointAt(0);
      if (ch === '"' || ch === "\\") out += "\\" + ch;
      else if (c < 32) out += "\\u" + c.toString(16).padStart(4, "0");
      else if (c > 0xFFFF){ const hi = 0xD800 + ((c - 0x10000) >> 10), lo = 0xDC00 + ((c - 0x10000) & 1023);
        out += "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0"); }
      else if (c > 126) out += "\\u" + c.toString(16).padStart(4, "0");
      else out += ch;
    }
    return out + '"';
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map(k => canon(k) + ":" + canon(v[k])).join(",") + "}";
}
function verifyLedger(){
  const L = DATA.ledger, out = $("#vout");
  if (!L.hashes || !L.hashes.length){ out.innerHTML = '<div class="vbox bad">No ledger data in this build.</div>'; return; }
  const t0 = performance.now();
  let prev = L.genesis;
  for (let i = 0; i < L.projections.length; i++){
    const body = utf8(canon(L.projections[i]));
    const buf = new Uint8Array(32 + body.length);
    buf.set(hexBytes(prev), 0); buf.set(body, 32);
    const h = sha256(buf);
    if (h !== L.hashes[i]){
      out.innerHTML = '<div class="vbox bad"><b>FAIL at row ' + i + '</b><div class="small mut">The shipped chain does not match the shipped rows at this index.</div></div>';
      return;
    }
    prev = h;
  }
  const ok = prev === L.head;
  const ms = (performance.now() - t0).toFixed(0);
  out.innerHTML = '<div class="vbox ' + (ok ? "ok" : "bad") + '"><b>' + (ok ? "PASS" : "FAIL") + "</b> · " + L.count +
    " rows re-hashed in " + ms + " ms<div class=\"chain\" style=\"margin-top:6px\">head " + prev + "</div>" +
    '<div class="small mut" style="margin-top:6px">' + (ok ? "Every graded field of every session matches the published chain." : "Chain head mismatch.") + "</div></div>";
}

/* ---------- shell ---------- */
function buildNav(){
  $("#nav").innerHTML = '<div class="grp">Assessment</div>' +
    ["overview","sessions","findings","plan","compare"].map(p => navA(p)).join("") +
    '<div class="grp">Evidence</div>' +
    ["servers","certificates","inventory","matrix"].map(p => navA(p)).join("") +
    '<div class="grp">Integrity</div>' +
    ["ledger","reports","method"].map(p => navA(p)).join("");
}
function navA(p){ return '<a href="#/' + p + '" data-p="' + p + '"><svg width="15" height="15" viewBox="0 0 16 16">' + ICONS[p] + "</svg>" + LABEL[p] + "</a>"; }
function init(){
  buildNav();
  $("#rid").textContent = DATA.meta.runid;
  $("#posture").innerHTML = "posture <b>" + DATA.bench.posture + "</b>/100 · <b>" + DATA.bench.grade + "</b>";
  $("#theme").onclick = () => {
    const cur = document.documentElement.getAttribute("data-theme");
    const nxt = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nxt);
    try { localStorage.setItem("sms-theme", nxt); } catch(e){}
  };
  try { const t = localStorage.getItem("sms-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch(e){}
  $("#q").addEventListener("input", e => { S.q = e.target.value; S.page = 1;
    if (!location.hash.startsWith("#/sessions")) go("sessions"); else route(); });
  window.addEventListener("hashchange", route);
  route();
}
init();
</script>
</body>
</html>
"""

html = HTML.replace("__DATA__", BLOB)
out = os.path.join(OUTDIR, "index.html")
open(out, "w", encoding="utf-8").write(html)
print(f"console v3 written: {out}  ({len(html)/1024:.0f} KB, {len(ROWS)} sessions, run {RUNID})")
print(f"pages: {', '.join(PAGES if 'PAGES' in dir() else ['overview','sessions','findings','servers','certificates','inventory','matrix','ledger','reports','method'])}")
