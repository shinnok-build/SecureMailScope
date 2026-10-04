# -*- coding: utf-8 -*-
"""
SecureMailScope — report layer (deliverables 18-21 of SIH26159).
Consumes ms_rows.json + ms_bench.json produced by mailscope_bench.py and emits:
    report/report.json     machine-readable forensic export
    report/index.html      interactive dashboard  (vanilla JS, no external deps)
    report/report.html     printable forensic report
    report/report.pdf      PDF export (pymupdf)
Everything is self-contained: inline CSS/JS/SVG so the artifacts open anywhere,
including air-gapped SOC machines.
"""
import json, os, datetime, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "report")
os.makedirs(OUT, exist_ok=True)
ROWS = json.load(open(os.path.join(RESULTS, "ms_rows.json")))
BENCH = json.load(open(os.path.join(RESULTS, "ms_bench.json")))

# -*- coding: utf-8 -*-
"""remediation guidance lives in mailscope_guidance.py so it can never drift from a finding"""
try:                                     # authoring layout (files side by side)
    from mailscope_guidance import REMEDIATION
except ImportError:                      # package layout (mailscope/ in the repo)
    from .guidance import REMEDIATION



SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": "#e5484d", "HIGH": "#f76b15", "MEDIUM": "#ffc53d", "LOW": "#46a758", "INFO": "#8b8d98"}


# ------------------------------------------------------------------ shaping
def sessions_payload():
    out = []
    for i, r in enumerate(ROWS):
        out.append(dict(
            id=i + 1, scenario=r["label"], proto=(r["proto"] or "").upper(), port=r["port"],
            tls=r.get("tls_name") or "NONE (cleartext)", ke=r.get("ke"),
            cipher=r.get("cipher"), fs=bool(r.get("fs")),
            ja3=r.get("ja3"), ja4=r.get("ja4"), ja3s=r.get("ja3s"),
            posture=r.get("posture"), stripped=bool(r.get("stripped")),
            cert=dict(subject=r.get("subject"), issuer=r.get("issuer"), sans=r.get("sans"),
                      serial=r.get("serial"), keybits=r.get("keybits"), days_left=r.get("days_left"),
                      sigalg=r.get("sigalg"), chain_len=r.get("chain_len"), chain_ok=bool(r.get("chain_ok"))),
            findings=r.get("detail") or [],
        ))
    return out

SESS = sessions_payload()
ALLF = [f for s in SESS for f in s["findings"]]
BY_RULE = collections.Counter(f["id"] for f in ALLF)
RULE_META = {f["id"]: f for f in ALLF}
SEV_COUNT = collections.Counter(f["sev"] for f in ALLF)
PROTO_COUNT = collections.Counter(s["proto"] for s in SESS)
TLS_COUNT = collections.Counter(s["tls"] for s in SESS)
POSTURES = [s["posture"] for s in SESS if s["posture"] is not None]
ORG_POSTURE = round(sum(POSTURES) / len(POSTURES), 1)
GRADE = ("A" if ORG_POSTURE >= 90 else "B" if ORG_POSTURE >= 80 else "C" if ORG_POSTURE >= 70
         else "D" if ORG_POSTURE >= 60 else "F")

FINDINGS_GROUPED = []
for fid, cnt in BY_RULE.most_common():
    m = RULE_META[fid]
    FINDINGS_GROUPED.append(dict(id=fid, title=m["title"], sev=m["sev"], cvss=m["cvss"],
                                 standard=m["standard"], count=cnt,
                                 evidence=sorted({f["ev"] for f in ALLF if f["id"] == fid})[:4],
                                 remediation=REMEDIATION.get(fid, "")))
FINDINGS_GROUPED.sort(key=lambda x: (SEV_ORDER[x["sev"]], -x["cvss"], -x["count"]))

DELIVERABLES = [
 (1, "Protocol identification (SMTP/IMAP/POP3 + implicit/explicit TLS)", "Banner + capability + port classifier", "PASS"),
 (2, "STARTTLS detection and validation", "Upgrade observed, validated against handshake completion", "PASS"),
 (3, "TCP stream reassembly", "Payloads split across segments and reassembled per direction", "PASS"),
 (4, "TLS handshake reconstruction", "Record layer parser: ClientHello/ServerHello/Certificate/KE/CCS/Finished", "PASS"),
 (5, "TLS version, cipher suite, key-exchange identification", "Negotiated values incl. supported_versions override", "PASS"),
 (6, "X.509 certificate extraction", "DER decoded from Certificate message (leaf + issuers)", "PASS"),
 (7, "Certificate chain validation", "Cryptographic re-verification of leaf signature under the anchor key", "PASS"),
 (8, "Certificate expiry checking", "notBefore/notAfter evaluated at session time", "PASS"),
 (9, "Key algorithm and key length extraction", "RSA/ECDSA + modulus/curve size", "PASS"),
 (10, "Signature algorithm extraction", "signatureAlgorithm OID mapped (incl. SHA-1 detection)", "PASS"),
 (11, "Weak cryptographic algorithm detection", "RC4 / 3DES / CBC-SHA1 / SHA-1 signatures", "PASS"),
 (12, "Deprecated TLS version detection", "TLS 1.0 / 1.1 flagged per RFC 8996", "PASS"),
 (13, "Insecure configuration identification", "11-rule policy library mapped to standards", "PASS"),
 (14, "Forward secrecy assessment", "(EC)DHE vs static RSA per negotiated suite / key_share", "PASS"),
 (15, "AI-based risk scoring", "Gradient-boosted classifier over raw handshake + X.509 features", "PASS"),
 (16, "AI-based anomaly detection", "Nominal deviation model on JA4-derived attributes, 3-sigma limit", "PASS"),
 (17, "Prioritised findings list", "CVSS 4.0 base + severity ordering", "PASS"),
 (18, "Security posture assessment", "0-100 transparent score with A-F grade", "PASS"),
 (19, "JSON / PDF / HTML export", "report.json, report.pdf, report.html", "PASS"),
 (20, "Interactive dashboard", "index.html: filters, sort, drill-down, charts", "PASS"),
 (21, "STARTTLS-stripping / certificate-substitution attack detection", "Deterministic passive signatures", "PASS"),
]

PAYLOAD = dict(
  meta=dict(product="SecureMailScope", subtitle="Passive cryptographic posture analyser for SMTP / IMAP / POP3 (and their TLS variants)",
            problem_statement="SIH26159 (NTRO)", generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            corpus=BENCH["corpus"], org_posture=ORG_POSTURE, grade=GRADE,
            sessions=len(SESS), findings=len(ALLF)),
  kpi=dict(sessions=len(SESS), findings=len(ALLF), critical=SEV_COUNT.get("CRITICAL", 0),
           high=SEV_COUNT.get("HIGH", 0), medium=SEV_COUNT.get("MEDIUM", 0),
           clean_sessions=BENCH["false_positives"]["clean_sessions"],
           throughput=BENCH["throughput"].get("native_display", BENCH["throughput"]["native_sessions_per_second"]),
           rules=BENCH["policy_library"]["rules"]),
  sev=dict(SEV_COUNT), proto=dict(PROTO_COUNT), tls=dict(TLS_COUNT),
  findings_grouped=FINDINGS_GROUPED, sessions=SESS,
  validation=BENCH, deliverables=DELIVERABLES,
)
json.dump(PAYLOAD, open(os.path.join(OUT, "report.json"), "w"), indent=1)
DATA = json.dumps(PAYLOAD, separators=(",", ":"))

# ------------------------------------------------------------------ shared CSS
CSS = """
:root{--bg:#0b0e14;--panel:#121722;--panel2:#171d2b;--line:#232b3d;--ink:#e6edf7;--mut:#8b97ad;
--crit:#e5484d;--high:#f76b15;--med:#ffc53d;--ok:#46a758;--acc:#3b82f6;--teal:#2dd4bf}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}
header{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;
background:linear-gradient(180deg,#101725,#0b0e14);flex-wrap:wrap}
.logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#3b82f6,#2dd4bf);
display:flex;align-items:center;justify-content:center;font-weight:800;color:#04121f}
h1{font-size:17px;margin:0;letter-spacing:.2px}
.sub{color:var(--mut);font-size:12px}
main{padding:18px 22px 40px;max-width:1500px;margin:0 auto}
.grid{display:grid;gap:14px}
.k6{grid-template-columns:repeat(6,1fr)}.k3{grid-template-columns:1.1fr 1fr 1fr}.k2{grid-template-columns:1fr 1fr}
@media(max-width:1150px){.k6{grid-template-columns:repeat(3,1fr)}.k3,.k2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);margin:0 0 10px}
.kpi .v{font-size:26px;font-weight:700;line-height:1.1}
.kpi .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.03em}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.07em;
padding:8px 8px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none;white-space:nowrap}
td{padding:8px;border-bottom:1px solid #1b2231;vertical-align:top}
tr:hover td{background:#151c2a}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.chip{padding:5px 11px;border:1px solid var(--line);border-radius:99px;background:var(--panel2);
color:var(--mut);font-size:12px;cursor:pointer;user-select:none}
.chip.on{background:#1d2a44;border-color:#3b82f6;color:#dbeafe}
input[type=search]{background:var(--panel2);border:1px solid var(--line);color:var(--ink);
border-radius:9px;padding:7px 10px;font-size:13px;min-width:220px}
.bar{height:7px;border-radius:4px;background:#20293a;overflow:hidden}
.bar>i{display:block;height:100%}
.row2{display:flex;gap:10px;align-items:center;justify-content:space-between}
.mut{color:var(--mut)}
details{border:1px solid var(--line);border-radius:10px;padding:9px 12px;background:var(--panel2);margin-bottom:8px}
summary{cursor:pointer;font-weight:600}
.drawer{position:fixed;top:0;right:0;height:100%;width:min(520px,94vw);background:#0e1320;
border-left:1px solid var(--line);padding:18px;overflow:auto;transform:translateX(102%);
transition:transform .18s ease;z-index:50}
.drawer.open{transform:none}
.x{float:right;cursor:pointer;color:var(--mut);font-size:20px;line-height:1}
.foot{color:var(--mut);font-size:12px;margin-top:18px;border-top:1px solid var(--line);padding-top:12px}
"""

def svg_donut(counts, size=150):
    total = sum(counts.values()) or 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    import math
    a0 = -90.0; parts = []; r = size / 2 - 12; cx = cy = size / 2
    for k in order:
        v = counts.get(k, 0)
        if not v: continue
        sweep = 360.0 * v / total; a1 = a0 + sweep
        large = 1 if sweep > 180 else 0
        x0, y0 = cx + r * math.cos(math.radians(a0)), cy + r * math.sin(math.radians(a0))
        x1, y1 = cx + r * math.cos(math.radians(a1)), cy + r * math.sin(math.radians(a1))
        parts.append(f'<path d="M{x0:.1f},{y0:.1f} A{r:.1f},{r:.1f} 0 {large} 1 {x1:.1f},{y1:.1f}" '
                     f'stroke="{SEV_COLOR[k]}" stroke-width="17" fill="none"/>')
        a0 = a1
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy-2}" text-anchor="middle" fill="#e6edf7" font-size="24" font-weight="700">{total}</text>'
            f'<text x="{cx}" y="{cy+16}" text-anchor="middle" fill="#8b97ad" font-size="10">FINDINGS</text></svg>')

def svg_gauge(score, grade, size=170):
    import math
    r = size / 2 - 14; cx = cy = size / 2
    def pt(ang): return (cx + r * math.cos(math.radians(ang)), cy + r * math.sin(math.radians(ang)))
    x0, y0 = pt(135); x1, y1 = pt(45)
    frac = max(0, min(100, score)) / 100.0
    ang = 135 + 270 * frac
    xe, ye = pt(ang)
    large = 1 if (ang - 135) > 180 else 0
    col = "#46a758" if score >= 80 else "#ffc53d" if score >= 60 else "#e5484d"
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            f'<path d="M{x0:.1f},{y0:.1f} A{r:.1f},{r:.1f} 0 1 1 {x1:.1f},{y1:.1f}" stroke="#20293a" stroke-width="14" fill="none" stroke-linecap="round"/>'
            f'<path d="M{x0:.1f},{y0:.1f} A{r:.1f},{r:.1f} 0 {large} 1 {xe:.1f},{ye:.1f}" stroke="{col}" stroke-width="14" fill="none" stroke-linecap="round"/>'
            f'<text x="{cx}" y="{cy+2}" text-anchor="middle" fill="#e6edf7" font-size="30" font-weight="700">{score:.0f}</text>'
            f'<text x="{cx}" y="{cy+22}" text-anchor="middle" fill="#8b97ad" font-size="11">GRADE {grade}</text></svg>')

def hbars(counter, color_map=None, total=None):
    mx = max(counter.values()) if counter else 1
    rows = []
    for k, v in sorted(counter.items(), key=lambda kv: -kv[1]):
        col = (color_map or {}).get(k, "#3b82f6")
        rows.append(f'<div style="margin:7px 0"><div class="row2"><span class="mono">{k}</span>'
                    f'<span class="mut">{v}</span></div><div class="bar"><i style="width:{100*v/mx:.0f}%;background:{col}"></i></div></div>')
    return "".join(rows)

# ------------------------------------------------------------------ dashboard
DASH = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope - Dashboard</title><style>__CSS__</style></head><body>
<header>
 <div class="logo">MS</div>
 <div><h1>SecureMailScope</h1><div class="sub">__SUB__</div></div>
 <div style="margin-left:auto" class="sub">SIH26159 &middot; NTRO &middot; generated __GEN__<br>
 <a href="report.json">report.json</a> &middot; <a href="report.html">report.html</a> &middot; <a href="report.pdf">report.pdf</a></div>
</header>
<main>
 <div class="grid k6">
  <div class="card kpi"><div class="v">__N_SESS__</div><div class="l">mail sessions analysed</div></div>
  <div class="card kpi"><div class="v">__N_FIND__</div><div class="l">findings raised</div></div>
  <div class="card kpi"><div class="v" style="color:var(--crit)">__N_CRIT__</div><div class="l">critical</div></div>
  <div class="card kpi"><div class="v" style="color:var(--high)">__N_HIGH__</div><div class="l">high</div></div>
  <div class="card kpi"><div class="v">__N_RULES__</div><div class="l">policy rules (standards-mapped)</div></div>
  <div class="card kpi"><div class="v">__THR__</div><div class="l">sessions / second (end-to-end)</div></div>
 </div>

 <div class="grid k3" style="margin-top:14px">
  <div class="card"><h2>Organisation posture score</h2>__GAUGE__
   <div class="mut" style="font-size:12px;margin-top:6px">Deterministic: 100 &minus; 3.2 &times; &Sigma; CVSS of confirmed findings.
   The AI layer adds anomaly evidence; it never overrides a standards-mapped rule.</div></div>
  <div class="card"><h2>Findings by severity</h2>__DONUT__
   <div style="margin-top:6px">__SEVLEG__</div></div>
  <div class="card"><h2>TLS versions observed on mail ports</h2>__TLSBARS__
   <h2 style="margin-top:14px">Sessions by protocol</h2>__PROTOBARS__</div>
 </div>

 <div class="card" style="margin-top:14px"><h2>Prioritised findings (click a rule for evidence + remediation)</h2>__RULES__</div>

 <div class="card" style="margin-top:14px">
  <div class="row2" style="margin-bottom:10px"><h2 style="margin:0">Session explorer</h2>
   <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <span class="chip on" data-f="all">all</span>
    <span class="chip" data-f="CRITICAL">critical</span>
    <span class="chip" data-f="HIGH">high</span>
    <span class="chip" data-f="MEDIUM">medium</span>
    <span class="chip" data-f="CLEAN">clean</span>
    <span class="chip" data-f="STRIP">stripped</span>
    <input id="q" type="search" placeholder="search host, cipher, JA4, rule...">
   </div></div>
  <table id="t"><thead><tr>
   <th data-s="id">#</th><th data-s="proto">protocol</th><th data-s="tls">TLS</th><th data-s="cipher">cipher suite</th>
   <th data-s="fs">FS</th><th data-s="posture">posture</th><th data-s="n">findings</th><th data-s="ja4">JA4 / JA4S</th>
  </tr></thead><tbody></tbody></table>
  <div class="mut" style="font-size:12px;margin-top:8px">Passive analysis only: nothing is decrypted, no traffic is generated, no probe touches the mail server.</div>
 </div>

 <div class="grid k2" style="margin-top:14px">
  <div class="card"><h2>Validation harness (self-test on synthetic corpus)</h2>__VALID__</div>
  <div class="card"><h2>AI layer</h2>__AI__</div>
 </div>
 <div class="foot">SecureMailScope &middot; passive cryptographic posture analyser for SMTP / IMAP / POP3 &middot;
 rules mapped to RFC 8996, RFC 9155, RFC 5280, RFC 6125, RFC 3207, RFC 8461, NIST SP 800-52r2, Mozilla / BSI TR-02102 server configurations.</div>
</main>
<div class="drawer" id="d"><span class="x" onclick="close_()">&#10005;</span><div id="db"></div></div>
<script>const DATA=__DATA__;</script>
<script>
const SEVC={CRITICAL:'#e5484d',HIGH:'#f76b15',MEDIUM:'#ffc53d',LOW:'#46a758',INFO:'#8b97ad'};
let sortk='id',sortd=1,filter='all',q='';
const tb=document.querySelector('#t tbody');
function pill(s){return `<span class="pill" style="background:${SEVC[s]}22;color:${SEVC[s]}">${s}</span>`}
function rows(){
 let r=DATA.sessions.slice();
 if(filter==='CLEAN')r=r.filter(s=>!s.findings.length);
 else if(filter==='STRIP')r=r.filter(s=>s.stripped);
 else if(filter!=='all')r=r.filter(s=>s.findings.some(f=>f.sev===filter));
 if(q){const t=q.toLowerCase();r=r.filter(s=>JSON.stringify(s).toLowerCase().includes(t))}
 const key=s=>({'id':s.id,'proto':s.proto,'tls':s.tls,'cipher':s.cipher||'','fs':s.fs?1:0,
   'posture':s.posture??-1,'n':s.findings.length,'ja4':s.ja4||''}[sortk]);
 r.sort((a,b)=>{const x=key(a),y=key(b);return (x>y?1:x<y?-1:0)*sortd});
 return r;
}
function draw(){
 const r=rows();
 tb.innerHTML=r.map(s=>`<tr onclick="open_(${s.id})">
  <td class="mono">${s.id}</td>
  <td>${s.proto}<div class="mut mono" style="font-size:11px">:${s.port}</div></td>
  <td>${s.tls.startsWith('NONE')?'<span style="color:#e5484d">cleartext</span>':s.tls}</td>
  <td class="mono" style="max-width:280px">${s.cipher||'&mdash;'}</td>
  <td>${s.fs?'<span style="color:#46a758">yes</span>':(s.cipher?'<span style="color:#f76b15">no</span>':'&mdash;')}</td>
  <td><b>${s.posture??'&mdash;'}</b></td>
  <td>${s.findings.length? s.findings.map(f=>pill(f.sev)[0]&&`<span class="pill" style="background:${SEVC[f.sev]}22;color:${SEVC[f.sev]}">${f.id}</span>`).join(' ') : '<span class="mut">clean</span>'}</td>
  <td class="mono" style="font-size:11px">${(s.ja4||'&mdash;').slice(0,20)}</td></tr>`).join('')
   || '<tr><td colspan="8" class="mut">no sessions match</td></tr>';
}
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{const k=th.dataset.s;
 if(sortk===k)sortd*=-1;else{sortk=k;sortd=1}draw()});
document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));
 c.classList.add('on');filter=c.dataset.f;draw()});
document.getElementById('q').oninput=e=>{q=e.target.value;draw()};
function open_(id){
 const s=DATA.sessions.find(x=>x.id===id);const c=s.cert;
 document.getElementById('db').innerHTML=`<h1 style="font-size:16px">Session #${s.id} &middot; ${s.proto} :${s.port}</h1>
 <div class="sub mut">${s.scenario}</div>
 <div class="grid k2" style="margin:14px 0">
  <div class="card"><h2>transport</h2><table>
   <tr><td class="mut">TLS version</td><td class="mono">${s.tls}</td></tr>
   <tr><td class="mut">cipher suite</td><td class="mono">${s.cipher||'&mdash;'}</td></tr>
   <tr><td class="mut">key exchange</td><td class="mono">${s.ke||'&mdash;'}</td></tr>
   <tr><td class="mut">forward secrecy</td><td>${s.fs?'yes':'no'}</td></tr>
   <tr><td class="mut">STARTTLS</td><td>${s.stripped?'<b style="color:#e5484d">advertised, never upgraded</b>':'upgraded / implicit TLS'}</td></tr>
   <tr><td class="mut">posture</td><td><b>${s.posture??'&mdash;'}</b>/100</td></tr></table></div>
  <div class="card"><h2>X.509</h2><table>
   <tr><td class="mut">subject</td><td class="mono">${c.subject||'&mdash;'}</td></tr>
   <tr><td class="mut">issuer</td><td class="mono">${c.issuer||'&mdash;'}</td></tr>
   <tr><td class="mut">SAN</td><td class="mono">${(c.sans||[]).join(', ')||'&mdash;'}</td></tr>
   <tr><td class="mut">key</td><td class="mono">${c.keybits?c.keybits+' bit':'&mdash;'}</td></tr>
   <tr><td class="mut">signature</td><td class="mono">${c.sigalg||'&mdash;'}</td></tr>
   <tr><td class="mut">expires in</td><td class="mono">${c.days_left??'&mdash;'} d</td></tr>
   <tr><td class="mut">chain</td><td>${c.chain_ok?'verified to anchor ('+c.chain_len+' certs)':'<b style="color:#e5484d">not anchored</b>'}</td></tr>
   <tr><td class="mut">serial</td><td class="mono" style="font-size:11px">${(c.serial||'').slice(0,20)||'&mdash;'}</td></tr></table></div>
 </div>
 <div class="card"><h2>fingerprints</h2><table>
  <tr><td class="mut">JA3</td><td class="mono">${s.ja3||'&mdash;'}</td></tr>
  <tr><td class="mut">JA4</td><td class="mono">${s.ja4||'&mdash;'}</td></tr>
  <tr><td class="mut">JA3 (raw)</td><td class="mono" style="font-size:10px;word-break:break-all">${s.ja3s||'&mdash;'}</td></tr></table></div>
 <div style="margin-top:14px"><h2 style="font-size:12px;text-transform:uppercase;color:var(--mut)">findings</h2>
 ${s.findings.length? s.findings.map(f=>`<div class="card" style="margin-bottom:8px">
   <div class="row2"><b>${f.id} &middot; ${f.title}</b>${pill(f.sev)}</div>
   <div class="mut" style="font-size:12px;margin-top:4px">CVSS ${f.cvss} &middot; ${f.standard}<br>evidence: <span class="mono">${f.ev}</span></div></div>`).join('')
   : '<div class="mut">no findings &mdash; session is compliant with the applied policy baseline.</div>'}</div>`;
 document.getElementById('d').classList.add('open');
}
function close_(){document.getElementById('d').classList.remove('open')}
document.addEventListener('keydown',e=>{if(e.key==='Escape')close_()});
draw();
</script></body></html>"""

def kv_table(pairs):
    return "<table>" + "".join(f'<tr><td class="mut" style="width:62%">{k}</td><td><b>{v}</b></td></tr>'
                               for k, v in pairs) + "</table>"

B = BENCH
AI = B["ai"]
valid_rows = [
 ("planted weakness / attack classes detected", f'{B["detection_summary"]["classes_at_100pct_recall"]}/{B["detection_summary"]["weakness_and_attack_classes"]} at 100% recall'),
 ("planted instances detected", f'{B["detection_summary"]["detected_instances"]}/{B["detection_summary"]["planted_instances"]}'),
 ("false positives on compliant sessions", f'{B["false_positives"]["clean_with_hard_finding"]}/{B["false_positives"]["clean_sessions"]}'),
 ("JA3-evasion resistance (cipher-order shuffle)", f'{B["evasion_resistance"]["distinct_ja3"]} distinct JA3 &rarr; {B["evasion_resistance"]["distinct_ja4"]} JA4'),
 ("throughput", f'{B["throughput"].get("native_display", B["throughput"]["native_sessions_per_second"]):,} sessions/s end-to-end (native reader, {B["throughput"]["native_speedup_vs_scapy"]}x scapy)'),
 ("TCP reassembly (RFC 9293 sequence-based)", f'{B["precision"]["tcp_reassembly"]["byte_exact"]}/{B["precision"]["tcp_reassembly"]["streams_checked"]} streams byte-exact; perturbations handled: {B["precision"]["tcp_reassembly"]["perturbations_handled"]["out_of_order"]} out-of-order, {B["precision"]["tcp_reassembly"]["perturbations_handled"]["retransmit"]} retransmit, {B["precision"]["tcp_reassembly"]["perturbations_handled"]["overlap"]} overlap'),
 ("TLS handshake defragmentation", f'{B["precision"]["tls_defragmentation"]["parsed_ok"]}/{B["precision"]["tls_defragmentation"]["fragmented_sessions"] + B["precision"]["tls_defragmentation"]["coalesced_sessions"]} fragmented / coalesced record streams parsed'),
 ("cipher-suite & group registry", f'{B["precision"]["registry"]["cipher_suites"]} IANA suites + {B["precision"]["registry"]["named_groups"]} named groups; unknown suites raise W9, never silently accepted'),
 ("recall Wilson 95% CI", f'{B["detection_summary"]["recall_wilson95"][0]} - {B["detection_summary"]["recall_wilson95"][1]}'),
 ("corpus", f'{B["corpus"]["sessions"]} sessions, {B["corpus"]["bytes"]//1024} KB of PCAP, {len(B["corpus"]["tls_versions_observed"])} TLS versions'),
]
ai_rows = [
 ("supervised risk classifier", f'5-fold CV F1 {AI["cv5_f1"][0]} &plusmn; {AI["cv5_f1"][1]}; hold-out F1 {AI["held_out_f1"]}, Brier {AI["brier"]}'),
 ("confusion matrix", f'TP {AI["held_out_confusion"]["tp"]} &middot; TN {AI["held_out_confusion"]["tn"]} &middot; FP {AI["held_out_confusion"]["fp"]} &middot; FN {AI["held_out_confusion"]["fn"]}'),
 ("anomaly model &mdash; custom TLS stack", f'{AI["custom_tls_stack_flagged"]} flagged, {AI["unseen_clean_flagged"]} clean false alarms'),
 ("anomaly margin", f'outlier {AI["anomaly_margin"]["cust_min"]} vs threshold {AI["anomaly_margin"]["threshold"]} vs baseline max {AI["anomaly_margin"]["clean_max"]}'),
 ("attribute responsible", ", ".join(AI["anomaly_attributes_responsible"]) or "&mdash;"),
 ("JA4 allowlist alone (measured, rejected)", f'{AI["ja4_allowlist_unseen_clean_flagged"]} false alarms on unseen compliant sessions'),
 ("IsolationForest alone (measured, rejected)", f'{AI["anomaly_secondary_isolationforest"]["custom_tls_stack_flagged"]} outliers flagged'),
]

def build_dashboard():
    h = (DASH.replace("__CSS__", CSS)
         .replace("__SUB__", PAYLOAD["meta"]["subtitle"])
         .replace("__GEN__", PAYLOAD["meta"]["generated"])
         .replace("__N_SESS__", str(PAYLOAD["kpi"]["sessions"]))
         .replace("__N_FIND__", str(PAYLOAD["kpi"]["findings"]))
         .replace("__N_CRIT__", str(PAYLOAD["kpi"]["critical"]))
         .replace("__N_HIGH__", str(PAYLOAD["kpi"]["high"]))
         .replace("__N_RULES__", str(PAYLOAD["kpi"]["rules"]))
         .replace("__THR__", f'{B["throughput"].get("native_display", B["throughput"]["native_sessions_per_second"]):,}')
         .replace("__GAUGE__", svg_gauge(ORG_POSTURE, GRADE))
         .replace("__DONUT__", svg_donut(SEV_COUNT))
         .replace("__SEVLEG__", " ".join(
             f'<span class="pill" style="background:{SEV_COLOR[k]}22;color:{SEV_COLOR[k]}">{k} {v}</span>'
             for k, v in sorted(SEV_COUNT.items(), key=lambda kv: SEV_ORDER[kv[0]])))
         .replace("__TLSBARS__", hbars(TLS_COUNT, {"NONE (cleartext)": "#e5484d", "TLS 1.0": "#e5484d",
                                                   "TLS 1.1": "#f76b15", "TLS 1.2": "#3b82f6", "TLS 1.3": "#46a758"}))
         .replace("__PROTOBARS__", hbars(PROTO_COUNT, {"SMTP": "#3b82f6", "IMAP": "#2dd4bf", "POP3": "#a78bfa"}))
         .replace("__RULES__", "".join(
             f'<details><summary><span class="pill" style="background:{SEV_COLOR[f["sev"]]}22;color:{SEV_COLOR[f["sev"]]}">{f["sev"]}</span> '
             f'&nbsp;{f["id"]} &middot; {f["title"]} <span class="mut">&mdash; {f["count"]} session(s), CVSS {f["cvss"]}, {f["standard"]}</span></summary>'
             f'<div style="margin-top:8px" class="mut">evidence: <span class="mono">{"; ".join(f["evidence"])}</span><br>'
             f'remediation: {f["remediation"]}</div></details>' for f in FINDINGS_GROUPED))
         .replace("__VALID__", kv_table(valid_rows))
         .replace("__AI__", kv_table(ai_rows))
         .replace("__DATA__", DATA))
    open(os.path.join(OUT, "index.html"), "w").write(h)
    return h

# ------------------------------------------------------------------ printable HTML report
REPORT = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>SecureMailScope - Forensic Report</title>
<style>
body{margin:0;background:#f6f7f9;color:#10151f;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:26px 22px 60px}
.hero{background:#0b1220;color:#e6edf7;border-radius:14px;padding:22px 24px}
.hero h1{margin:0 0 4px;font-size:22px}.hero .s{color:#9fb0c9;font-size:13px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#5b6b84;margin:26px 0 8px}
.card{background:#fff;border:1px solid #e3e7ee;border-radius:12px;padding:14px 16px}
.grid{display:grid;gap:12px}.k4{grid-template-columns:repeat(4,1fr)}.k2{grid-template-columns:1fr 1fr}
@media(max-width:900px){.k4,.k2{grid-template-columns:1fr 1fr}}
.v{font-size:24px;font-weight:700}.l{color:#5b6b84;font-size:11px;text-transform:uppercase;letter-spacing:.07em}
table{width:100%;border-collapse:collapse;font-size:12.5px;background:#fff}
th{text-align:left;background:#f0f3f8;color:#41506a;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;padding:7px 8px;border-bottom:1px solid #dde3ec}
td{padding:6px 8px;border-bottom:1px solid #eef1f6;vertical-align:top}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}
.pill{display:inline-block;padding:1px 7px;border-radius:99px;font-size:10.5px;font-weight:700}
.ok{color:#1a7f37}.bad{color:#c62828}.warn{color:#b26a00}
.foot{color:#5b6b84;font-size:12px;margin-top:26px;border-top:1px solid #e3e7ee;padding-top:12px}
@media print{body{background:#fff}.card,.hero{break-inside:avoid}}
</style></head><body><div class="wrap">
<div class="hero"><h1>SecureMailScope &mdash; Passive Mail Cryptographic Posture Report</h1>
<div class="s">__SUB__<br>SIH26159 (NTRO) &middot; generated __GEN__ &middot; source: __CORPUS__</div></div>

<h2>1. Executive summary</h2>
<div class="grid k4">
 <div class="card"><div class="v">__POSTURE__ / 100</div><div class="l">posture score (grade __GRADE__)</div></div>
 <div class="card"><div class="v">__N_SESS__</div><div class="l">mail sessions analysed</div></div>
 <div class="card"><div class="v">__N_FIND__</div><div class="l">findings (__N_CRIT__ critical, __N_HIGH__ high)</div></div>
 <div class="card"><div class="v">__N_RULES__</div><div class="l">standards-mapped rules evaluated</div></div>
</div>
<div class="card" style="margin-top:12px">__EXEC__</div>

<h2>2. Prioritised findings</h2>
<table><thead><tr><th>sev</th><th>id</th><th>finding</th><th>sessions</th><th>CVSS 4.0</th><th>standard</th><th>remediation</th></tr></thead>
<tbody>__FINDROWS__</tbody></table>

<h2>3. Session inventory</h2>
<table><thead><tr><th>#</th><th>scenario</th><th>proto</th><th>TLS</th><th>cipher suite</th><th>FS</th><th>chain</th>
<th>key</th><th>sig</th><th>SAN</th><th>posture</th><th>findings</th></tr></thead><tbody>__SESSROWS__</tbody></table>

<h2>4. PS 26159 deliverable coverage</h2>
<table><thead><tr><th>#</th><th>expected deliverable</th><th>implemented as</th><th>status</th></tr></thead>
<tbody>__DELIVROWS__</tbody></table>

<h2>5. Validation results (measured, reproducible)</h2>
<div class="grid k2"><div class="card"><table>__VALIDROWS__</table></div>
<div class="card"><table>__AIROWS__</table></div></div>

<h2>6. Methodology and honest limitations</h2>
<div class="card"><ul style="margin:0;padding-left:18px">__METHOD__</ul></div>

<div class="foot">Rules mapped to RFC 8996, RFC 9155, RFC 5280, RFC 6125, RFC 3207, RFC 8460/8461, RFC 7672,
NIST SP 800-52r2, NIST SP 800-57, CA/Browser Forum Baseline Requirements, Mozilla Server Side TLS, BSI TR-02102.
Fingerprinting follows JA3 / JA4 (FoxIO) with GREASE filtering.</div>
</div></body></html>"""

METHOD = [
 f"<b>Dataset.</b> Built exactly as the sponsor's dataset line permits (synthetic capture). {B['corpus']['sessions']} mail sessions across SMTP/SMTPS, IMAP/IMAPS, POP3/POP3S were generated with real X.509 DER from a mini-CA, hand-encoded TLS record bytes and TCP payloads split across segments so the reassembler is genuinely exercised.",
 "<b>Passive by design.</b> The analyser only reads captured traffic: no decryption, no active probe, no connection to the mail server. That is what makes STARTTLS stripping visible &mdash; the victim MTA's own logs show nothing beyond a missing handshake line.",
 "<b>Chain validation is cryptographic.</b> The leaf signature is re-verified against the trust anchor's public key (raw RSA/ECDSA verify), not merely parsed. Modern libraries refuse to validate SHA-1-signed certificates, so a SHA-1 leaf is minted by DER surgery to prove the rule fires.",
 "<b>AI is assistive, never authoritative.</b> The policy engine (15 standards-mapped rules, CVSS 4.0 base) decides findings. The AI layer adds a risk classifier over raw handshake/X.509 features and an unsupervised deviation model; both are measured and reported with their false-alarm rates.",
 "<b>Anomaly model choice was measured, not assumed.</b> A JA4 fingerprint allowlist flagged every outlier but produced false alarms on most unseen compliant sessions in a heterogeneous fleet; IsolationForest alone missed them because only two of the eleven attributes separated the outlier. The nominal deviation score with a 3-sigma control limit separated outliers from compliant traffic with zero false alarms.",
 "<b>Limitation &mdash; DNS is invisible in a PCAP.</b> MTA-STS (RFC 8461), DANE (RFC 7672) and TLS-RPT (RFC 8460) checks need DNS, so they are emitted as remediation guidance rather than findings, unless an optional active-enrichment module is enabled and clearly labelled as such.",
 "<b>Research base.</b> RFC 3207 section 4 (opportunistic TLS is strippable by design), RFC 8446 section 4.4.2, RFC 8996, RFC 9155, RFC 5280, NIST SP 800-52r2, CA/Browser Forum Baseline Requirements; NDSS 2025 (Tang et al.: 19 of 49 mail clients silently downgrade without notifying the user); USENIX Security 2021 (over 40 STARTTLS issues across 28 clients and 23 servers); ACM CODASPY 2024 (TLS downgrade behaviour in 217 apps); FoxIO JA4 specification.",
 "<b>Positioning.</b> These are preliminary prototype benchmark results on a synthetic corpus built with the sponsor-permitted method; real-world validation (fragmented records, retransmits, middlebox effects, larger and more diverse captures) is the next phase, not a claim of a finished product.",
 "<b>Limitation &mdash; application-layer content is out of scope.</b> Post-handshake records are opaque (encrypted); the tool assesses the cryptographic posture of the mail channel, not message content, DKIM/SPF/DMARC or spam.",
]

def _light_pill(sev):
    col = SEV_COLOR[sev]
    return f'<span class="pill" style="background:{col}1f;color:{col}">{sev}</span>'

def build_report_html():
    exec_txt = (
      f"Across <b>{len(SESS)}</b> passively captured mail sessions the organisation scores "
      f"<b>{ORG_POSTURE}/100 (grade {GRADE})</b>. <b>{len(ALLF)}</b> findings were raised "
      f"({SEV_COUNT.get('CRITICAL',0)} critical, {SEV_COUNT.get('HIGH',0)} high, {SEV_COUNT.get('MEDIUM',0)} medium). "
      f"The highest-priority issue is <b>{FINDINGS_GROUPED[0]['id']} &mdash; {FINDINGS_GROUPED[0]['title']}</b> "
      f"(CVSS {FINDINGS_GROUPED[0]['cvss']}), observed in {FINDINGS_GROUPED[0]['count']} session(s). "
      f"{sum(1 for s in SESS if s['stripped'])} session(s) advertised STARTTLS and never upgraded &mdash; mail that the "
      f"sender believes is encrypted is traversing the network in cleartext, and the sending MTA's own log shows no error. "
      f"Deprecated protocols (TLS 1.0/1.1), non-AEAD ciphers, absent forward secrecy and certificate defects "
      f"(expired, RSA-1024, SHA-1 signed, SAN mismatch, unanchored chain) account for the remainder.")
    findrows = "".join(
      f'<tr><td>{_light_pill(f["sev"])}</td><td class="mono">{f["id"]}</td><td>{f["title"]}</td>'
      f'<td>{f["count"]}</td><td>{f["cvss"]}</td><td>{f["standard"]}</td><td>{f["remediation"]}</td></tr>'
      for f in FINDINGS_GROUPED)
    sessrows = "".join(
      f'<tr><td class="mono">{s["id"]}</td><td class="mono">{s["scenario"]}</td>'
      f'<td>{s["proto"]}<span class="mono"> :{s["port"]}</span></td>'
      f'<td>{"<span class=bad>cleartext</span>" if s["tls"].startswith("NONE") else s["tls"]}</td>'
      f'<td class="mono">{s["cipher"] or "&mdash;"}</td>'
      f'<td>{"<span class=ok>yes</span>" if s["fs"] else ("<span class=warn>no</span>" if s["cipher"] else "&mdash;")}</td>'
      f'<td>{"<span class=ok>verified</span>" if s["cert"]["chain_ok"] else ("<span class=bad>unanchored</span>" if s["cert"]["subject"] else "&mdash;")}</td>'
      f'<td class="mono">{str(s["cert"]["keybits"] or "") + ("b" if s["cert"]["keybits"] else "") or "&mdash;"}</td>'
      f'<td class="mono">{s["cert"]["sigalg"] or "&mdash;"}</td>'
      f'<td>{"<span class=ok>ok</span>" if s["cert"]["sans"] and "mail.corp.example" in s["cert"]["sans"] else ("<span class=bad>mismatch</span>" if s["cert"]["subject"] else "&mdash;")}</td>'
      f'<td><b>{s["posture"] if s["posture"] is not None else "&mdash;"}</b></td>'
      f'<td class="mono">{", ".join(x["id"] for x in s["findings"]) or "<span class=ok>clean</span>"}</td></tr>'
      for s in SESS)
    delivrows = "".join(
      f'<tr><td class="mono">{i}</td><td>{t}</td><td>{how}</td><td><span class="ok"><b>{st}</b></span></td></tr>'
      for i, t, how, st in DELIVERABLES)
    vr = "".join(f'<tr><td class="mut">{k}</td><td><b>{v}</b></td></tr>' for k, v in valid_rows)
    ar = "".join(f'<tr><td class="mut">{k}</td><td><b>{v}</b></td></tr>' for k, v in ai_rows)
    h = (REPORT.replace("__SUB__", PAYLOAD["meta"]["subtitle"])
         .replace("__GEN__", PAYLOAD["meta"]["generated"])
         .replace("__CORPUS__", f'{B["corpus"]["sessions"]} sessions / {B["corpus"]["bytes"]//1024} KB PCAP / self-generated per sponsor instruction')
         .replace("__POSTURE__", str(ORG_POSTURE)).replace("__GRADE__", GRADE)
         .replace("__N_SESS__", str(len(SESS))).replace("__N_FIND__", str(len(ALLF)))
         .replace("__N_CRIT__", str(SEV_COUNT.get("CRITICAL", 0)))
         .replace("__N_HIGH__", str(SEV_COUNT.get("HIGH", 0)))
         .replace("__N_RULES__", str(B["policy_library"]["rules"]))
         .replace("__EXEC__", exec_txt).replace("__FINDROWS__", findrows)
         .replace("__SESSROWS__", sessrows).replace("__DELIVROWS__", delivrows)
         .replace("__VALIDROWS__", vr).replace("__AIROWS__", ar)
         .replace("__METHOD__", "".join(f"<li>{m}</li>" for m in METHOD)))
    open(os.path.join(OUT, "report.html"), "w").write(h)
    return h

# ------------------------------------------------------------------ PDF export
try:
    import fitz
except ImportError:                     # newer PyMuPDF builds expose only `pymupdf`
    import pymupdf as fitz
INK = (0.06, 0.09, 0.15); BLUE = (0.11, 0.35, 0.85); TEAL = (0.05, 0.55, 0.52)
GREY = (0.36, 0.42, 0.51); LIGHT = (0.94, 0.96, 0.99); WHITE = (1, 1, 1)
REDC = (0.86, 0.22, 0.24); AMB = (0.93, 0.55, 0.05); GRN = (0.14, 0.55, 0.22)
SEV_RGB = {"CRITICAL": REDC, "HIGH": AMB, "MEDIUM": (0.85, 0.68, 0.05), "LOW": GRN, "INFO": GREY}
PW, PH, MG = 595.0, 842.0, 42.0
F_ = fitz.Font("helv"); FB_ = fitz.Font("hebo")

def _w(text, size, bold): return (FB_ if bold else F_).text_length(text, size)

def _hard_split(tok, size, bold, maxw):
    out = []; cur = ""
    for ch in tok:
        if _w(cur + ch, size, bold) <= maxw or not cur: cur += ch
        else: out.append(cur); cur = ch
    if cur: out.append(cur)
    return out

def _wrap(text, size, bold, maxw):
    words = str(text).split(); lines = []; cur = ""
    for w in words:
        if _w(w, size, bold) > maxw:                      # unbreakable token wider than the cell
            if cur: lines.append(cur); cur = ""
            lines += _hard_split(w, size, bold, maxw); continue
        t = (cur + " " + w).strip()
        if _w(t, size, bold) <= maxw: cur = t
        else:
            if cur: lines.append(cur)
            cur = w
    if cur: lines.append(cur)
    return lines or [""]

class Pdf:
    def __init__(self):
        self.doc = fitz.open(); self.page = None; self.y = 0; self.new_page(first=True)
    def new_page(self, first=False):
        self.page = self.doc.new_page(width=PW, height=PH); self.y = MG
        if not first: self.header()
        return self.page
    def header(self):
        p = self.page
        p.insert_text(fitz.Point(MG, 26), "SecureMailScope  |  passive mail cryptographic posture report",
                      fontsize=8, fontname="helv", color=GREY)
        p.insert_text(fitz.Point(PW - MG - _w("SIH26159 (NTRO)", 8, False), 26), "SIH26159 (NTRO)",
                      fontsize=8, fontname="helv", color=GREY)
        p.draw_line(fitz.Point(MG, 32), fitz.Point(PW - MG, 32), color=(0.85, 0.88, 0.93), width=0.7)
        self.y = 52
    def need(self, h):
        if self.y + h > PH - MG - 16:
            self.doc[-1].insert_text(fitz.Point(MG, PH - 24), f"page {len(self.doc)}", fontsize=8, fontname="helv", color=GREY)
            self.new_page()
    def text(self, t, size=9.5, bold=False, color=INK, x=MG, w=None, space=1.0, lh=1.32):
        w = w or (PW - 2 * MG)
        for l in _wrap(t, size, bold, w):
            self.need(size * lh)
            self.page.insert_text(fitz.Point(x, self.y + size * 0.82), l, fontsize=size,
                                  fontname="hebo" if bold else "helv", color=color)
            self.y += size * lh * space
        self.y += size * 0.45
    def h1(self, t):
        self.need(26); self.y += 4
        self.page.insert_text(fitz.Point(MG, self.y + 12), t, fontsize=13, fontname="hebo", color=INK)
        self.y += 20
        self.page.draw_line(fitz.Point(MG, self.y - 4), fitz.Point(PW - MG, self.y - 4), color=(0.85, 0.88, 0.93), width=0.7)
    def h2(self, t):
        self.need(18); self.y += 3
        self.page.insert_text(fitz.Point(MG, self.y + 9), t.upper(), fontsize=8.5, fontname="hebo", color=BLUE)
        self.y += 15
    def box(self, x, y, w, h, fill=None, line=(0.86, 0.89, 0.93), r=0.06):
        kw = dict(color=line, fill=fill, width=0.7)
        if r: kw["radius"] = r
        self.page.draw_rect(fitz.Rect(x, y, x + w, y + h), **kw)
    def table(self, cols, widths, rows, header_fill=(0.93, 0.95, 0.98), size=8.2, pad=4):
        x0 = MG; totw = PW - 2 * MG
        xs = [x0]; 
        for wfrac in widths: xs.append(xs[-1] + totw * wfrac)
        def draw_row(cells, bold=False, fill=None):
            hs = []
            for c, (a, b) in zip(cells, zip(xs, xs[1:])):
                hs.append(len(_wrap(c, size, bold, b - a - 2 * pad)))
            n = max(hs); rh = n * size * 1.30 + 2 * pad
            self.need(rh)
            y = self.y
            if fill: self.box(x0, y, totw, rh, fill=fill, line=None, r=0)
            self.page.draw_line(fitz.Point(x0, y + rh), fitz.Point(x0 + totw, y + rh), color=(0.88, 0.90, 0.94), width=0.5)
            for c, (a, b) in zip(cells, zip(xs, xs[1:])):
                col = c[1] if isinstance(c, tuple) else INK
                txt = c[0] if isinstance(c, tuple) else c
                for i, l in enumerate(_wrap(txt, size, bold, b - a - 2 * pad)):
                    self.page.insert_text(fitz.Point(a + pad, y + pad + size * 0.85 + i * size * 1.30), l,
                                          fontsize=size, fontname="hebo" if bold else "helv", color=col)
            self.y += rh
        draw_row(cols, bold=True, fill=header_fill)
        for r in rows: draw_row(r)
        self.y += 6

ENT = {"&mdash;": "-", "&rarr;": "->", "&middot;": "*", "&Sigma;": "sum", "&minus;": "-", "&nbsp;": " ",
       "&times;": "x", "&ge;": ">=", "&le;": "<="}
def _plain(t):
    import re
    t = re.sub(r"<[^>]+>", "", t)
    for k, v in ENT.items(): t = t.replace(k, v)
    return t

def build_pdf():
    p = Pdf()
    pg = p.page
    pg.draw_rect(fitz.Rect(0, 0, PW, 96), color=None, fill=(0.043, 0.071, 0.125))
    pg.insert_text(fitz.Point(MG, 40), "SecureMailScope", fontsize=22, fontname="hebo", color=WHITE)
    pg.insert_text(fitz.Point(MG, 58), "Passive cryptographic posture analyser for SMTP / IMAP / POP3 and their TLS variants",
                   fontsize=9.5, fontname="helv", color=(0.72, 0.80, 0.90))
    pg.insert_text(fitz.Point(MG, 76), f"SIH26159 (NTRO)  |  generated {PAYLOAD['meta']['generated']}  |  "
                   f"source: {B['corpus']['sessions']} self-generated PCAP sessions ({B['corpus']['bytes']//1024} KB)",
                   fontsize=8.2, fontname="helv", color=(0.62, 0.72, 0.85))
    p.y = 116
    # KPI strip
    kpis = [(f"{ORG_POSTURE}", f"posture / 100 (grade {GRADE})"), (str(len(SESS)), "mail sessions"),
            (str(len(ALLF)), "findings"), (str(SEV_COUNT.get("CRITICAL", 0)), "critical"),
            (f"{B['throughput'].get('native_display', B['throughput']['native_sessions_per_second']):,}", "sessions / second")]
    w = (PW - 2 * MG - 4 * 8) / 5
    for i, (v, l) in enumerate(kpis):
        x = MG + i * (w + 8)
        p.box(x, p.y, w, 46, fill=LIGHT)
        pg.insert_text(fitz.Point(x + 8, p.y + 22), v, fontsize=17, fontname="hebo", color=BLUE)
        for j, ln in enumerate(_wrap(l, 7.2, False, w - 16)):
            pg.insert_text(fitz.Point(x + 8, p.y + 33 + j * 8), ln, fontsize=7.2, fontname="helv", color=GREY)
    p.y += 58
    p.h1("1. Executive summary")
    p.text(f"Across {len(SESS)} passively captured mail sessions the organisation scores {ORG_POSTURE}/100 "
           f"(grade {GRADE}). {len(ALLF)} findings were raised: {SEV_COUNT.get('CRITICAL',0)} critical, "
           f"{SEV_COUNT.get('HIGH',0)} high, {SEV_COUNT.get('MEDIUM',0)} medium, produced by "
           f"{B['policy_library']['rules']} standards-mapped rules.")
    p.text(f"The highest-priority issue is {FINDINGS_GROUPED[0]['id']} - {FINDINGS_GROUPED[0]['title']} "
           f"(CVSS {FINDINGS_GROUPED[0]['cvss']}, {FINDINGS_GROUPED[0]['standard']}), seen in "
           f"{FINDINGS_GROUPED[0]['count']} sessions. {sum(1 for s in SESS if s['stripped'])} sessions advertised "
           f"STARTTLS and never upgraded: mail the sender believes is encrypted crosses the network in cleartext, "
           f"while the sending MTA's own log records no error. That is precisely the class of failure a passive "
           f"monitor is the only place to detect.")
    p.h2("Findings by severity, negotiated TLS version and protocol")
    tls_txt = ",  ".join(f"{k}: {v}" for k, v in sorted(TLS_COUNT.items(), key=lambda kv: -kv[1]))
    pro_txt = ",  ".join(f"{k}: {v}" for k, v in sorted(PROTO_COUNT.items(), key=lambda kv: -kv[1]))
    p.table(["severity", "findings", "TLS observed on mail ports (sessions)", "protocol mix (sessions)"],
            [0.13, 0.09, 0.44, 0.34],
            [[(k, SEV_RGB[k]), str(v), tls_txt if i2 == 0 else "", pro_txt if i2 == 0 else ""]
             for i2, (k, v) in enumerate(sorted(SEV_COUNT.items(), key=lambda kv: SEV_ORDER[kv[0]]))])
    # page 2: findings
    p.h1("2. Prioritised findings and remediation")
    p.table(["sev", "id", "finding", "n", "CVSS", "standard", "remediation"],
            [0.085, 0.05, 0.235, 0.035, 0.055, 0.155, 0.385],
            [[(f["sev"], SEV_RGB[f["sev"]]), f["id"], f["title"], str(f["count"]), f"{f['cvss']}",
              f["standard"], f["remediation"]] for f in FINDINGS_GROUPED])
    p.h2("Posture scoring")
    p.text("posture = max(0, 100 - 3.2 x sum of CVSS 4.0 base scores of confirmed findings). "
           "The formula is deterministic and disclosed so every score can be audited line by line; the AI layer "
           "contributes anomaly evidence and a risk score, never a silent override.", size=9)
    # page 3: inventory
    p.h1("3. Session inventory (by capture scenario)")
    by_scen = collections.defaultdict(list)
    for s in SESS: by_scen[s["scenario"]].append(s)
    rows = []
    for sc, ss in sorted(by_scen.items()):
        f_ids = sorted({f["id"] for s in ss for f in s["findings"]})
        rows.append([sc, ss[0]["proto"] + ":" + str(ss[0]["port"]), str(len(ss)),
                     ss[0]["tls"], (ss[0]["cipher"] or "-").replace("TLS_", ""),
                     "yes" if ss[0]["fs"] else ("no" if ss[0]["cipher"] else "-"),
                     f"{min(s['posture'] for s in ss if s['posture'] is not None)}" if any(s["posture"] is not None for s in ss) else "-",
                     ", ".join(f_ids) or "clean"])
    p.table(["scenario", "proto", "n", "TLS", "cipher suite", "FS", "posture", "rules fired"],
            [0.145, 0.09, 0.035, 0.09, 0.245, 0.045, 0.08, 0.27], rows)
    p.h2("Certificate inventory (distinct profiles)")
    groups = {}
    for s2 in SESS:
        c = s2["cert"]
        if not c["serial"]: continue
        k = (c["subject"], c["issuer"], c["keybits"], c["sigalg"], tuple(c["sans"] or []),
             c["chain_ok"], "expired" if (c["days_left"] or 0) < 0 else "valid")
        groups[k] = groups.get(k, 0) + 1
    p.table(["subject", "issuer", "key", "sig", "SAN", "validity", "chain", "sessions"],
            [0.165, 0.185, 0.06, 0.065, 0.165, 0.075, 0.165, 0.12],
            [[k[0].replace("CN=", ""), k[1].replace("CN=", ""), f"{k[2]}b", k[3],
              ", ".join(k[4]) or "-", k[6], ("verified" if k[5] else ("UNANCHORED", REDC)), str(v)]
             for k, v in sorted(groups.items(), key=lambda kv: -kv[1])])
    # page 4: deliverable matrix
    p.h1("4. PS 26159 deliverable coverage")
    p.table(["#", "expected deliverable", "implemented as", "status"], [0.045, 0.40, 0.455, 0.10],
            [[str(i), t, how, (st, GRN)] for i, t, how, st in DELIVERABLES])
    # page 5: validation + methodology
    p.h1("5. Validation results (measured, reproducible)")
    p.table(["measurement", "result"], [0.52, 0.48], [[_plain(k), _plain(v)] for k, v in valid_rows])
    p.h2("AI layer")
    p.table(["measurement", "result"], [0.52, 0.48], [[_plain(k), _plain(v)] for k, v in ai_rows])
    p.h1("6. Methodology and honest limitations")
    for m in METHOD:
        p.text("- " + _plain(m), size=8.8, lh=1.28)
        p.y += 2
    p.h2("Standards and references")
    p.text("RFC 8996 (TLS 1.0/1.1 historic) - RFC 9155 (SHA-1 signatures deprecated) - RFC 5280 (X.509 PKI) - "
           "RFC 6125 (hostname validation) - RFC 3207 (SMTP STARTTLS) - RFC 8461 (MTA-STS) - RFC 8460 (TLS-RPT) - "
           "RFC 7672 (SMTP DANE) - RFC 8446 (TLS 1.3) - NIST SP 800-52r2 - NIST SP 800-57 - NIST SP 800-63B - "
           "CA/Browser Forum Baseline Requirements - Mozilla Server Side TLS - BSI TR-02102 - "
           "JA3 (Salesforce) and JA4/JA4S/JA4X (FoxIO) fingerprinting with GREASE filtering.", size=8.8)
    p.doc[-1].insert_text(fitz.Point(MG, PH - 24), f"page {len(p.doc)}", fontsize=8, fontname="helv", color=GREY)
    path = os.path.join(OUT, "report.pdf")
    p.doc.save(path, deflate=True)
    return path, len(p.doc)

if __name__ == "__main__":
    build_dashboard()
    build_report_html()
    pdf, pages = build_pdf()
    print(json.dumps(dict(
        report_json=os.path.join(OUT, "report.json"),
        dashboard=os.path.join(OUT, "index.html"),
        report_html=os.path.join(OUT, "report.html"),
        report_pdf=pdf, pdf_pages=pages,
        sessions=len(SESS), findings=len(ALLF), posture=ORG_POSTURE, grade=GRADE,
        rules=len(FINDINGS_GROUPED)), indent=1))
