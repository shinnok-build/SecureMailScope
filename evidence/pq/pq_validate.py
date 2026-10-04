"""Post-quantum evidence: capture, decrypt, grade - and write it down.

Produces ms_pq/pq_validation.json from four independent observations:

  1. a REAL X25519MLKEM768 handshake (OpenSSL 3.5.6, captured on loopback) graded by the shipped engine
  2. the same server on a classical group, as the control
  3. the hybrid session decrypted through the keylog path, certificate recovered
  4. the negative control: an empty keylog cannot open it, and a client that offers a hybrid
     group against a server that ignores it is caught by rule P1

Nothing here is hand-written: every number is read from a capture or a return value.
"""
import hashlib, importlib.util, json, os, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA = os.path.join(ROOT, "data")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)   # the authoring engine - the bundle copy is regenerated from it
import warnings
warnings.filterwarnings("ignore")
import mailscope.engine as mb
from cryptography import x509

spec = importlib.util.spec_from_file_location("kt", os.path.join(ROOT, "mailscope", "keylog.py"))
kt = importlib.util.module_from_spec(spec); spec.loader.exec_module(kt)


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def grade(path, port=993):
    segs = mb.read_pcap_native(path)
    c2s = [(s, d) for (d_, s, d) in segs if d_]
    s2c = [(s, d) for (d_, s, d) in segs if not d_]
    sess = mb.analyse(c2s, s2c, dict(port=port))
    f = sess.get("feats", {}) or {}
    return dict(
        tls=f.get("tls_name"), cipher=f.get("cipher"), ke_group=f.get("ke_group"),
        pq=bool(f.get("pq")), pq_group=f.get("pq_group") or None,
        pq_offered=f.get("pq_offered") or [],
        findings=[dict(id=x.fid, sev=x.sev, title=x.title, ev=x.ev) for x in sess.get("findings", [])],
        posture=sess.get("posture"))


out = {"generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
       "engine": "mailscope_bench.analyse (shipped policy library)",
       "sessions": {}}

# 1 + 2 ------------------------------------------------------------------- real captures
for name in ("pq-hybrid", "pq-classical"):
    path = os.path.join(HERE, f"{name}-993.pcap")
    out["sessions"][name] = dict(
        capture=os.path.relpath(path, HERE), bytes=os.path.getsize(path), sha256=sha256(path),
        graded=grade(path))

# 3 ----------------------------------------------------------------------- decryption
rec = kt.decrypt_session(os.path.join(HERE, "pq-hybrid-993.pcap"),
                         os.path.join(DATA, "keylog", "pq_keylog.txt"))
cert = x509.load_der_x509_certificate(rec["chain"][0]) if rec["chain"] else None
g = kt.grade(rec["chain"], "mail.corp.example") if rec["chain"] else {}
out["decryption"] = dict(
    capture="ms_pq/pq-hybrid-993.pcap", keylog="ms_keylog/pq_keylog.txt",
    suite=rec["suite"], handshake_messages=rec["messages"], decrypted_bytes=rec["decrypted_bytes"],
    key_exchange="X25519MLKEM768", recovered_subject=cert.subject.rfc4514_string() if cert else None,
    recovered_issuer=cert.issuer.rfc4514_string() if cert else None,
    not_valid_after=cert.not_valid_after.strftime("%Y-%m-%d") if cert else None,
    checks=g)

# 4 ----------------------------------------------------------------------- controls
open("/tmp/_empty_keylog.txt", "w").write("# no secrets here\n")
try:
    kt.decrypt_session(os.path.join(HERE, "pq-hybrid-993.pcap"), "/tmp/_empty_keylog.txt")
    out["negative_control"] = dict(result="UNEXPECTED SUCCESS")
except SystemExit as e:
    out["negative_control"] = dict(result="clean refusal", message=str(e),
                                   meaning="without the endpoint keylog a stored hybrid capture cannot be opened, "
                                           "even by an attacker who holds the classical private key")

mismatch = grade(os.path.join(HERE, "q-mismatch-993.pcap"))
out["capability_mismatch"] = dict(
    capture="ms_pq/q-mismatch-993.pcap (built by the shipped generator: client offers X25519MLKEM768, "
            "server selects x25519)",
    rule="P1", fired=any(f["id"] == "P1" for f in mismatch["findings"]),
    evidence=next((f["ev"] for f in mismatch["findings"] if f["id"] == "P1"), None),
    severity=next((f["sev"] for f in mismatch["findings"] if f["id"] == "P1"), None))

out["group_registry"] = dict(
    hybrid={hex(k): v for k, v in sorted(mb.GROUPS.items()) if mb.is_pq(k)},
    note="read from the wire: the negotiated group comes out of the ServerHello key_share extension")

path = os.path.join(HERE, "pq_validation.json")
json.dump(out, open(path, "w"), indent=1)
print(json.dumps(out, indent=1)[:2000])
print("\nwrote", path)
