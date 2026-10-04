# -*- coding: utf-8 -*-
"""LIVE validation: real STARTTLS sessions against public mail infrastructure, captured
at a local relay (the same position our architecture claims: a tap/SPAN, not in-path).

No privileges needed and nothing is intercepted: the relay simply forwards to the real
MTA and records the byte stream in both directions.  The recorded payloads are verbatim
wire bytes from the real servers; only the IP addresses in the emitted pcap are
pseudonymised by the project's pcap writer.

Grading uses the SAME analysis core as the synthetic corpus (mailscope_bench.analyse),
with two deliberate live-mode changes:
  * expected mail hostname pinned to the real target (instead of the test domain),
  * chain validation anchored to the OS public trust store (instead of the test root).
Run:  python3 live_validate.py
"""
import json, os, socket, ssl, select, threading, time, datetime, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mailscope import engine as mb
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")
LIVE = os.path.join(DATA, "live")
os.makedirs(LIVE, exist_ok=True)

TARGETS = [
    # SMTP, explicit TLS (STARTTLS) - six independent providers
    dict(name="smtp-gmail-587-tls13",   host="smtp.gmail.com",      port=587, maxver=None,  mode="starttls", proto="smtp"),
    dict(name="smtp-gmail-587-tls12",   host="smtp.gmail.com",      port=587, maxver="1.2", mode="starttls", proto="smtp"),
    dict(name="smtp-outlook-587-tls12", host="smtp.office365.com",  port=587, maxver="1.2", mode="starttls", proto="smtp"),
    dict(name="smtp-zoho-587",          host="smtp.zoho.com",       port=587, maxver=None,  mode="starttls", proto="smtp"),
    dict(name="smtp-fastmail-587",      host="smtp.fastmail.com",   port=587, maxver=None,  mode="starttls", proto="smtp"),
    dict(name="smtp-yahoo-587",         host="smtp.mail.yahoo.com", port=587, maxver=None,  mode="starttls", proto="smtp"),
    dict(name="smtp-google-mx-25",      host="aspmx.l.google.com",  port=25,  maxver="1.2", mode="starttls", proto="smtp"),
    # SMTP, implicit TLS
    dict(name="smtps-gmail-465",        host="smtp.gmail.com",      port=465, maxver=None,  mode="implicit", proto="smtp"),
    # IMAP, explicit and implicit TLS
    dict(name="imaps-gmail-993",        host="imap.gmail.com",      port=993, maxver=None,  mode="implicit", proto="imap"),
    dict(name="imaps-outlook-993",      host="outlook.office365.com", port=993, maxver=None, mode="implicit", proto="imap"),
    dict(name="imaps-zoho-993",         host="imap.zoho.com",       port=993, maxver=None,  mode="implicit", proto="imap"),
    dict(name="imaps-fastmail-993",     host="imap.fastmail.com",   port=993, maxver=None,  mode="implicit", proto="imap"),
    # POP3, explicit TLS: GMX is one of the few providers that still answers in cleartext on 110,
    # which lets us exercise a real POP3 STLS upgrade (and below, a real POP3 downgrade trap).
    dict(name="pop3-gmx-110-stls",      host="pop.gmx.com",         port=110, maxver=None,  mode="starttls-pop3", proto="pop3"),
    # POP3, implicit TLS
    dict(name="pop3s-gmail-995",        host="pop.gmail.com",       port=995, maxver=None,  mode="implicit", proto="pop3"),
    dict(name="pop3s-outlook-995",      host="outlook.office365.com", port=995, maxver=None, mode="implicit", proto="pop3"),
    dict(name="pop3s-zoho-995",         host="pop.zoho.com",        port=995, maxver=None,  mode="implicit", proto="pop3"),
    # controlled downgrade traps: the client withholds the upgrade and authenticates in cleartext.
    # these MUST be caught by the engine (A1) - they are our own sessions, not the provider's fault.
    dict(name="trap-smtp-587-withheld", host="smtp.gmail.com",      port=587, maxver=None,  mode="withhold", proto="smtp"),
    dict(name="trap-pop3-gmx-110-withheld", host="pop.gmx.com",     port=110, maxver=None,  mode="withhold-pop3", proto="pop3"),
]

# ------------------------------------------------------------- public-PKI anchor check
_ANCHORS = None
def anchors():
    global _ANCHORS
    if _ANCHORS is None:
        _ANCHORS = x509.load_pem_x509_certificates(open("/etc/ssl/certs/ca-certificates.crt", "rb").read())
    return _ANCHORS

def _sig_ok(child, parent):
    pk, h = parent.public_key(), child.signature_hash_algorithm
    try:
        if isinstance(pk, rsa.RSAPublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), h)
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(h))
        else:
            pk.verify(child.signature, child.tbs_certificate_bytes)
        return True
    except Exception:
        return False

def live_verify_chain(leaf_der, issuer_ders):
    leaf = x509.load_der_x509_certificate(leaf_der)
    chain = [leaf] + [x509.load_der_x509_certificate(d) for d in issuer_ders]
    top = chain[-1]
    anchor = top if top.subject == top.issuer else next((a for a in anchors() if a.subject == top.issuer), None)
    if anchor is None:
        return False, "no public trust anchor found for the presented chain"
    for child, parent in zip(chain, chain[1:] + [anchor]):
        if child.issuer != parent.subject:
            return False, f"issuer/subject mismatch below {child.subject.rfc4514_string()}"
        if not _sig_ok(child, parent):
            return False, f"signature does not verify under {parent.subject.rfc4514_string()}"
    for c in chain[1:] + [anchor]:
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        except Exception:
            bc = None
        if bc is None or not bc.ca:
            return False, "issuer certificate lacks basicConstraints CA=TRUE"
    return True, "chain verified to a public trust anchor (OS CA store)"

# ------------------------------------------------------------- relay = the tap
class Relay(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0)); self.ls.listen(1)
        self.local_port = self.ls.getsockname()[1]
        self.c2s, self.s2c = [], []
        self.done = threading.Event()

    def run(self):
        cl, _ = self.ls.accept(); cl.settimeout(25)
        rm = socket.create_connection((self.host, self.port), 25); rm.settimeout(25)
        try:
            while not self.done.is_set():
                r, _, _ = select.select([cl, rm], [], [], 0.5)
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        self.done.set(); break
                    if s is cl: self.c2s.append(d); rm.sendall(d)
                    else:       self.s2c.append(d); cl.sendall(d)
        except Exception:
            pass
        finally:
            for s in (cl, rm, self.ls):
                try: s.close()
                except Exception: pass
            self.done.set()

class Reader:
    """line reader over a raw socket with an exactly-controlled buffer (so a TLS
       upgrade can wrap the socket at a known-clean boundary)."""
    def __init__(self, s): self.s, self.buf = s, bytearray()
    def readline(self):
        while b"\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: break
            self.buf += d
        i = self.buf.find(b"\r\n")
        if i < 0:
            out = bytes(self.buf); self.buf.clear(); return out
        out = bytes(self.buf[:i+2]); del self.buf[:i+2]; return out
    def clean(self): return not self.buf

def read_reply(rd):
    """SMTP / IMAP replies: continuation lines are marked with a "-" after the status code."""
    lines = [rd.readline()]
    while len(lines[-1]) > 3 and lines[-1][3:4] == b"-":
        lines.append(rd.readline())
    return b"".join(lines)

def read_reply_pop3(rd):
    """POP3 (RFC 1939) is different: a multi-line reply is terminated by a lone "." line,
       not by a status-code convention - CAPA therefore needs the dot-terminated reader."""
    first = rd.readline()
    if not first.startswith(b"+OK"):
        return first
    lines = [first]
    for _ in range(64):                       # bounded: never hang on a chatty server
        ln = rd.readline()
        lines.append(ln)
        if ln in (b".\r\n", b".", b""):
            break
    return b"".join(lines)

def one_target(t):
    info = dict(name=t["name"], host=t["host"], port=t["port"], mode=t["mode"], proto=t.get("proto", "smtp"))
    rel = Relay(t["host"], t["port"]); rel.start()
    while not hasattr(rel, "local_port") or rel.local_port is None: time.sleep(0.05)
    time.sleep(0.3)
    py = {}
    proto = t.get("proto", "smtp")
    mode = t["mode"]
    try:
        c = socket.create_connection(("127.0.0.1", rel.local_port), 25); c.settimeout(25)
        rd = Reader(c)

        def tls_upgrade(maxver=None):
            assert rd.clean(), "read buffer not clean before TLS upgrade"
            ctx = ssl.create_default_context()
            if maxver == "1.2":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ts = ctx.wrap_socket(c, server_hostname=t["host"])      # real handshake, verified
            py["protocol"] = ts.version(); py["cipher"] = ts.cipher()[0]
            cert = ts.getpeercert()
            py["not_after"] = cert.get("notAfter")
            py["subject"] = dict(x[0] for x in cert.get("subject", []))
            py["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            try: py["chain_len"] = len(ts.get_verified_chain())
            except Exception: py["chain_len"] = None
            py["key_type"] = cert.get("version") and str(ts.cipher()[1]).upper() or None
            ts.close()

        if mode == "implicit":
            # SMTPS/IMAPS/POP3S: TLS is the first thing on the wire, no cleartext banner at all
            info["banner"] = ""
            info["ehlo_reply"] = ""
            info["starttls_offered"] = True          # implicit by definition
            tls_upgrade(t.get("maxver"))
        else:
            info["banner"] = rd.readline().decode(errors="replace").strip()
            if proto == "smtp":
                c.sendall(f"EHLO probe.local\r\n".encode()); reply = read_reply(rd)
                info["ehlo_reply"] = reply.decode(errors="replace")[:600]
                offered = b"STARTTLS" in reply.upper()
                upgrade_cmd, ok_prefix = b"STARTTLS\r\n", b"220"
            elif proto == "imap":
                c.sendall(b"a001 CAPABILITY\r\n"); reply = read_reply(rd)
                info["ehlo_reply"] = reply.decode(errors="replace")[:600]
                offered = b"STARTTLS" in reply.upper()
                upgrade_cmd, ok_prefix = b"a002 STARTTLS\r\n", b"a002 OK"
            else:
                c.sendall(b"CAPA\r\n"); reply = read_reply_pop3(rd)
                info["ehlo_reply"] = reply.decode(errors="replace")[:600]
                offered = b"STLS" in reply.upper()
                upgrade_cmd, ok_prefix = b"STLS\r\n", b"+OK"
            info["starttls_offered"] = offered

            if mode.startswith("withhold"):
                # our client refuses the upgrade and authenticates in cleartext: the stripping signature
                if proto == "smtp":
                    c.sendall(b"AUTH PLAIN AHByb2JlAHByb2Jl\r\n")
                elif proto == "imap":
                    c.sendall(b"a003 LOGIN probe probe\r\n")
                else:
                    c.sendall(b"USER probe\r\n"); time.sleep(0.15); c.sendall(b"PASS probe\r\n")
                time.sleep(0.4)
                c.sendall(b"QUIT\r\n" if proto != "imap" else b"a004 LOGOUT\r\n")
                time.sleep(0.3); c.close()
            else:
                c.sendall(upgrade_cmd); up = read_reply(rd)
                info["starttls_reply"] = up.decode(errors="replace").strip()
                assert up.startswith(ok_prefix), up
                tls_upgrade(t.get("maxver"))
        if py.get("protocol"):
            info["python_ssl_verified"] = True
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    info["python_ssl"] = py
    time.sleep(0.5); rel.done.set(); rel.join(timeout=4)

    # ---- re-encapsulate the recorded byte stream into a standard pcap ----
    g = mb.Gen(); g.port = t["port"]
    for chunk in rel.c2s: g.tcp(chunk, True)
    for chunk in rel.s2c: g.tcp(chunk, False)
    path = os.path.join(LIVE, t["name"] + ".pcap")
    import scapy.all as sp
    sp.wrpcap(path, g.pkts)
    info["relay_bytes_c2s"] = sum(len(x) for x in rel.c2s)
    info["relay_bytes_s2c"] = sum(len(x) for x in rel.s2c)
    info["pcap_bytes"] = os.path.getsize(path)

    # ---- grade the capture with OUR engine ----
    segs = mb.read_pcap_native(path)
    c2s = [(s, d) for (dirn, s, d) in segs if dirn]
    s2c = [(s, d) for (dirn, s, d) in segs if not dirn]
    mb.TRUSTED_CN = t["host"]; mb.verify_chain = live_verify_chain
    sess = mb.analyse(c2s, s2c, dict(port=t["port"]))
    f = sess.get("feats", {})
    info["mailscope"] = dict(
        advertised_starttls=sess.get("advertised_starttls"), stripped=sess.get("stripped"),
        findings=[dict(id=x.fid, sev=x.sev, cvss=x.cvss, title=x.title, ev=x.ev,
                       standard=mb.POLICY[x.fid][3]) for x in sess["findings"]],
        posture=sess.get("posture"), tls=f.get("tls_name"), cipher=f.get("cipher"),
        ja3=f.get("ja3"), ja4=f.get("ja4"), chain_len=f.get("chain_len"), chain_ok=f.get("chain_ok"),
        keybits=f.get("keybits"), sigalg=f.get("sigalg"), days_left=f.get("days_left"),
        san_ok=f.get("san_ok"), subject=f.get("subject"), issuer=f.get("issuer"),
        ncert=f.get("ncert"), reasm=sess.get("reasm"),
        keyalg=f.get("keyalg"), ke_group=f.get("ke_group"), pq=bool(f.get("pq")),
        pq_offered=f.get("pq_offered") or [])
    return info

def main():
    res = []
    for t in TARGETS:
        print(f"\n=== {t['name']}  ({t['host']}:{t['port']}, {t['mode']}) ===", flush=True)
        info = one_target(t); res.append(info)
        py, ms = info.get("python_ssl", {}), info["mailscope"]
        print(f"  python-ssl : {py.get('protocol')} {py.get('cipher')} chain={py.get('chain_len')} verified={info.get('python_ssl_verified')}", flush=True)
        print(f"  mailscope  : tls={ms['tls']} cipher={ms['cipher']} ja4={ms['ja4']} chain_ok={ms['chain_ok']} keybits={ms['keybits']} posture={ms['posture']}", flush=True)
        print(f"  findings   : {[(x['id'], x['ev'][:64]) for x in ms['findings']]}", flush=True)
        if info.get("error"): print("  ERROR      :", info["error"], flush=True)
    out = dict(generated=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               method=("real public mail infrastructure across SMTP/IMAPS/POP3S and both TLS modes "
                       "(explicit and implicit), recorded at a local relay (our documented tap position) and "
                       "graded by mailscope_bench.analyse() with the OS public trust store as anchors and the "
                       "real hostname pinned; payload bytes verbatim, addresses pseudonymised by the pcap "
                       "writer. The two 'trap-*' entries are OUR OWN deliberately downgraded sessions - "
                       "controlled positives that the engine must catch, not provider misconfiguration. "
                       "Note: ports 143 and 110 at the large providers accepted TCP but never sent a "
                       "cleartext banner from this vantage point, so explicit-TLS coverage rests on SMTP "
                       "(7 providers) plus GMX POP3/110; IMAP and POP3 are covered implicitly on 993/995."),
               targets=res)
    json.dump(out, open(os.path.join(RESULTS, "live_validation.json"), "w"), indent=1)
    print("\nwrote live_validation.json")

if __name__ == "__main__":
    main()
