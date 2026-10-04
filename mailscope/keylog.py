# -*- coding: utf-8 -*-
"""keylog_tls13.py — the TLS 1.3 certificate, recovered the way a forensic team actually does it.

TLS 1.3 encrypts the handshake that follows the ServerHello, and the certificate travels inside it
(RFC 8446 section 4.4.2). So on TLS 1.3 our passive rules grade version, cipher suite, key exchange
and handshake presence, and the console prints "not observable" for the certificate. That is honest,
but it is also incomplete: an operator who owns the endpoint can hand over an SSLKEYLOGFILE, and then
the same capture yields the certificate.

This module does that end to end, with no trust in our own claims:

  1. mints a leaf under the corpus test CA and runs a real IMAPS server with it (Python's ssl, which
     is OpenSSL - not a hand-rolled mock);
  2. captures a real TLS 1.3 handshake at a relay - the same tap position the live validation uses -
     so the pcap is byte-for-byte what crossed the wire;
  3. keeps the SSLKEYLOGFILE the client wrote;
  4. derives the handshake traffic keys from those secrets (HKDF-Expand-Label) and opens the
     encrypted records (AES-GCM, per-record nonce from the sequence number);
  5. parses the Certificate message out of the decrypted handshake and grades it with the same
     checks the rest of the engine uses;
  6. proves it: the recovered certificate must be byte-identical to the one the server was holding.

Usage
    python3 keylog_tls13.py --out ms_keylog          # capture + decrypt + write keylog_validation.json
    python3 keylog_tls13.py --verify keylog_validation.json
"""
import argparse, hashlib, json, os, socket, ssl, struct, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.basename(HERE) == "mailscope"
ROOT = os.path.dirname(HERE) if PKG else HERE
RESULTS = os.path.join(ROOT, "results")

sys.path.insert(0, HERE)
try:
    import mailscope_bench as mb
except ImportError:
    from mailscope import engine as mb

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography import x509

SUITES = {
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "hash": "sha256", "key_len": 16, "aead": "aesgcm"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "hash": "sha384", "key_len": 32, "aead": "aesgcm"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "hash": "sha256", "key_len": 32, "aead": "chacha"},
}
# ServerHello with this random is a HelloRetryRequest: the key schedule restarts, so we refuse it
# rather than guess (the corpus never produces one: both ends negotiate X25519 on the first try).
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def _res(name):
    for base in (RESULTS, HERE):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return os.path.join(HERE, name)


# ---------------------------------------------------------------- capture (real traffic)
class Relay(threading.Thread):
    """Listens locally, forwards to the real server, and keeps every byte in both directions."""

    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0)); self.ls.listen(1)
        self.local_port = self.ls.getsockname()[1]
        self.c2s, self.s2c = [], []
        self.done = threading.Event()

    def run(self):
        cl, _ = self.ls.accept(); cl.settimeout(15)
        rm = socket.create_connection((self.host, self.port), 15); rm.settimeout(15)
        try:
            while not self.done.is_set():
                import select
                r, _, _ = select.select([cl, rm], [], [], 0.4)
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        self.done.set(); break
                    if s is cl:
                        self.c2s.append(d); rm.sendall(d)
                    else:
                        self.s2c.append(d); cl.sendall(d)
        except Exception:
            pass
        finally:
            for s in (cl, rm, self.ls):
                try:
                    s.close()
                except Exception:
                    pass
            self.done.set()


class ImapsServer(threading.Thread):
    """A real TLS 1.3 IMAPS endpoint holding the test leaf, so the capture is real protocol traffic."""

    def __init__(self, cert_pem, key_pem):
        super().__init__(daemon=True)
        self.cert_pem, self.key_pem = cert_pem, key_pem
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0)); self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.negotiated = {}

    def run(self):
        try:
            conn, _ = self.ls.accept(); conn.settimeout(15)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(self.cert_pem, self.key_pem)
            tls = ctx.wrap_socket(conn, server_side=True)
            self.negotiated = {"version": tls.version(), "cipher": tls.cipher()[0]}
            tls.sendall(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] SecureMailScope test server\r\n")
            tls.recv(4096)                       # the client's LOGOUT line
            tls.close()
        except Exception:
            pass
        finally:
            try:
                self.ls.close()
            except Exception:
                pass


def make_capture(outdir, host_name="mail.corp.example", days_valid=120):
    """Real TLS 1.3 IMAPS handshake through a relay; returns the pcap + keylog + served leaf."""
    os.makedirs(outdir, exist_ok=True)
    key_pem = os.path.join(outdir, "_server_key.pem")
    # a fresh leaf under the corpus test CA, with a private key we hold: the point is a real
    # handshake over a real socket, so the server needs its own key material.
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as _dt
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ca = mb.root_ca()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host_name)])
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    leaf = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(ca["cert"].subject)
            .public_key(ec_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=7))
            .not_valid_after(now + _dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host_name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca["key"], hashes.SHA256()))
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    cert_pem = os.path.join(outdir, "_server_cert.pem")
    with open(cert_pem, "wb") as fh:
        fh.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(key_pem, "wb") as fh:
        fh.write(ec_key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))

    srv = ImapsServer(cert_pem, key_pem); srv.start()
    relay = Relay("127.0.0.1", srv.port); relay.start()
    time.sleep(0.25)

    keylog = os.path.join(outdir, "sslkeylog.txt")
    if os.path.exists(keylog):
        os.remove(keylog)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.keylog_filename = keylog                # exactly what an operator would hand over
    raw = socket.create_connection(("127.0.0.1", relay.local_port), 15)
    tls = ctx.wrap_socket(raw, server_hostname=host_name)
    banner = tls.recv(4096)
    tls.sendall(b"a1 LOGOUT\r\n")
    negotiated = {"version": tls.version(), "cipher": tls.cipher()[0]}
    try:
        tls.close()
    except Exception:
        pass
    relay.done.set()
    time.sleep(0.6)

    g = mb.Gen(); g.port = 993                  # IMAPS: implicit TLS
    for chunk in relay.c2s:
        g.tcp(chunk, True)
    for chunk in relay.s2c:
        g.tcp(chunk, False)
    import scapy.utils as sp
    pcap = os.path.join(outdir, "imaps_tls13_keylog.pcap")
    sp.wrpcap(pcap, g.pkts)

    return {"pcap": pcap, "keylog": keylog, "leaf_der": leaf_der, "host": host_name,
            "banner": banner.decode("utf-8", "replace").strip(), "client": negotiated,
            "server": srv.negotiated, "c2s_bytes": sum(len(x) for x in relay.c2s),
            "s2c_bytes": sum(len(x) for x in relay.s2c)}


# ---------------------------------------------------------------- decryption
def read_keylog(path):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = line.split()
        if len(parts) == 3:
            label, client_random, secret = parts
            out.setdefault(label, {})[client_random.lower()] = bytes.fromhex(secret)
    return out


def hkdf_expand_label(secret, label, context, length, hash_name):
    """RFC 8446 section 7.1: HKDF-Expand-Label."""
    full = b"tls13 " + label.encode()
    hkdf_label = struct.pack("!H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    h = hashes.SHA256() if hash_name == "sha256" else hashes.SHA384()
    return HKDFExpand(algorithm=h, length=length, info=hkdf_label).derive(secret)


def traffic_keys(secret, suite):
    key = hkdf_expand_label(secret, "key", b"", suite["key_len"], suite["hash"])
    iv = hkdf_expand_label(secret, "iv", b"", 12, suite["hash"])
    return key, iv


def nonce_for(iv, seq):
    pad = b"\x00" * (12 - 8) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, pad))


def open_record(suite, key, iv, seq, header, payload):
    try:
        aead = AESGCM(key) if suite["aead"] == "aesgcm" else ChaCha20Poly1305(key)
        return aead.decrypt(nonce_for(iv, seq), payload, header)
    except Exception:
        return None


def tls_records(buf):
    """Split a byte stream into (type, version, header, payload) records."""
    out, i = [], 0
    while i + 5 <= len(buf):
        rtype, ver, ln = struct.unpack("!BHH", buf[i:i + 5])
        if i + 5 + ln > len(buf):
            break
        out.append((rtype, ver, buf[i:i + 5], buf[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


def handshake_messages(buf):
    """Concatenated handshake bytes -> [(msg_type, body)]."""
    out, i = [], 0
    while i + 4 <= len(buf):
        mtype = buf[i]
        ln = int.from_bytes(buf[i + 1:i + 4], "big")
        if i + 4 + ln > len(buf):
            break
        out.append((mtype, buf[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def certs_from_certificate_message(body):
    """TLS 1.3 Certificate (RFC 8446 section 4.4.2): context, then a list of DER certs."""
    ctx_len = body[0]
    i = 1 + ctx_len
    total = int.from_bytes(body[i:i + 3], "big"); i += 3
    end = i + total
    certs = []
    while i + 3 <= end:
        ln = int.from_bytes(body[i:i + 3], "big"); i += 3
        certs.append(body[i:i + ln]); i += ln
        ext_ln = int.from_bytes(body[i:i + 2], "big"); i += 2 + ext_ln
    return certs


def decrypt_session(pcap, keylog_path):
    """Reassemble the capture, unlock the handshake, return the recovered certificate chain."""
    segs = mb.read_pcap_native(pcap)
    c2s = [(s, d) for (dirn, s, d) in segs if dirn]
    s2c = [(s, d) for (dirn, s, d) in segs if not dirn]
    cbuf, _ = mb.reassemble(c2s)
    sbuf, _ = mb.reassemble(s2c)

    # client hello -> client_random and offered suites
    ch = None
    for rtype, ver, hdr, payload in tls_records(bytes(cbuf)):
        if rtype == 22 and payload[:1] == b"\x01":
            ch = payload
            break
    if ch is None:
        raise SystemExit("no ClientHello in the capture")
    client_random = ch[6:38].hex()
    # suite list: session_id len, session_id, suite len, suites
    i = 38
    sid_len = ch[i]; i += 1 + sid_len
    cs_len = int.from_bytes(ch[i:i + 2], "big"); i += 2
    suites = [int.from_bytes(ch[i + j * 2:i + j * 2 + 2], "big") for j in range(cs_len // 2)]

    # server hello -> chosen suite, negotiated version
    sh = None
    for rtype, ver, hdr, payload in tls_records(bytes(sbuf)):
        if rtype == 22 and payload[:1] == b"\x02":
            sh = payload
            break
    if sh is None:
        raise SystemExit("no ServerHello in the capture")
    if sh[6:38] == HRR_RANDOM:
        raise SystemExit("HelloRetryRequest: the key schedule restarts, refusing to guess")
    sid_len = sh[38]; i = 39 + sid_len
    suite_id = int.from_bytes(sh[i:i + 2], "big"); i += 2
    suite = SUITES.get(suite_id)
    if not suite:
        raise SystemExit(f"unsupported TLS 1.3 suite 0x{suite_id:04x}")

    kl = read_keylog(keylog_path)
    shs = kl.get("SERVER_HANDSHAKE_TRAFFIC_SECRET", {}).get(client_random)
    chs = kl.get("CLIENT_HANDSHAKE_TRAFFIC_SECRET", {}).get(client_random)
    if not shs:
        raise SystemExit("the keylog has no SERVER_HANDSHAKE_TRAFFIC_SECRET for this ClientHello")

    key, iv = traffic_keys(shs, suite)

    # decrypt the server's protected records (the ServerHello itself is plaintext, so the first
    # protected record is sequence 0)
    plain, seq, saw_sh = bytearray(), 0, False
    for rtype, ver, hdr, payload in tls_records(bytes(sbuf)):
        if rtype == 22 and payload[:1] == b"\x02":
            saw_sh = True
            continue
        if not saw_sh or rtype != 23:
            continue
        p = open_record(suite, key, iv, seq, hdr, payload)
        seq += 1
        if p is None:
            break                      # a later record belongs to the application traffic key
        # RFC 8446 s5.4: the inner plaintext is content, then the real content type, then zero
        # padding. Strip the padding first, then the type byte - per record, or the handshake
        # messages after the first one misalign.
        p = p.rstrip(b"\x00")
        if p:
            p = p[:-1]
        plain += p

    msgs = handshake_messages(bytes(plain))
    chain = None
    kinds = []
    for mtype, body in msgs:
        kinds.append({8: "EncryptedExtensions", 11: "Certificate", 15: "CertificateVerify",
                      20: "Finished"}.get(mtype, hex(mtype)))
        if mtype == 11 and chain is None:
            chain = certs_from_certificate_message(body)
    return {"client_random": client_random, "suite": suite["name"], "suite_id": suite_id,
            "offered_suites": suites, "chain": chain or [], "messages": kinds,
            "client_secret_present": bool(chs), "decrypted_bytes": len(plain)}


# ---------------------------------------------------------------- grading + evidence
def grade(chain, host):
    """Grade the recovered chain with the same checks the rest of the engine uses."""
    leaf = x509.load_der_x509_certificate(chain[0])
    issuers = [x509.load_der_x509_certificate(d) for d in chain[1:]]
    ca = mb.root_ca()
    anchors = [ca["cert"]] + issuers
    ok, why = mb.verify_chain(chain[0], [i.public_bytes(serialization.Encoding.DER) for i in anchors[1:]])
    sans = []
    try:
        sans = list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    import datetime as _dt
    now = _dt.datetime.utcnow()
    days_left = (leaf.not_valid_after - now).days
    pub = leaf.public_key()
    from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa as _rsa
    if isinstance(pub, _ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.curve.key_size
    elif isinstance(pub, _rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    else:
        key_type, key_bits = type(pub).__name__, 0
    return {
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": str(leaf.serial_number),
        "sans": sans,
        "san_matches_host": mb.san_matches(host, sans),
        "key_type": key_type,
        "key_bits": key_bits,
        "sig_alg": leaf.signature_hash_algorithm.name,
        "not_before": leaf.not_valid_before.isoformat(sep=" ")[:19],
        "not_after": leaf.not_valid_after.isoformat(sep=" ")[:19],
        "days_left": days_left,
        "chain_len": len(chain),
        "chain_anchored": bool(ok),
        "chain_note": why,
    }


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def build(outdir, results_path):
    facts = make_capture(outdir)
    got = decrypt_session(facts["pcap"], facts["keylog"])
    if not got["chain"]:
        raise SystemExit("no certificate recovered - refusing to write a result")
    graded = grade(got["chain"], facts["host"])
    # the proof: the certificate we recovered must be the one the server was holding
    identical = got["chain"][0] == facts["leaf_der"]
    if not identical:
        raise SystemExit("recovered certificate does not match the served certificate")

    rec = {
        "method": "real TLS 1.3 IMAPS handshake between Python ssl (OpenSSL) endpoints, captured at "
                  "a relay - the same tap position as the live validation; the certificate is "
                  "recovered from the encrypted handshake using the SSLKEYLOGFILE the client wrote, "
                  "by deriving the handshake traffic keys (HKDF-Expand-Label, RFC 8446 s7.1) and "
                  "opening the records (AES-GCM, per-record nonce from the sequence number)",
        "caveats": "the endpoint and the capture are local, and a keylog is only available to an "
                   "operator who owns an endpoint - that is the honest precondition of this route. "
                   "Without a keylog the certificate stays 'not observable' and we say so; this run "
                   "shows what the same capture yields when the precondition is met.",
        "host": facts["host"],
        "server_banner": facts["banner"],
        "client_negotiated": facts["client"],
        "decrypted": {k: v for k, v in got.items() if k != "chain"},
        "certificate": graded,
        "chain_len_recovered": len(got["chain"]),
        "certificate_matches_served": identical,
        "served_cert_sha256": hashlib.sha256(facts["leaf_der"]).hexdigest(),
        "recovered_cert_sha256": hashlib.sha256(got["chain"][0]).hexdigest(),
        "capture": os.path.basename(facts["pcap"]),
        "capture_sha256": sha256_file(facts["pcap"]),
        "keylog": os.path.basename(facts["keylog"]),
        "bytes_c2s": facts["c2s_bytes"], "bytes_s2c": facts["s2c_bytes"],
    }
    json.dump(rec, open(results_path, "w", encoding="utf-8"), indent=1, sort_keys=True)
    print(f"TLS 1.3 keylog path")
    print(f"  capture   : {rec['capture']} ({rec['bytes_c2s']}+{rec['bytes_s2c']} bytes)")
    print(f"  negotiated: {got['suite']}, handshake messages after ServerHello: {', '.join(got['messages'])}")
    print(f"  recovered : {graded['subject']} · {graded['key_type']} {graded['key_bits']} · "
          f"{graded['sig_alg']} · {graded['days_left']} days left · chain {graded['chain_len']} "
          f"{'anchored' if graded['chain_anchored'] else 'NOT anchored'}")
    print(f"  proof     : recovered certificate == served certificate ({identical})")
    print(f"  written   : {os.path.relpath(results_path, ROOT)}")
    return 0


def _find(name, *extra):
    """Find a shipped artefact whether we are authoring (ms_keylog/) or inside the package
    (data/keylog/ + results/)."""
    for base in list(extra) + [os.path.join(ROOT, "ms_keylog"), os.path.join(ROOT, "data", "keylog"),
                               RESULTS, os.path.join(HERE, "data", "keylog"), HERE]:
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return name


def verify(results_path):
    """Re-derive the whole thing from the shipped capture + keylog and compare to the record."""
    rec = json.load(open(results_path))
    base = os.path.dirname(results_path)
    pcap = _find(rec["capture"], base)
    keylog = _find(rec["keylog"], base)
    try:
        got = decrypt_session(pcap, keylog)
    except SystemExit as e:
        print(f"FAIL - the capture could not be unlocked: {e}")
        return 1
    if not got["chain"]:
        print("FAIL - no certificate recovered with this keylog: the secrets do not match this capture")
        return 1
    graded = grade(got["chain"], rec["host"])
    problems = []
    if got["suite"] != rec["decrypted"]["suite"]:
        problems.append(f"suite {got['suite']} != {rec['decrypted']['suite']}")
    if graded["subject"] != rec["certificate"]["subject"]:
        problems.append("subject mismatch")
    if hashlib.sha256(got["chain"][0]).hexdigest() != rec["recovered_cert_sha256"]:
        problems.append("recovered certificate hash mismatch")
    if sha256_file(pcap) != rec["capture_sha256"]:
        problems.append("capture bytes changed")
    ok = not problems
    print(("PASS - " if ok else "FAIL - ") + (", ".join(problems) if problems
          else f"recovered {graded['subject']} from {len(got['chain'])} certificate(s) in {got['suite']}"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="TLS 1.3 keylog path: capture, decrypt, grade, prove.")
    ap.add_argument("--out", default=os.path.join(ROOT, "ms_keylog"), help="where the capture lives")
    ap.add_argument("--results", default=None, help="path for keylog_validation.json")
    ap.add_argument("--verify", metavar="RESULTS_JSON", help="re-derive from the shipped capture")
    a = ap.parse_args()
    if a.verify:
        return verify(a.verify)
    results = a.results or os.path.join(
        RESULTS if os.path.isdir(RESULTS) else ROOT, "keylog_validation.json")
    return build(a.out, results)


if __name__ == "__main__":
    sys.exit(main())
