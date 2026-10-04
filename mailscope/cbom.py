# -*- coding: utf-8 -*-
"""mailscope_cbom.py - CycloneDX 1.6 Cryptography Bill of Materials from captures.

    python3 mailscope_cbom.py ms_pq/ --out ms_pq/cbom.json      # any capture or directory
    python3 mailscope_cbom.py ms_pcaps/ --out ms_cbom.json      # a whole corpus

Every component is read off the wire by the same engine that grades the corpus: protocol
version, cipher suite, key-agreement group (with the post-quantum hybrids marked), certificate
public-key and signature algorithms. Nothing is inferred from a policy wish-list, and each
component carries the captures it was seen in as evidence.
"""
import argparse, glob, json, os, sys, warnings, datetime

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_HERE = HERE
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mailscope import engine as mb

TLS_NAMES = {769: "1.0", 770: "1.1", 771: "1.2", 772: "1.3"}

# NIST IR 8547 / SP 800-208 style levels: classical bits, and the quantum category a
# post-quantum primitive is expected to reach (0 = not quantum-resistant at all)
GROUP_LEVELS = {
    "X25519MLKEM768": (128, 3), "SecP256r1MLKEM768": (128, 3), "SecP384r1MLKEM1024": (192, 5),
    "MLKEM512": (0, 1), "MLKEM768": (0, 3), "MLKEM1024": (0, 5),
    "X25519Kyber768Draft00": (128, 3), "X25519Kyber768Draft00 (Chrome draft codepoint)": (128, 3),
    "x25519": (128, 0), "x448": (224, 0), "P-256": (128, 0), "P-384": (192, 0), "P-521": (256, 0),
    "ffdhe2048": (112, 0), "ffdhe3072": (128, 0), "ffdhe4096": (152, 0),
}
HASH_LEVELS = {"sha256": (128, 0), "sha384": (192, 0), "sha512": (256, 0), "sha1": (63, 0), "md5": (0, 0)}


def port_from_name(path):
    for p in os.path.basename(path).replace(".", "-").split("-"):
        if p.isdigit() and int(p) in (25, 110, 143, 465, 587, 993, 995, 999):
            return int(p)
    return 993


def read_one(path, port=None):
    segs = mb.read_pcap_native(path)
    c2s = [(s, d) for (d_, s, d) in segs if d_]
    s2c = [(s, d) for (d_, s, d) in segs if not d_]
    if not c2s and not s2c:
        return None
    return mb.analyse(c2s, s2c, dict(port=port or port_from_name(path)))


def main():
    ap = argparse.ArgumentParser(description="Emit a CycloneDX 1.6 CBOM from mail captures.")
    ap.add_argument("path", help="a .pcap file or a directory of them")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--out", default="cbom.json")
    ap.add_argument("--name", default=None, help="component name for the BOM metadata")
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.path, "*.pcap"))) if os.path.isdir(a.path) else [a.path]
    algos, protos, certs = {}, {}, {}
    sessions, read, pq_sessions = 0, 0, 0
    corpus_files = []

    for path in files:
        sess = read_one(path, a.port)
        if not sess or not sess.get("feats"):
            continue
        read += 1; sessions += 1
        f = sess["feats"]; rel = os.path.relpath(path, _HERE)
        corpus_files.append(rel)
        if not f.get("ver"):
            continue
        # --- protocol component
        ver = TLS_NAMES.get(f.get("ver"), "unknown")
        pid = f"tls-{ver}"
        p = protos.setdefault(pid, dict(version=ver, suites={}, occurrences=[]))
        if f.get("cipher"):
            p["suites"].setdefault(f["cipher"], {"id": "0x%04x" % (f.get("cipher_id") or 0), "n": 0})["n"] += 1
        p["occurrences"].append(rel)
        # --- key agreement
        ke = f.get("ke_group") or ""
        if ke:
            is_pq = any(name == ke for name in mb.GROUPS.values() if mb.is_pq(
                [k for k, v in mb.GROUPS.items() if v == ke][0]))
            klass, quantum = GROUP_LEVELS.get(ke, (128, 0))
            c = algos.setdefault(f"ka:{ke}", dict(name=ke, primitive="key-agree",
                                                  klass=klass, quantum=quantum, pq=is_pq, occ=[]))
            c["occ"].append(rel)
            if is_pq:
                pq_sessions += 1
        # --- cipher suite -> encryption + hash components, driven by the IANA registry name
        full = mb.SUITES.get(f.get("cipher_id") or 0) or (f.get("cipher") or "")
        kex, auth = "", ""
        enc_token, hash_token = "", ""
        if full.startswith("TLS_AES") or full.startswith("TLS_CHACHA"):
            parts = full[4:].split("_")
            enc_token = "_".join(parts[:-1]); hash_token = parts[-1]
            kex = "key_share"
        elif "_WITH_" in full:
            ka, rest = full[4:].split("_WITH_")
            kex, _, auth = ka.partition("_")
            enc_token, _, hash_token = rest.rpartition("_")
        norm = (enc_token.replace("AES_", "AES-").replace("CHACHA20_POLY1305", "CHACHA20-POLY1305")
                .replace("3DES_EDE", "3DES-EDE").replace("DES40", "DES40").replace("RC4_128", "RC4")
                .replace("_GCM", "-GCM").replace("_CBC", "-CBC").replace("_CCM", "-CCM"))
        if norm and "NULL" not in norm:
            bits = 256 if "256" in norm else (192 if "192" in norm else (128 if "128" in norm else 0))
            primitive = "aead" if ("GCM" in norm or "POLY1305" in norm or "CCM" in norm) else "cipher"
            c = algos.setdefault(f"enc:{norm}", dict(name=norm, primitive=primitive, klass=bits,
                                                     quantum=0, pq=False, occ=[]))
            c["occ"].append(rel)
        ht = hash_token.lower().replace("-", "")
        if ht in ("sha", "sha1", "sha256", "sha384", "sha512", "md5"):
            nm = {"sha": "SHA-1", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384",
                  "sha512": "SHA-512", "md5": "MD5"}[ht]
            klass, quantum = HASH_LEVELS.get(ht if ht != "sha" else "sha1", (128, 0))
            c = algos.setdefault(f"hash:{nm}", dict(name=nm, primitive="hash", klass=klass, quantum=0,
                                                    pq=False, occ=[], weak=(ht in ("sha", "sha1", "md5"))))
            c["occ"].append(rel)
        if kex and kex not in ("key_share", "UNKNOWN"):
            c = algos.setdefault(f"kex:{kex}", dict(name=kex, primitive="key-agree",
                                                    klass=(128 if kex in ("ECDHE", "DHE") else 0),
                                                    quantum=0, pq=False, occ=[]))
            c["occ"].append(rel)
        if auth and auth not in ("UNKNOWN", "cert"):
            c = algos.setdefault(f"auth:{auth}", dict(name=auth, primitive="signature", klass=128,
                                                      quantum=0, pq=False, occ=[]))
            c["occ"].append(rel)
        # --- certificate components, from what the handshake actually showed
        if f.get("subject"):
            key_kind = f.get("keyalg") or "unknown"
            key_bits = f.get("keybits") or 0
            sig = f.get("sigalg") or ""
            nm = f"{key_kind}-{key_bits}" if key_bits else key_kind
            c = algos.setdefault(f"pk:{nm}", dict(name=nm, primitive="pke", klass=key_bits, quantum=0,
                                                  pq=False, occ=[]))
            c["occ"].append(rel)
            cid = "cert:%s" % f["subject"]
            cc = certs.setdefault(cid, dict(subject=f.get("subject"), issuer=f.get("issuer"),
                                            not_after=f.get("days_left"), key=nm, sig=sig, occ=[]))
            cc["occ"].append(rel)

    comps = []
    for pid, p in sorted(protos.items()):
        comps.append(dict(
            type="cryptographic-asset", bom_ref=pid, name=f"TLS {p['version']}",
            cryptoProperties=dict(
                assetType="protocol",
                protocolProperties=dict(
                    type="tls", version=p["version"],
                    cipherSuites=[dict(name=n, identifiers=[v["id"]], algorithms=[]) for n, v in sorted(p["suites"].items())])),
            evidence=dict(occurrences=[dict(location=x) for x in sorted(set(p["occurrences"]))])))
    for ref, c in sorted(algos.items()):
        props = dict(primitive=c["primitive"], classicalSecurityLevel=c["klass"])
        if c["pq"]:
            props["nistQuantumSecurityLevel"] = c["quantum"]
        comps.append(dict(
            type="cryptographic-asset", bom_ref=ref, name=c["name"],
            cryptoProperties=dict(assetType="algorithm", algorithmProperties=props),
            properties=[dict(name="pqc:post-quantum", value="true" if c["pq"] else "false")]
                       + ([dict(name="pqc:weak-hash", value="true")] if c.get("weak") else []),
            evidence=dict(occurrences=[dict(location=x) for x in sorted(set(c["occ"]))])))
    for ref, c in sorted(certs.items()):
        comps.append(dict(
            type="cryptographic-asset", bom_ref=ref, name=c["subject"] or "certificate",
            cryptoProperties=dict(
                assetType="certificate",
                certificateProperties=dict(subjectName=c["subject"], issuerName=c["issuer"],
                                           certificateFormat="X.509",
                                           signatureAlgorithmRef="sig:%s" % c["sig"],
                                           subjectPublicKeyRef="pk:%s" % c["key"])),
            evidence=dict(occurrences=[dict(location=x) for x in sorted(set(c["occ"]))])))

    bom = dict(
        bomFormat="CycloneDX", specVersion="1.6", version=1,
        metadata=dict(timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      tools=[dict(vendor="SecureMailScope", name="mailscope_cbom", version="1.0")],
                      component=dict(type="application", name=a.name or "SecureMailScope",
                                     bom_ref="mailscope")),
        components=comps,
        properties=[
            dict(name="mailscope:sessions-graded", value=str(sessions)),
            dict(name="mailscope:captures-read", value=str(read)),
            dict(name="mailscope:post-quantum-sessions", value=str(pq_sessions)),
            dict(name="mailscope:pqc-ready", value="true" if pq_sessions else "false"),
        ])
    def fix(o):
        if isinstance(o, dict):
            return {k.replace("bom_ref", "bom-ref"): fix(v) for k, v in o.items()}
        if isinstance(o, list):
            return [fix(x) for x in o]
        return o
    json.dump(fix(bom), open(a.out, "w"), indent=1)
    print(f"CBOM written to {a.out}")
    print(f"  captures read       : {read} of {len(files)}")
    print(f"  sessions graded     : {sessions}")
    print(f"  post-quantum ready  : {pq_sessions} session(s)")
    print(f"  components          : {len(comps)}  "
          f"({len(protos)} protocol, {len(algos)} algorithm, {len(certs)} certificate)")
    for ref, c in sorted(algos.items()):
        if c["pq"]:
            print(f"    PQ algorithm: {c['name']}  (quantum category {c['quantum']}, "
                  f"{len(set(c['occ']))} capture(s))")


if __name__ == "__main__":
    main()
