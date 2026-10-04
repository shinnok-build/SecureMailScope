"""Capture two REAL TLS 1.3 handshakes against a local OpenSSL 3.5 server:

  A. X25519MLKEM768  - the standardised hybrid post-quantum group
  B. x25519          - the classical group, same server, same keys

Both run over loopback on port 993 (IMAPS) with SSLKEYLOGFILE on both sides, so the
captures can be decrypted afterwards by the same keylog path the console ships.
The result is a genuine post-quantum handshake on the wire, graded by the same
engine that grades the corpus - not a synthetic packet dump.
"""
import os, signal, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = HERE
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")
DATA = os.path.join(ROOT, "data")
CERT = os.path.join(DATA, "keylog", "_server_cert.pem")
KEY = os.path.join(DATA, "keylog", "_server_key.pem")
OUT = os.path.join(DATA, "keylog")
PCAPS = os.path.join(ROOT, "evidence", "pq")
PORT = 993


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def clear_strays():
    sh("sudo pkill -x openssl")          # exact binary name: never matches this shell
    time.sleep(0.5)


def wait_listen(port, timeout=10):
    """Poll with ss(8): a real connect would consume the server's single accept slot."""
    end = time.time() + timeout
    while time.time() < end:
        out = sh(f"sudo ss -ltn").stdout
        if f":{port}" in out:
            return True
        time.sleep(0.25)
    return False


def capture(group, name):
    pcap = os.path.join(PCAPS, f"{name}-993.pcap")
    keylog = os.path.join(OUT, f"pq_{name}_keylog.txt")          # server side (root)
    keylog_cli = os.path.join(OUT, f"pq_{name}_cli.txt")          # client side (this user)
    for f in (pcap, keylog, keylog_cli):
        if os.path.exists(f):
            os.remove(f)
    clear_strays()
    srv = subprocess.Popen(["sudo", "openssl", "s_server", "-accept", str(PORT), "-tls1_3",
                            "-groups", group, "-cert", CERT, "-key", KEY,
                            "-keylogfile", keylog, "-naccept", "1", "-quiet", "-ign_eof"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not wait_listen(PORT):
        srv.kill()
        raise SystemExit(f"server never listened on {PORT}")
    tcp = subprocess.Popen(["sudo", "tcpdump", "-i", "lo", "-w", pcap, "-s", "0", f"tcp port {PORT}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2.5)
    print("     ss:", " | ".join(l.split()[3] for l in sh("sudo ss -ltn").stdout.splitlines() if ":993" in l)[:120] or "NOT LISTENING")
    # shell pipeline: this is the sequence that produced a 5.7 kB capture in testing
    cli = sh(f"printf 'a1 LOGIN analyst secret\\r\\n' | timeout 25 openssl s_client "
             f"-connect 127.0.0.1:{PORT} -tls1_3 -groups {group} -quiet -keylogfile {keylog_cli} 2>&1")
    time.sleep(1.5)
    tcp.send_signal(signal.SIGINT)
    try:
        _, te = tcp.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        tcp.kill(); te = ""
    srv.kill()
    sh("sudo pkill -x openssl")
    print(f"     client rc={cli.returncode} stderr={(cli.stderr or '')[:160]!r}")
    size = os.path.getsize(pcap) if os.path.exists(pcap) else 0
    stats = [l for l in (te or "").splitlines() if "captured" in l or "listening on" in l]
    print("     tcpdump:", " / ".join(x.strip() for x in stats)[:200])
    nlines = sum(len(open(f).read().splitlines()) for f in (keylog, keylog_cli) if os.path.exists(f))
    negotiated = next((l.strip() for l in (cli.stdout or "").splitlines() if "group" in l.lower()), "")
    print(f"  {name:14s} group={group:16s} pcap={size:7d} B  keylog={nlines} lines  {stats[0] if stats else ''}")
    print(f"     negotiated: {negotiated or '(client produced no summary line)'}")
    return pcap, keylog, keylog_cli


print("capturing real handshakes on loopback:993")
a = capture("X25519MLKEM768", "pq-hybrid")
b = capture("x25519", "pq-classical")

merged = os.path.join(OUT, "pq_keylog.txt")
lines = []
for kl in (a[1], a[2], b[1], b[2]):
    if os.path.exists(kl):
        lines += [l for l in open(kl).read().splitlines() if l.strip() and not l.startswith("#")]
seen, uniq = set(), []
for l in lines:
    if l not in seen:
        seen.add(l); uniq.append(l)
open(merged, "w").write("\n".join(uniq) + "\n")
print(f"\nmerged keylog: {merged}  ({len(uniq)} secret lines)")
kinds = sorted({l.split()[0] for l in uniq})
print("secret types:", kinds)
for kl in (a[1], a[2], b[1], b[2]):
    if os.path.exists(kl):
        os.remove(kl)
for f in ("pq-hybrid-993.pcap", "pq-classical-993.pcap"):
    p = os.path.join(PCAPS, f)
    print(f"{f}: {os.path.getsize(p)} B")
