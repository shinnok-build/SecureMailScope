# -*- coding: utf-8 -*-
"""scale_test.py — how the pipeline behaves when the capture stops being a demo.

The 448-session corpus proves correctness. It does not say what happens when a mirror port
delivers a real sweep: thousands of sessions, tens of megabytes, one process. This script
measures that, and writes ms_scale.json so the number is checkable rather than asserted.

    python3 scale_test.py            # 5,000 sessions, ~3 minutes
    python3 scale_test.py 200        # a quick smoke run

Two figures are recorded, because they answer different questions:

  end_to_end   read the capture from disk -> reassemble both directions -> grade it. One pass
               per session, exactly the path an analyst runs with the CLI.
  analysis     grade pre-parsed sessions, median of 3 passes: the same measurement the
               448-session headline uses (2,800+ sessions/s), so the two are comparable.

Reassembly is re-checked against the generator's ground truth for every session at scale, so a
fast-but-wrong result cannot hide behind a throughput number.

Caveats printed and stored with the numbers: sessions are synthetic (as the problem statement
allows), generated on the machine that grades them, and a mirror port also has to write the
capture to disk - this measures the analysis pipeline, not the switch.
"""
import json, os, resource, statistics, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.basename(HERE) == "mailscope"          # True inside the shipped package
ROOT = os.path.dirname(HERE) if PKG else HERE
RESULTS = os.path.join(ROOT, "results")

sys.path.insert(0, HERE)
try:
    import mailscope_bench as mb                     # authoring tree
except ImportError:                                   # shipped package
    from mailscope import engine as mb

import scapy.utils as sp


def out_path(name):
    for base in (RESULTS, HERE):
        if os.path.isdir(base):
            return os.path.join(base, name)
    return os.path.join(HERE, name)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    tmp = os.path.join(ROOT, ".scale_pcaps")
    os.makedirs(tmp, exist_ok=True)

    # ---- pass A: generate, write, then read back, reassemble and grade (end to end) -----------
    t0 = time.perf_counter()
    sessions, exact, total, findings, postures = 0, 0, 0, 0, []
    t_pipe = 0.0
    t_gen = 0.0
    bytes_written = 0
    seg_cache = []
    for i in range(n):
        label, proto, cfg, weak = mb.SCENARIOS[i % len(mb.SCENARIOS)]
        c = dict(cfg)
        c["tag"] = f"scale-{i}"
        c["cert"] = mb.cert_for(c)
        c["pseed"] = i
        c["profile"] = mb.rnd_profile(i, forced=cfg.get("cipher"), minimal=cfg.get("minimal", False),
                                      grease=cfg.get("grease", False), shuffle=cfg.get("shuffle", False))
        tg = time.perf_counter()
        g = mb.build_session(proto, c)
        path = os.path.join(tmp, f"s{i}.pcap")
        sp.wrpcap(path, g.pkts)
        t_gen += time.perf_counter() - tg
        bytes_written += os.path.getsize(path)
        truth_c2s, truth_s2c = bytes(g.truth[True]), bytes(g.truth[False])
        g.pkts = None
        sessions += 1

        # everything an analyst's pipeline does: read the capture from disk, split the
        # directions, reassemble both, then grade the session.
        t1 = time.perf_counter()
        segs = mb.read_pcap_native(path)
        c2s = [(s, d) for (dirn, s, d) in segs if dirn]
        s2c = [(s, d) for (dirn, s, d) in segs if not dirn]
        f_bytes, _ = mb.reassemble(c2s)
        r_bytes, _ = mb.reassemble(s2c)
        got = mb.analyse(c2s, s2c, c)
        t_pipe += time.perf_counter() - t1

        total += 2
        if f_bytes == truth_c2s:
            exact += 1
        if r_bytes == truth_s2c:
            exact += 1
        findings += len(got["findings"])
        if got.get("posture") is not None:
            postures.append(got["posture"])
        if len(seg_cache) < min(n, 2000):
            seg_cache.append((c2s, s2c, c, len(segs)))
        os.remove(path)
    wall = time.perf_counter() - t0
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    # ---- pass B: analysis-only rate, median of 3, comparable with the 448-session headline ----
    passes = []
    for _ in range(3):
        t1 = time.perf_counter()
        for c2s, s2c, c, _n in seg_cache:
            mb.analyse(c2s, s2c, c)
        passes.append(time.perf_counter() - t1)
    med = statistics.median(passes)
    sps_analysis = len(seg_cache) / med

    bench_path = os.path.join(RESULTS, "ms_bench.json")
    if not os.path.exists(bench_path):
        bench_path = os.path.join(HERE, "ms_bench.json")
    baseline = None
    if os.path.exists(bench_path):
        b = json.load(open(bench_path))
        baseline = (b.get("throughput") or {}).get("native_sessions_per_second")

    rec = dict(
        method="one process, single thread; the pipeline figure reads every capture back from "
               "disk, reassembles both directions and grades it (generation of the synthetic "
               "corpus is timed separately and excluded); the analysis figure grades "
               "pre-parsed sessions, median of 3 passes, so it is comparable with the "
               "448-session headline rate",
        caveats="sessions are synthetic and generated on the same machine that grades them; "
                "a real mirror port also has to write the capture to disk, so this measures "
                "the analysis pipeline, not the switch or the disk",
        sessions=sessions,
        capture_bytes=bytes_written,
        capture_mb=round(bytes_written / 1048576.0, 2),
        wall_seconds=round(wall, 2),
        generation_seconds=round(t_gen, 2),
        generation_sessions_per_second=round(sessions / t_gen, 1) if t_gen else None,
        pipeline_seconds=round(t_pipe, 2),
        pipeline_sessions_per_second=round(sessions / t_pipe, 1) if t_pipe else None,
        analysis_seconds_median=round(med, 3),
        analysis_sessions_per_second=round(sps_analysis, 1),
        analysis_sample=len(seg_cache),
        corpus_baseline_sessions_per_second=baseline,
        peak_rss_mb=round(peak_mb, 1),
        reassembly_byte_exact=f"{exact}/{total}",
        findings=findings,
        posture_mean=(round(statistics.mean(postures), 1) if postures else None),
    )
    dest = out_path("ms_scale.json")
    json.dump(rec, open(dest, "w", encoding="utf-8"), indent=1, sort_keys=True)
    print(f"scale run: {sessions} sessions, {rec['capture_mb']} MB of capture")
    print(f"  pipeline          : {rec['pipeline_seconds']} s  ->  {rec['pipeline_sessions_per_second']} sessions/s"
          f"  (read + reassemble + grade)")
    print(f"  lab generation    : {rec['generation_seconds']} s  ->  {rec['generation_sessions_per_second']} sessions/s"
          f"  (building the synthetic captures, excluded from the pipeline figure)")
    print(f"  analysis only     : {rec['analysis_seconds_median']} s for {rec['analysis_sample']} sessions"
          f"  ->  {rec['analysis_sessions_per_second']} sessions/s")
    print(f"  reassembly        : {rec['reassembly_byte_exact']} byte-exact at scale")
    print(f"  peak RSS          : {rec['peak_rss_mb']} MB")
    print(f"  written           : {os.path.relpath(dest, ROOT)}")
    try:
        os.rmdir(tmp)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
