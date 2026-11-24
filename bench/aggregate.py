"""Turn the raw per-connection / per-message CSVs into results/summary.json.

Statistics: every metric is first averaged *within* each run, then we report the mean of
those run means and their standard deviation across runs (n = number of runs, 5 in the
plan). That is the "mean and spread over >=3 runs" the course asks for; the pooled
min / max / p95 are kept alongside so outliers stay visible rather than hidden.

    python3 -m bench.aggregate --raw results/raw --out results/summary.json
"""
import argparse
import csv
import glob
import json
import os
import statistics as st
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench import conditions as C


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summarize(by_run):
    """by_run: {run: [values]} -> stats dict."""
    run_means = [st.fmean(v) for _, v in sorted(by_run.items()) if v]
    allv = [x for v in by_run.values() for x in v]
    if not allv:
        return None
    return dict(mean=st.fmean(run_means), sd=st.stdev(run_means) if len(run_means) > 1 else 0.0,
                runs=len(run_means), run_means=run_means, n=len(allv), min=min(allv), max=max(allv),
                median=st.median(allv), p95=pct(allv, 95))


def read(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def handshake(raw):
    out = defaultdict(lambda: defaultdict(dict))
    for path in glob.glob(os.path.join(raw, "handshake_*.csv")):
        rows = read(path)
        groups = defaultdict(list)
        for r in rows:
            groups[(r["cond"], r["config"])].append(r)
        for (cond, config), rs in groups.items():
            errs = [r for r in rs if r.get("error")]
            ok = [r for r in rs if not r.get("error")]
            entry = dict(connections=len(rs), errors=len(errs),
                         resumed_fraction=(sum(int(r["resumed"]) for r in ok) / len(ok)) if ok else 0.0)
            for metric in ("tcp_ms", "tls_ms", "ttfd_ms"):
                by_run = defaultdict(list)
                for r in ok:
                    by_run[int(r["run"])].append(float(r[metric]))
                entry[metric] = summarize(by_run)
            out[cond][config] = entry
    return out


def latency(raw):
    out = defaultdict(lambda: defaultdict(dict))
    groups = defaultdict(lambda: defaultdict(list))
    wire = {}
    for path in glob.glob(os.path.join(raw, "latency_*.csv")):
        for r in read(path):
            groups[(r["cond"], r["mode"], int(r["payload"]))][int(r["run"])].append(float(r["latency_us"]) / 1000)
            wire[(r["cond"], r["mode"], int(r["payload"]))] = int(r["wire_bytes"])
    for (cond, mode, payload), by_run in groups.items():
        s = summarize(by_run)
        s["wire_body_bytes"] = wire[(cond, mode, payload)]
        out[cond][mode][str(payload)] = s       # milliseconds
    return out


def verification(raw):
    out = {}
    for path in glob.glob(os.path.join(raw, "verify_*.json")):
        with open(path) as f:
            d = json.load(f)
        out[d["cond"]] = d
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", default="results/raw")
    p.add_argument("--out", default="results/summary.json")
    p.add_argument("--env", default="netns", help="netns | loopback-emulated")
    a = p.parse_args()
    hs, lat, ver = handshake(a.raw), latency(a.raw), verification(a.raw)
    present = set(hs) | set(lat)
    conds = []
    for cid, rtt, loss, sweep in C.CONDITIONS:
        if cid in present:
            conds.append(dict(id=cid, rtt_ms=rtt, loss_pct=loss, sweep=sweep, measured=ver.get(cid)))
    summary = dict(meta=dict(env=a.env, generated=time.strftime("%Y-%m-%d %H:%M:%S"),
                             labels=C.LABELS, payloads=C.PAYLOADS),
                   conditions=conds, handshake=hs, latency=lat)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(summary, f, indent=1)

    # flat CSV tables for the report appendix
    base = os.path.splitext(a.out)[0]
    with open(base + "_handshake.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cond", "config", "metric", "mean_ms", "sd_ms", "runs", "n", "min", "max", "p95", "errors"])
        for cond in hs:
            for config, e in hs[cond].items():
                for m in ("tcp_ms", "tls_ms", "ttfd_ms"):
                    s = e[m]
                    if s:
                        w.writerow([cond, config, m, f"{s['mean']:.3f}", f"{s['sd']:.3f}", s["runs"], s["n"],
                                    f"{s['min']:.3f}", f"{s['max']:.3f}", f"{s['p95']:.3f}", e["errors"]])
    with open(base + "_latency.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cond", "mode", "payload_B", "mean_ms", "sd_ms", "runs", "n", "median", "p95", "max", "wire_body_B"])
        for cond in lat:
            for mode in lat[cond]:
                for pl, s in lat[cond][mode].items():
                    w.writerow([cond, mode, pl, f"{s['mean']:.3f}", f"{s['sd']:.3f}", s["runs"], s["n"],
                                f"{s['median']:.3f}", f"{s['p95']:.3f}", f"{s['max']:.3f}", s["wire_body_bytes"]])
    print("wrote", a.out, "and", base + "_handshake.csv,", base + "_latency.csv")


if __name__ == "__main__":
    main()
