"""Static figures for the report, from results/summary.json (matplotlib, no display needed).

    python3 -m bench.plots [--summary results/summary.json] [--out results/plots]

Every bar is a mean over runs with the standard deviation across runs as the error bar,
exactly the numbers in the experiment tables.
"""
import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench import conditions as C

COLORS = {"tcp": "#bdbdbd", "tls12": "#7f7f7f", "tls13": "#3f3f3f", "tls13_resumed": "#000000",
          "tls": "#7f7f7f", "e2ee": "#000000"}


def style():
    plt.rcParams.update({"figure.dpi": 140, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.grid": True, "grid.alpha": .25, "axes.axisbelow": True,
                         "font.size": 9.5, "axes.titleweight": "bold", "legend.frameon": False})


def label(c):
    return f"{c['rtt_ms']} ms\n{c['loss_pct']}% loss"


def grouped(ax, conds, series, get, ylabel):
    n = len(series)
    w = 0.8 / n
    for i, key in enumerate(series):
        xs, ys, es = [], [], []
        for j, c in enumerate(conds):
            s = get(c["id"], key)
            if s:
                xs.append(j + (i - (n - 1) / 2) * w)
                ys.append(s["mean"]); es.append(s["sd"])
        ax.bar(xs, ys, w * .92, yerr=es, capsize=2, color=COLORS[key], label=C.LABELS[key], error_kw=dict(lw=.8))
    ax.set_xticks(range(len(conds)))
    ax.set_xticklabels([label(c) for c in conds])
    ax.set_ylabel(ylabel)
    ax.legend(ncol=2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--summary", default="results/summary.json")
    p.add_argument("--out", default="results/plots")
    a = p.parse_args()
    style()
    S = json.load(open(a.summary))
    os.makedirs(a.out, exist_ok=True)
    conds = S["conditions"]
    A = [c for c in conds if "A" in c["sweep"]]
    B = [c for c in conds if "B" in c["sweep"]]
    H, L = S["handshake"], S["latency"]
    env = S["meta"]["env"]
    tag = "" if env == "netns" else f"  [{env}]"

    def hs(metric):
        return lambda cid, cfg: (H.get(cid, {}).get(cfg) or {}).get(metric)

    for name, sweep, title in (("rtt", A, "RTT sweep (0% loss)"), ("loss", B, "Loss sweep (~20 ms RTT)")):
        if not sweep:
            continue
        for metric, nice in (("tls_ms", "TLS handshake time"), ("ttfd_ms", "Time to first application data")):
            fig, ax = plt.subplots(figsize=(7, 3.4))
            grouped(ax, sweep, [k for k in C.HANDSHAKE_CONFIGS if metric != "tls_ms" or k != "tcp"],
                    hs(metric), "ms")
            ax.set_title(f"{nice}: {title}{tag}")
            fig.tight_layout(); fig.savefig(f"{a.out}/handshake_{metric}_{name}.png"); plt.close(fig)

    def lat(payload):
        return lambda cid, mode: (L.get(cid, {}).get(mode, {}) or {}).get(str(payload))

    for name, sweep, title in (("rtt", A, "RTT sweep"), ("loss", B, "Loss sweep")):
        if not sweep:
            continue
        fig, axes = plt.subplots(1, len(C.PAYLOADS), figsize=(8.2, 3.7), sharey=True)
        for ax, pl in zip(axes, C.PAYLOADS):
            grouped(ax, sweep, C.MODES, lat(pl), "message latency (ms)")
            if name == "rtt":                      # 16 KiB takes several RTTs; a log axis keeps 64 B visible
                top = max(v["mean"] + v["sd"] for c in sweep for m in C.MODES
                          for v in [lat(pl)(c["id"], m)] if v) * 2.2
                ax.set_yscale("log"); ax.set_ylim(10, top)
            ax.set_title(f"{pl} B payload")
        for ax in axes:
            if ax.get_legend():
                ax.get_legend().remove()
        handles = [plt.Rectangle((0, 0), 1, 1, color=COLORS[m]) for m in C.MODES]
        fig.suptitle(f"End-to-end message latency A -> relay -> B: {title}{tag}", fontweight="bold")
        fig.legend(handles, [C.LABELS[m] for m in C.MODES], loc="lower center", ncol=3, fontsize=9)
        fig.tight_layout(rect=(0, 0.07, 1, 1)); fig.savefig(f"{a.out}/latency_{name}.png"); plt.close(fig)

    # E2EE overhead vs payload size: fixed 40 B => proportionally huge for tiny messages
    fig, ax = plt.subplots(figsize=(5.6, 3.2))
    sizes = C.PAYLOADS
    ax.bar([str(s) for s in sizes], [40 / s * 100 for s in sizes], color=COLORS["e2ee"])
    for i, s in enumerate(sizes):
        ax.text(i, 40 / s * 100 + 1, f"{40 / s * 100:.1f}%", ha="center", fontsize=8)
    ax.set_xlabel("plaintext payload (bytes)"); ax.set_ylabel("E2EE overhead (% of payload)")
    ax.set_title("Fixed 40 B (24 B nonce + 16 B MAC) E2EE overhead")
    fig.tight_layout(); fig.savefig(f"{a.out}/e2ee_overhead.png"); plt.close(fig)
    print("plots written to", a.out)


if __name__ == "__main__":
    main()
