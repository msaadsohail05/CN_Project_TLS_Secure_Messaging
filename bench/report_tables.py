"""Print the experiment tables as Markdown, ready to paste into docs/REPORT.md.

    python3 -m bench.report_tables [results/summary.json]
"""
import json
import sys


def pm(s, d=1):
    return "–" if not s else f"{s['mean']:.{d}f} ± {s['sd']:.{d}f}"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    path = sys.argv[1] if len(sys.argv) > 1 else "results/summary.json"
    S = json.load(open(path))
    H, L, lab = S["handshake"], S["latency"], S["meta"]["labels"]
    print(f"<!-- generated from {path}; environment: {S['meta']['env']} -->\n")
    print("### Handshake (ms, mean ± σ across runs)\n")
    print("| Condition | Configuration | TCP connect | TLS handshake | Time to first data | Runs | Errors |")
    print("|---|---|---|---|---|---|---|")
    for c in S["conditions"]:
        for cfg in ("tcp", "tls12", "tls13", "tls13_resumed"):
            e = H.get(c["id"], {}).get(cfg)
            if e:
                print(f"| {c['rtt_ms']} ms / {c['loss_pct']} % | {lab[cfg]} | {pm(e['tcp_ms'], 2)} | "
                      f"{'–' if cfg == 'tcp' else pm(e['tls_ms'])} | {pm(e['ttfd_ms'])} | {e['tls_ms']['runs'] if e['tls_ms'] else 0} | {e['errors']} |")
    print("\n### Message latency (ms, mean ± σ across runs)\n")
    print("| Condition | Mode | Payload | Mean ± σ | Median | p95 | Max | Body on wire (B) |")
    print("|---|---|---|---|---|---|---|---|")
    for c in S["conditions"]:
        for mode in ("tcp", "tls", "e2ee"):
            for pl, e in sorted(L.get(c["id"], {}).get(mode, {}).items(), key=lambda kv: int(kv[0])):
                print(f"| {c['rtt_ms']} ms / {c['loss_pct']} % | {lab[mode]} | {pl} B | {pm(e, 2)} | {e['median']:.2f} | {e['p95']:.2f} | {e['max']:.1f} | {e['wire_body_bytes']} |")
    ver = [c for c in S["conditions"] if c.get("measured")]
    if ver:
        print("\n### Condition verification (ping, configured vs measured)\n")
        print("| Condition | Configured RTT | Measured RTT | Configured loss | Measured loss |")
        print("|---|---|---|---|---|")
        for c in ver:
            m = c["measured"]
            print(f"| {c['id']} | {m['configured_rtt_ms']} ms | {m['measured_rtt_ms']} ms | {m['configured_loss_pct']} % | {m['measured_loss_pct']} % |")


if __name__ == "__main__":
    main()
