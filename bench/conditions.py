"""The experiment matrix from the proposal (Part 6): two sweeps sharing a baseline.

    Set A (RTT sweep):   20 ms / 100 ms / 200 ms RTT, 0 % loss
    Set B (loss sweep):  ~20 ms RTT with 0 % (shared with A-1) / 2 % / 5 % loss

rtt_ms is the *added* round-trip delay, split evenly over the two router-side interfaces
of the R1-R2 transit link. Loss is applied on ONE direction only (R1 egress), so the
nominal 2 % / 5 % is the loss rate each packet in that direction sees; see the report's
methodology section for why we do not split it across both directions.
"""

CONDITIONS = [
    # id,            rtt_ms, loss_pct, sweep
    ("rtt20_loss0",    20,   0, "A+B"),
    ("rtt100_loss0",  100,   0, "A"),
    ("rtt200_loss0",  200,   0, "A"),
    ("rtt20_loss2",    20,   2, "B"),
    ("rtt20_loss5",    20,   5, "B"),
]

HANDSHAKE_CONFIGS = ["tcp", "tls12", "tls13", "tls13_resumed"]
MODES = ["tcp", "tls", "e2ee"]
PAYLOADS = [64, 1024, 16384]

LABELS = {
    "tcp": "Plain TCP", "tls12": "TLS 1.2", "tls13": "TLS 1.3", "tls13_resumed": "TLS 1.3 resumed",
    "tls": "TLS only", "e2ee": "TLS + E2EE",
}


def get(cond_id):
    for c in CONDITIONS:
        if c[0] == cond_id:
            return dict(id=c[0], rtt_ms=c[1], loss_pct=c[2], sweep=c[3])
    raise KeyError(cond_id)
