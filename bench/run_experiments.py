"""Stage 16: run the whole experiment matrix and aggregate it.

Official runs (Linux, root, topology built by topology.sh):

    sudo python3 -m bench.run_experiments --env netns

For every condition in bench/conditions.py it
  1. applies the impairment on the R1-R2 link (scripts/impair.sh -> tc netem),
  2. verifies it independently with ping (configured vs measured RTT / loss),
  3. runs the handshake matrix from clientA  (bench/exp_handshake.py),
  4. runs the message-latency matrix clientA -> relay -> clientB  (bench/msgbench.py),
  5. clears the impairment,
then writes results/summary.json (bench/aggregate.py).

`--env local` runs the same pipeline on loopback with a user-space delay emulator
(bench/linkemu.py) so it can be smoke-tested without namespaces; its output is labelled
`loopback-emulated`, has no packet loss, and is not a substitute for the netns runs.
"""
import argparse
import json
import os
import platform
import random
import re
import ssl
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import certs_tool
from bench import aggregate
from bench import conditions as C

PY = sys.executable


class NetnsEnv:
    name = "netns"
    host, tls_port, plain_port = "10.0.2.10", 8443, 8080

    def __init__(self):
        self.relay = None

    def wrap(self, ns, argv):
        return ["ip", "netns", "exec", ns] + argv

    def start_relay(self):
        self.log = open("results/relay.log", "w")
        self.relay = subprocess.Popen(
            self.wrap("relay", [PY, "-u", "relay.py", "--host", self.host, "--port", str(self.tls_port),
                                "--tls", "--allow-tls12", "--plain-port", str(self.plain_port)]),
            stdout=self.log, stderr=subprocess.STDOUT)
        probe = "import socket;socket.create_connection(('%s',%d),2)" % (self.host, self.tls_port)
        for _ in range(40):
            if subprocess.run(self.wrap("clientA", [PY, "-c", probe]), capture_output=True).returncode == 0:
                return
            time.sleep(0.25)
        raise SystemExit("relay did not come up; is the topology built (sudo bash topology.sh up)?")

    def set_condition(self, cond):
        subprocess.run(["bash", "scripts/impair.sh", "set", "--rtt-ms", str(cond["rtt_ms"]),
                        "--loss", str(cond["loss_pct"])], check=True)

    def clear(self):
        subprocess.run(["bash", "scripts/impair.sh", "clear"], check=True, capture_output=True)

    def verify(self, cond):
        """Independent check that the condition really is what we configured."""
        out = subprocess.run(self.wrap("clientA", ["ping", "-c", "200", "-i", "0.02", "-q", self.host]),
                             capture_output=True, text=True).stdout
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
        l = re.search(r"([\d.]+)% packet loss", out)
        return dict(cond=cond["id"], method="ping -c 200 -i 0.02 clientA->relay",
                    configured_rtt_ms=cond["rtt_ms"], configured_loss_pct=cond["loss_pct"],
                    measured_rtt_ms=float(m.group(2)) if m else None,
                    measured_loss_pct=float(l.group(1)) if l else None)

    def stop(self):
        if self.relay:
            self.relay.terminate()


class LocalEnv:
    name = "loopback-emulated"
    host, tls_port, plain_port = "127.0.0.1", 28443, 28080

    def __init__(self):
        self.proxies = []

    def wrap(self, ns, argv):
        return argv

    def start_relay(self):
        import tlsutil
        from relay import Relay
        ctx = tlsutil.server_ctx("certs/server.crt", "certs/server.key", allow_tls12=True)
        self.relay = Relay("127.0.0.1", 18443, ctx, plain_port=18080, verbose=False).start()

    def set_condition(self, cond):
        from bench.linkemu import DelayProxy
        self.clear()
        d = cond["rtt_ms"] / 2        # half the RTT in each direction, like the two-sided netem
        self.proxies = [DelayProxy(self.tls_port, ("127.0.0.1", 18443), d),
                        DelayProxy(self.plain_port, ("127.0.0.1", 18080), d)]

    def clear(self):
        for p in self.proxies:
            p.stop()
        self.proxies = []

    def verify(self, cond):
        return dict(cond=cond["id"], method="emulated delay proxy (no ping verification)",
                    configured_rtt_ms=cond["rtt_ms"], configured_loss_pct=0,
                    measured_rtt_ms=None, measured_loss_pct=None)

    def stop(self):
        self.clear()
        self.relay.stop()


def flags(env):
    return ["--host", env.host, "--tls-port", str(env.tls_port), "--plain-port", str(env.plain_port)]


def trial(env, cond, mode, payload, run, a, raw):
    out = os.path.join(raw, f"latency_{cond['id']}.csv")
    base = [PY, "-u", "-m", "bench.msgbench"]
    common = flags(env) + ["--mode", mode, "--payload", str(payload), "-n", str(a.msgs), "--cond", cond["id"],
                           "--run", str(run), "--out", out]
    timeout = a.msgs * 0.01 + 90
    recv = subprocess.Popen(env.wrap("clientB", base + ["recv"] + common + ["--timeout", str(timeout)]),
                            stdout=subprocess.PIPE, text=True)
    line = recv.stdout.readline().strip()
    if line != "READY":
        recv.kill()
        return False
    s = subprocess.run(env.wrap("clientA", base + ["send"] + common), capture_output=True, text=True,
                       timeout=timeout)
    try:
        recv.wait(timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        recv.kill()
    return s.returncode == 0 and recv.returncode == 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--env", choices=["netns", "local"], default="netns")
    p.add_argument("--runs", type=int, default=5, help="repetitions per condition (>=3 required)")
    p.add_argument("--conns", type=int, default=20, help="sequential connections per handshake config per run")
    p.add_argument("--msgs", type=int, default=100, help="messages A->B per latency trial")
    p.add_argument("--conditions", nargs="+", default=[c[0] for c in C.CONDITIONS])
    p.add_argument("--only", choices=["handshake", "latency"])
    p.add_argument("--quick", action="store_true", help="smoke test: 2 runs, 5 conns, 20 msgs")
    p.add_argument("--out", default="results")
    p.add_argument("--seed", type=int, default=1)
    a = p.parse_args()
    if a.quick:
        a.runs, a.conns, a.msgs = 2, 5, 20
    if a.env == "netns" and os.geteuid() != 0:
        sys.exit("netns runs need root: sudo python3 -m bench.run_experiments")

    raw = os.path.join(a.out, "raw")
    os.makedirs(raw, exist_ok=True)
    for f in os.listdir(raw):                      # fresh run: never mix with an old matrix
        os.remove(os.path.join(raw, f))
    certs_tool.ensure("certs", rogue=False)
    env = NetnsEnv() if a.env == "netns" else LocalEnv()
    rng = random.Random(a.seed)
    env.start_relay()
    t_start = time.time()
    try:
        for cid in a.conditions:
            cond = C.get(cid)
            print(f"\n=== condition {cid}: RTT {cond['rtt_ms']} ms, loss {cond['loss_pct']} % ===", flush=True)
            env.set_condition(cond)
            time.sleep(1)
            ver = env.verify(cond)
            with open(os.path.join(raw, f"verify_{cid}.json"), "w") as f:
                json.dump(ver, f, indent=1)
            print("verified:", ver, flush=True)
            if a.only != "latency":
                subprocess.run(env.wrap("clientA", [PY, "-u", "-m", "bench.exp_handshake", *flags(env),
                                                    "--cond", cid, "--runs", str(a.runs), "--conns", str(a.conns),
                                                    "--seed", str(a.seed),
                                                    "--out", os.path.join(raw, f"handshake_{cid}.csv")]),
                               check=True)
            if a.only != "handshake":
                combos = [(m, pl) for m in C.MODES for pl in C.PAYLOADS]
                for run in range(1, a.runs + 1):
                    rng.shuffle(combos)            # randomised order inside every run
                    for mode, payload in combos:
                        ok = trial(env, cond, mode, payload, run, a, raw)
                        if not ok:                 # one retry: the old connection may still be closing
                            time.sleep(1)
                            ok = trial(env, cond, mode, payload, run, a, raw)
                        print(f"  latency run {run} {mode:5s} {payload:5d} B  {'ok' if ok else 'FAILED'}", flush=True)
                        time.sleep(0.3 + cond["rtt_ms"] / 1000)
            env.clear()
    finally:
        env.clear()
        env.stop()

    meta = dict(env=env.name, runs=a.runs, conns=a.conns, msgs=a.msgs, seconds=round(time.time() - t_start),
                kernel=platform.release(), python=platform.python_version(), openssl=ssl.OPENSSL_VERSION,
                finished=time.strftime("%Y-%m-%d %H:%M:%S"))
    with open(os.path.join(a.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    sys.argv = ["aggregate", "--raw", raw, "--out", os.path.join(a.out, "summary.json"), "--env", env.name]
    aggregate.main()


if __name__ == "__main__":
    main()
