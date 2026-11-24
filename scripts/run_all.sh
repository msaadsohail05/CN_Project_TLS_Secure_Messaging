#!/bin/bash
# Stage 18: reproduce everything on a clean Ubuntu 20.04/22.04/24.04 machine, in order.
#   sudo bash scripts/run_all.sh [--quick]
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
PY=${PYTHON:-python3}
QUICK=${1:-}

echo "== 0. dependencies"
$PY -c "import nacl" 2>/dev/null || pip3 install -r requirements.txt
echo "== 1. certificates"
$PY certs_tool.py
echo "== 2. topology"
bash topology.sh up
echo "== 3. routing proof"
mkdir -p evidence results/raw
for n in clientA clientB r1 r2 relay; do echo "== $n"; ip -n $n route; done | tee evidence/routing_tables.txt
ip netns exec clientA traceroute -n 10.0.2.10 | tee evidence/traceroute_clientA.txt
ip netns exec clientB traceroute -n 10.0.2.10 | tee evidence/traceroute_clientB.txt
echo "== 4. unit tests"
$PY -m unittest discover -s tests
echo "== 5. captures"
bash scripts/capture_evidence.sh
echo "== 6. attack demos"
bash scripts/attack_demo.sh all
echo "== 7. experiments"
bash topology.sh up
if [ "$QUICK" = "--quick" ]; then
  $PY -m bench.run_experiments --env netns --quick
else
  $PY -m bench.run_experiments --env netns
fi
echo "== 8. plots + overhead analysis"
$PY -m bench.plots
for f in tls13_full tls13_resumed tls12_handshake; do
  if [ -f evidence/captures/$f.pcapng ]; then
    $PY -m bench.analyze_overhead evidence/captures/$f.pcapng --server-port 8443 --json > results/overhead_$f.json || true
  fi
done
echo "done. Open the dashboard:  $PY ui/server.py   (http://127.0.0.1:8088)"
