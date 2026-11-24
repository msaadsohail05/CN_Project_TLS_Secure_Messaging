#!/bin/bash
# Stage 9/16: record the nine required captures (proposal Part 9) in one go.
#
#   sudo bash topology.sh up
#   sudo bash scripts/capture_evidence.sh
#
# Output: evidence/captures/*.pcapng  (+ *.keylog so Wireshark can decrypt the TLS records:
#         Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename).
# The keylog files only contain secrets of this project's throw-away test CA/sessions.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
PY=${PYTHON:-python3}
CAP=evidence/captures
mkdir -p "$CAP" results/raw
rm -f "$CAP"/*.keylog

R=10.0.2.10
NS() { ip netns exec "$@"; }
cap_start() { bash scripts/capture.sh start "$@"; }
cap_stop()  { bash scripts/capture.sh stop "$@"; }

[ -f certs/server.crt ] || $PY certs_tool.py
pkill -f "relay.py --host $R" 2>/dev/null || true
sleep 0.5
NS relay $PY -u relay.py --host $R --port 8443 --tls --allow-tls12 --plain-port 8080 \
    --keylog "$CAP/relay.keylog" > evidence/relay_capture.log 2>&1 &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true' EXIT
sleep 1.5

echo "== 1. routing proof: traceroute + ICMP TTL-exceeded"
cap_start clientA eth0 routing_traceroute icmp
NS clientA traceroute -n -I $R | tee evidence/traceroute_clientA.txt
cap_stop routing_traceroute

echo "== 2. TCP three-way handshake (plain TCP, port 8080)"
cap_start r1 eth-t tcp_handshake "tcp port 8080"
NS clientA $PY -m bench.probe tcp --host $R
cap_stop tcp_handshake

echo "== 3. TLS 1.3 full handshake (decrypt with the keylog)"
cap_start r1 eth-t tls13_full "tcp port 8443"
NS clientA $PY -m bench.probe tls13 --host $R --keylog "$CAP/tls13_full.keylog"
cap_stop tls13_full

echo "== 4. TLS 1.2 handshake (comparison)"
cap_start r1 eth-t tls12_handshake "tcp port 8443"
NS clientA $PY -m bench.probe tls12 --host $R --keylog "$CAP/tls12_handshake.keylog"
cap_stop tls12_handshake

echo "== 5. TLS 1.3 resumed handshake (no Certificate / CertificateVerify when decrypted)"
cap_start r1 eth-t tls13_resumed "tcp port 8443"
NS clientA $PY -m bench.probe resumed --host $R --keylog "$CAP/tls13_resumed.keylog"
cap_stop tls13_resumed

echo "== 6/7. key registration + lookup, and one full E2EE message relay (A -> relay -> B)"
# capture on the transit link (what a network observer sees) and on the relay's own link
cap_start r1 eth-t e2ee_transit "tcp port 8443"
cap_start r2 eth-rl e2ee_relay_side "tcp port 8443"
rm -f results/raw/latency_capture.csv /tmp/recv.out
NS clientB $PY -u -m bench.msgbench recv --host $R --mode e2ee -n 5 --cond capture --payload 64 \
    --out results/raw/latency_capture.csv --keylog "$CAP/e2ee_transit.keylog" > /tmp/recv.out &
RECV=$!
for i in $(seq 1 40); do grep -q READY /tmp/recv.out 2>/dev/null && break; sleep 0.25; done
NS clientA $PY -u -m bench.msgbench send --host $R --mode e2ee -n 5 --cond capture --payload 64 \
    --keylog "$CAP/e2ee_transit.keylog"
wait $RECV
cap_stop e2ee_transit
cap_stop e2ee_relay_side
# the relay-side capture is decrypted with the relay's own secrets
cp "$CAP/relay.keylog" "$CAP/e2ee_relay_side.keylog" 2>/dev/null || true

echo "== 8. untrusted certificate rejection (on-path MITM with a forged certificate)"
bash scripts/attack_demo.sh mitm-capture

echo "== 9. substituted public key / fingerprint mismatch"
bash scripts/attack_demo.sh keyswap-capture

echo
echo "done. captures:"
ls -1 "$CAP"/*.pcap* 2>/dev/null || true
