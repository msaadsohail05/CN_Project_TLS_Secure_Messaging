#!/bin/bash
# Stage 17: the security demonstrations inside the routed topology.
#
#   sudo bash scripts/attack_demo.sh mitm        # forged certificate on the path (R1 is compromised)
#   sudo bash scripts/attack_demo.sh keyswap     # malicious relay substitutes Bob's key
#   sudo bash scripts/attack_demo.sh all
#   (mitm-capture / keyswap-capture do the same and also save the .pcapng evidence)
#
# The honest relay must NOT be running on 10.0.2.10 for `keyswap` (the script replaces it);
# restart it afterwards with:  sudo ip netns exec relay python3 relay.py --host 10.0.2.10 --tls ...
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
PY=${PYTHON:-python3}
R=10.0.2.10
NS() { ip netns exec "$@"; }
which=${1:-all}
CAPTURE=0
case "$which" in *-capture) CAPTURE=1; which=${which%-capture} ;; esac
[ -f certs/rogue/server.crt ] || $PY certs_tool.py
mkdir -p evidence

stop_all() {
  pkill -f "tls_mitm.py" 2>/dev/null || true
  pkill -f "evil_relay.py" 2>/dev/null || true
  NS r1 iptables -t nat -F PREROUTING 2>/dev/null || true
}
trap stop_all EXIT

run_mitm() {
  echo "### Attack 1: forged certificate, R1 redirects $R:8443 to an attacker proxy"
  stop_all
  NS r1 $PY -u attacks/tls_mitm.py --listen 9443 --upstream $R:8443 > evidence/mitm.log 2>&1 &
  sleep 1
  NS r1 iptables -t nat -A PREROUTING -p tcp -d $R --dport 8443 -j REDIRECT --to-ports 9443
  if [ $CAPTURE = 1 ]; then bash scripts/capture.sh start r1 eth-a untrusted_cert_rejection "tcp port 8443"; fi
  echo "--- victim trusting only the project CA:"
  if NS clientA $PY -m bench.probe tls13 --host $R; then
    echo "FAIL: client accepted the forged certificate"; exit 1
  else
    echo "=> connection refused (expected)"
  fi
  if [ $CAPTURE = 1 ]; then bash scripts/capture.sh stop untrusted_cert_rejection; fi
  echo "--- what the attacker saw:"; cat evidence/mitm.log
  NS r1 iptables -t nat -F PREROUTING
}

run_keyswap() {
  echo "### Attack 2: the relay hands out its own key for Bob"
  stop_all
  pkill -f "relay.py --host $R" 2>/dev/null || true
  sleep 0.5
  NS relay $PY -u attacks/evil_relay.py --host $R --tls --victims alice alice2 bob > evidence/evil_relay.log 2>&1 &
  sleep 1.5
  rm -rf keys_demo; mkdir keys_demo
  if [ $CAPTURE = 1 ]; then bash scripts/capture.sh start r1 eth-t keyswap_fingerprint_mismatch "tcp port 8443"; fi
  # Bob stays online for a few seconds (his real fingerprint is printed on start-up)
  ( sleep 9; echo /quit ) | NS clientB env PYTHONPATH=. $PY -u client.py bob --host $R --mode e2ee > evidence/keyswap_bob.txt 2>&1 &
  BOB_PID=$!
  sleep 2.5
  FP=$(grep -m1 'fingerprint:' evidence/keyswap_bob.txt | sed 's/fingerprint: *//')
  echo "Bob's real fingerprint:  $FP"
  echo "--- Alice WITHOUT pinning (attack succeeds silently):"
  ( echo "bob: the vault code is 4711"; sleep 3; echo /quit ) | NS clientA $PY -u client.py alice --host $R --mode e2ee || true
  echo "--- Alice WITH Bob's fingerprint pinned (attack detected):"
  ( echo "bob: the vault code is 4711"; sleep 3; echo /quit ) | NS clientA $PY -u client.py alice2 --host $R --mode e2ee --trust "bob=$FP" || true
  wait $BOB_PID || true
  if [ $CAPTURE = 1 ]; then bash scripts/capture.sh stop keyswap_fingerprint_mismatch; fi
  echo "--- what the malicious relay did:"; cat evidence/evil_relay.log
  echo "--- Bob's screen:"; cat evidence/keyswap_bob.txt
  stop_all
  rm -rf keys_demo
}

case "$which" in
  mitm) run_mitm ;;
  keyswap) run_keyswap ;;
  all) run_mitm; run_keyswap ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
