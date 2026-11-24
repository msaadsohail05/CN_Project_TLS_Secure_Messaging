#!/bin/bash
# Stage 10: impairment control for the R1-R2 transit link (tc netem + tc tbf).
#
#   sudo bash scripts/impair.sh set --rtt-ms 100 [--loss 2] [--rate 10mbit]
#   sudo bash scripts/impair.sh clear
#   sudo bash scripts/impair.sh show
#
# Design (proposal Part 1.6 / 2.5):
#   * qdiscs attach to an interface's EGRESS, so the delay is applied on BOTH router-side
#     interfaces of the link (r1:eth-t and r2:eth-t), each carrying half of the target RTT.
#   * loss is applied on ONE direction only (r1:eth-t egress, i.e. client -> relay), so
#     "2 %" means each packet in that direction has a 2 % chance of being dropped and the
#     condition stays interpretable.
#   * an optional tbf child on the same qdisc caps the bandwidth.
set -euo pipefail

IFACE=eth-t
usage() { sed -n '2,15p' "$0"; exit 1; }
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
[ $# -ge 1 ] || usage
cmd=$1; shift

clear_all() {
  for ns in r1 r2; do
    ip netns exec "$ns" tc qdisc del dev "$IFACE" root 2>/dev/null || true
  done
}

case "$cmd" in
  clear)
    clear_all; echo "impairments cleared" ;;
  show)
    for ns in r1 r2; do echo "== $ns $IFACE"; ip netns exec "$ns" tc qdisc show dev "$IFACE"; done ;;
  set)
    rtt=0; loss=0; rate=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --rtt-ms) rtt=$2; shift 2 ;;
        --loss)   loss=$2; shift 2 ;;
        --rate)   rate=$2; shift 2 ;;
        *) usage ;;
      esac
    done
    clear_all
    half=$(awk -v r="$rtt" 'BEGIN{printf "%g", r/2}')
    for ns in r1 r2; do
      args="delay ${half}ms"
      if [ "$ns" = r1 ] && [ "$loss" != "0" ]; then args="$args loss ${loss}%"; fi
      # shellcheck disable=SC2086
      ip netns exec "$ns" tc qdisc add dev "$IFACE" root handle 1: netem $args
      if [ -n "$rate" ]; then
        ip netns exec "$ns" tc qdisc add dev "$IFACE" parent 1:1 handle 10: tbf rate "$rate" burst 32kbit latency 400ms
      fi
    done
    echo "impairment set: rtt=${rtt}ms (${half}ms per direction) loss=${loss}% (client->relay only) rate=${rate:-unlimited}" ;;
  *) usage ;;
esac
