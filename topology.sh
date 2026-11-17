#!/bin/bash
# Stage 1: namespace topology (5 namespaces, veth links, forwarding)
# Usage: sudo bash topology.sh up|down|status
set -e

NS="clientA clientB r1 r2 relay"

[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }

down() {
  for n in $NS; do ip netns del "$n" 2>/dev/null || true; done
  echo "topology down"
}

up() {
  down
  for n in $NS; do
    ip netns add "$n"
    ip -n "$n" link set lo up
  done

 # create each pair with temporary unique names, then move and rename the ends
mkpair() {   # mkpair <tmpA> <nsA> <nameA> <tmpB> <nsB> <nameB>
  ip link add "$1" type veth peer name "$4"
  ip link set "$1" netns "$2" name "$3"
  ip link set "$4" netns "$5" name "$6"
}
mkpair tmpa1 clientA eth0  tmpa2 r1 eth-a
mkpair tmpb1 clientB eth0  tmpb2 r1 eth-b
mkpair tmpr1 relay   eth0  tmpr2 r2 eth-rl
mkpair tmpt1 r1      eth-t tmpt2 r2 eth-t

  # addresses (from the addressing plan)
  ip -n clientA addr add 10.0.1.10/24 dev eth0
  ip -n r1      addr add 10.0.1.1/24  dev eth-a
  ip -n clientB addr add 10.0.3.10/24 dev eth0
  ip -n r1      addr add 10.0.3.1/24  dev eth-b
  ip -n relay   addr add 10.0.2.10/24 dev eth0
  ip -n r2      addr add 10.0.2.1/24  dev eth-rl
  ip -n r1      addr add 10.0.12.1/29 dev eth-t
  ip -n r2      addr add 10.0.12.2/29 dev eth-t

  # bring every interface up
  for pair in "clientA eth0" "clientB eth0" "relay eth0" \
              "r1 eth-a" "r1 eth-b" "r1 eth-t" "r2 eth-rl" "r2 eth-t"; do
    set -- $pair
    ip -n "$1" link set "$2" up
  done

  # hosts use their router as default gateway
  ip -n clientA route add default via 10.0.1.1
  ip -n clientB route add default via 10.0.3.1
  ip -n relay   route add default via 10.0.2.1

  # routers forward packets
  ip netns exec r1 sysctl -qw net.ipv4.ip_forward=1
  ip netns exec r2 sysctl -qw net.ipv4.ip_forward=1

  echo "topology up"
}

status() {
  for n in $NS; do echo "== $n"; ip -n "$n" -br addr; done
}

case "$1" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "Usage: sudo bash topology.sh up|down|status" ;;
esac