#!/bin/bash
# Stage 9: packet-capture helper.
#
#   sudo bash scripts/capture.sh start <namespace> <interface> <name> [bpf filter...]
#   sudo bash scripts/capture.sh stop  <name>
#
# Writes evidence/captures/<name>.pcapng (converted with editcap when Wireshark's CLI tools
# are installed; otherwise the classic .pcap is kept, which Wireshark opens just as well).
set -euo pipefail

DIR=evidence/captures
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
mkdir -p "$DIR"
cmd=${1:-}; shift || true

case "$cmd" in
  start)
    ns=$1; iface=$2; name=$3; shift 3
    rm -f "$DIR/$name.pcap" "$DIR/$name.pcapng"
    ip netns exec "$ns" tcpdump -i "$iface" -U -s 0 -w "$DIR/$name.pcap" "$@" \
        >"/tmp/cap_$name.log" 2>&1 &
    echo $! > "/tmp/cap_$name.pid"
    sleep 1                       # let tcpdump open the interface before traffic starts
    echo "capturing $ns/$iface -> $DIR/$name.pcap (pid $(cat /tmp/cap_"$name".pid))" ;;
  stop)
    name=$1
    sleep 0.5                     # let the last packets reach the capture buffer
    kill -INT "$(cat "/tmp/cap_$name.pid")" 2>/dev/null || true
    sleep 0.5
    if command -v editcap >/dev/null 2>&1; then
      editcap -F pcapng "$DIR/$name.pcap" "$DIR/$name.pcapng" && rm -f "$DIR/$name.pcap"
      echo "saved $DIR/$name.pcapng"
    else
      echo "saved $DIR/$name.pcap (install wireshark-common for editcap to get .pcapng)"
    fi
    rm -f "/tmp/cap_$name.pid" ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac
