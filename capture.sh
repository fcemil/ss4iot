#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "Usage: $0 <output.pcap> [interface] [excluded-host]"
  exit 1
fi

OUTPUT_FILE="$1"
INTERFACE="${2:-wlan0}"
EXCLUDED_HOST="${3:-}"

TCPDUMP_CMD=(sudo tcpdump -U -i "$INTERFACE" -w -)

if [[ -n "$EXCLUDED_HOST" ]]; then
  TCPDUMP_CMD+=(-f "not (host $EXCLUDED_HOST)")
fi

"${TCPDUMP_CMD[@]}" \
  | tee "$OUTPUT_FILE" \
  | tcpdump -n -r -