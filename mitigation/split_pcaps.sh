#!/usr/bin/env bash
# First 70% of every pcap -> <out>/train, last 30% -> <out>/test (chronological, no overlap).
# Usage: split_pcaps.sh <pcap folder> <out folder>
set -euo pipefail
mkdir -p "$2/train" "$2/test"
for f in "$1"/*.pcap; do
    n=$(capinfos -TrcM "$f" | cut -f2); cut_at=$((n * 70 / 100)); b=$(basename "$f")
    editcap -F pcap -r "$f" "$2/train/$b" "1-$cut_at"
    editcap -F pcap -r "$f" "$2/test/$b" "$((cut_at + 1))-$n"
    echo "$b: train $cut_at, test $((n - cut_at))"
done
