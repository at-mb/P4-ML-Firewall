#!/usr/bin/env bash
# Compare mitigation off / src / 5tuple on held-out traffic. Run in the P4 VM, venv active.
# Modes: off | src | srcN (src, block only sources with >= N flagged flows per round) | 5tuple
# Usage: run_test.sh <model.h5> <attack test pcap> <benign test pcap> <out folder>
# Optional env: MODES, ATTACK_PPS, BENIGN_PPS, DURATION (s), ATTACKER, PROTECT, DATASET_TYPE, P4DDLE_ROOT
set -euo pipefail
[[ $# -eq 4 ]] || { sed -n '2,4p' "$0"; exit 1; }
[[ -n "${VIRTUAL_ENV:-}" ]] || { echo "Activate the venv first"; exit 1; }
ROOT="${P4DDLE_ROOT:-$HOME/p4ddle/p4-ddos}"
MODEL=$(realpath "$1"); mkdir -p "$4"; OUT=$(realpath "$4")
MODES="${MODES:-off src src5 5tuple}"; ATTACK_PPS="${ATTACK_PPS:-100}"; BENIGN_PPS="${BENIGN_PPS:-50}"
DURATION="${DURATION:-60}"; ATTACKER="${ATTACKER:-172.16.0.5}"; PROTECT="${PROTECT:-192.168.50.0/24}"
DATASET_TYPE="${DATASET_TYPE:-DOS2019_MC}"
PY=$(which python3); WARMUP=10

[[ -f "$ROOT/control-plane/mitigation.py" ]] || { echo "Apply mitigation.patch first"; exit 1; }
sudo -v

# No looping: trim both traces to what is sent, so that "offered" is exact.
# Benign starts WARMUP seconds earlier and keeps running during the attack.
editcap -F pcap -r "$2" "$OUT/attack.pcap" "1-$((ATTACK_PPS * DURATION))"
editcap -F pcap -r "$3" "$OUT/benign.pcap" "1-$((BENIGN_PPS * (DURATION + WARMUP)))"
count() { tcpdump -nn -r "$1" "$2" 2>/dev/null | wc -l; }
ATT="ip and src host $ATTACKER"; BEN="ip and not host $ATTACKER"

# Always compile: the repository ships an old JSON without the mitigation tables.
(cd "$ROOT/data-plane/p4ddle" && p4c --target bmv2 --arch v1model --std p4-16 p4_bloom_management.p4)
JSON="$ROOT/data-plane/p4ddle/p4_bloom_management.json"
grep -q 'MyIngress.blocked_flows' "$JSON" || { echo "Compiled JSON lacks the mitigation tables"; exit 1; }

PRED=""
cleanup() {
    [[ -n "$PRED" ]] && kill -TERM "$PRED" 2>/dev/null || true
    sudo pkill -f "launcher.py --behavioral-exe" 2>/dev/null || true
    sudo pkill -x tcpreplay 2>/dev/null || true
    sudo pkill -x simple_switch 2>/dev/null || true
    sudo mn -c >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "mode,attack_offered,attack_received,attack_blocked_pct,benign_offered,benign_received,benign_lost_pct,rules,seconds_to_first_rule,predicted_attack_flows" > "$OUT/summary.csv"

for mode in $MODES; do
    echo "=== mitigation: $mode ==="
    D="$OUT/$mode"; rm -rf "$D"; mkdir -p "$D"
    mitigate="$mode"; min_flows=1
    if [[ "$mode" =~ ^src([0-9]+)$ ]]; then mitigate=src; min_flows="${BASH_REMATCH[1]}"; fi
    sudo mn -c >/dev/null 2>&1 || true
    (cd "$ROOT/data-plane/runner" && sudo "$PY" -u launcher.py --behavioral-exe simple_switch --json "$JSON" \
        --cli simple_switch_CLI < <(tail -f /dev/null) > "$D/switch.log" 2>&1) &
    # "Ready !" is printed after commands1.txt (forwarding rules, sampling_treshold=1) is loaded
    for _ in $(seq 60); do grep -q "Ready !" "$D/switch.log" 2>/dev/null && break; sleep 1; done
    grep -q "Ready !" "$D/switch.log" || { echo "switch not ready after 60 s, see $D/switch.log"; exit 1; }
    "$PY" -c "import socket; socket.create_connection(('localhost',22222),5)" || { echo "switch failed, see $D/switch.log"; exit 1; }

    H1=$(pgrep -f 'mininet:h1$' | head -n1 || true); H2=$(pgrep -f 'mininet:h2$' | head -n1 || true)
    [[ -n "$H1" && -n "$H2" ]] || { echo "Mininet hosts h1/h2 not found, see $D/switch.log"; exit 1; }
    in1() { sudo nsenter -t "$H1" -n "$@"; }

    sudo nsenter -t "$H2" -n tcpdump -i eth0 -Q in -s 96 -Z root -w "$D/h2.pcap" ip 2>/dev/null &
    cd "$D"
    PYTHONUNBUFFERED=1 "$PY" "$ROOT/control-plane/lucid_cnn.py" --predict_live localhost:22222 --model "$MODEL" \
        --dataset_type "$DATASET_TYPE" -r 14 -si p4ddle --mitigate "$mitigate" --min_flows "$min_flows" --protect "$PROTECT" > predictor.log 2>&1 &
    PRED=$!
    for _ in $(seq 60); do grep -q "Prediction on network traffic" predictor.log && break; sleep 1; done
    sleep 8; kill -0 "$PRED" || { echo "predictor died, see $D/predictor.log"; exit 1; }

    in1 tcpreplay -q -i eth0 --pps "$BENIGN_PPS" "$OUT/benign.pcap" > benign.log 2>&1 & B=$!
    sleep "$WARMUP"
    T0=$(date +%s.%N)
    in1 tcpreplay -q -i eth0 --pps "$ATTACK_PPS" "$OUT/attack.pcap" > attack.log 2>&1 || true
    wait "$B" || true
    sleep 5
    kill -TERM "$PRED" 2>/dev/null || true; wait "$PRED" 2>/dev/null || true; PRED=""
    sudo pkill -x tcpdump || true; sleep 1
    cd "$OUT"

    ao=$(count attack.pcap "$ATT"); ar=$(count "$D/h2.pcap" "$ATT")
    bo=$(count benign.pcap "$BEN"); br=$(count "$D/h2.pcap" "$BEN")
    # rules installed, time to the first rule against the attacker, and the attack types
    # predicted over the whole run (log/classes-*.csv, multi-class models only)
    "$PY" - "$D" "$T0" "$ATTACKER" "$mode" "$ao" "$ar" "$bo" "$br" <<'PYEOF' | tee -a summary.csv
import csv, glob, sys
d, t0, attacker, mode = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
ao, ar, bo, br = (int(x) for x in sys.argv[5:9])
rules, first = 0, '-'
for path in glob.glob(d + '/log/mitigation-*.csv'):
    for row in csv.DictReader(open(path)):
        if row['event'] == 'block':
            rules += 1
            if first == '-' and float(row['time']) > t0 and attacker in row['rule']:
                first = '%.2f' % (float(row['time']) - t0)
types = '-'
for path in glob.glob(d + '/log/classes-*.csv'):
    rows = list(csv.reader(open(path)))
    totals = {name: sum(int(r[i]) for r in rows[1:]) for i, name in enumerate(rows[0]) if i >= 2 and name != 'benign'}
    types = ' '.join('%s=%d' % kv for kv in totals.items())
print('%s,%d,%d,%.1f,%d,%d,%.1f,%d,%s,%s' % (mode, ao, ar, 100.0 * (ao - ar) / ao if ao else 0,
      bo, br, 100.0 * (bo - br) / bo if bo else 0, rules, first, types))
PYEOF
    cleanup; wait 2>/dev/null || true
done
echo; column -s, -t "$OUT/summary.csv"
