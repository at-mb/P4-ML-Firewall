#!/usr/bin/env bash
# apply_patches.sh — apply all known upstream fixes to p4ddle so the
# pipeline works end-to-end in both offline and live modes.
#
# Idempotent: safe to run multiple times. Each patch checks whether it's
# already applied before doing anything.
#
# Set P4DDLE_ROOT if your p4ddle checkout is not at $HOME/p4ddle/p4-ddos.

set -euo pipefail

P4DDLE_ROOT="${P4DDLE_ROOT:-$HOME/p4ddle/p4-ddos}"
LAUNCHER="$P4DDLE_ROOT/data-plane/runner/launcher.py"
LUCID="$P4DDLE_ROOT/control-plane/lucid_cnn.py"

# === Sanity checks ===

for f in "$LAUNCHER" "$LUCID"; do
    if [[ ! -f "$f" ]]; then
        echo "File not found: $f" >&2
        echo "(Set P4DDLE_ROOT if your p4ddle checkout is elsewhere.)" >&2
        exit 1
    fi
done

echo "Applying patches to p4ddle in: $P4DDLE_ROOT"
echo ""

# === Patch A: disable verbose BMv2 console logging in launcher.py ===

if grep -qE "log_console\s*=\s*False" "$LAUNCHER"; then
    echo "  -  A: already applied (log_console = False)"
elif grep -qE "log_console\s*=\s*True" "$LAUNCHER"; then
    sed -i 's/log_console *= *True/log_console = False/' "$LAUNCHER"
    echo "  ✓  A: disabled log_console in launcher.py"
else
    echo "  !  A: could not find log_console line; manual check needed" >&2
fi

# === Patch B: capture ignored_packets in the UNPACKING line ===
# process_live_traffic returns 9 values in p4ddle mode but the caller used to
# unpack 8. We anchor on "= \" at end of line to target only the unpacking line
# (line ~475), not the report_results call site (line ~501) which shares the
# substring "total_packet_captured_in_round, round_time, round_counter".

if grep -qE "total_packet_captured_in_round, *ignored_packets, *round_time, *round_counter *=" "$LUCID"; then
    echo "  -  B: already applied (ignored_packets captured in unpacking)"
elif grep -qE "total_packet_captured_in_round, *_, *round_time, *round_counter *=" "$LUCID"; then
    sed -i 's/total_packet_captured_in_round, *_, *round_time, *round_counter *=/total_packet_captured_in_round, ignored_packets, round_time, round_counter =/' "$LUCID"
    echo "  ✓  B: upgraded _ to ignored_packets in the unpacking line"
elif grep -qE "total_packet_captured_in_round, *round_time, *round_counter *=" "$LUCID"; then
    sed -i 's/total_packet_captured_in_round, *round_time, *round_counter *=/total_packet_captured_in_round, ignored_packets, round_time, round_counter =/' "$LUCID"
    echo "  ✓  B: applied unpacking fix (capturing ignored_packets)"
else
    echo "  !  B: could not find unpacking line; manual check needed" >&2
fi

# === Patch C: convert switch_impl to keyword arg in the report_results CALL ===
# We anchor on `packet_writer, args.switch_impl)` (closing paren) to target ONLY
# the report_results call. The process_live_traffic call nearby legitimately has
# `switch_impl=args.switch_impl,` but with a comma (not paren) after.

if grep -qE "switch_impl=args\.switch_impl\)" "$LUCID"; then
    echo "  -  C: already applied (switch_impl is keyword in report_results call)"
elif grep -qE "packet_writer, *args\.switch_impl\)" "$LUCID"; then
    sed -i 's/packet_writer, *args\.switch_impl)/packet_writer, switch_impl=args.switch_impl)/' "$LUCID"
    echo "  ✓  C: switch_impl converted to keyword arg in report_results call"
else
    echo "  !  C: could not find report_results call site; manual check needed" >&2
fi

# === Patch D: pass ignored_packets to report_results ===
# Insert "ignored_packets=ignored_packets," just before "switch_impl=args.switch_impl)".
# We anchor on the closing paren to avoid touching the process_live_traffic call
# (where switch_impl=args.switch_impl is followed by a comma, not a paren).

if grep -qE "ignored_packets=ignored_packets, *switch_impl=args\.switch_impl\)" "$LUCID"; then
    echo "  -  D: already applied (ignored_packets passed to report_results)"
elif grep -qE ", *switch_impl=args\.switch_impl\)" "$LUCID"; then
    sed -i 's/, *switch_impl=args\.switch_impl)/, ignored_packets=ignored_packets, switch_impl=args.switch_impl)/' "$LUCID"
    echo "  ✓  D: ignored_packets passed to report_results"
else
    echo "  !  D: cannot proceed without Patch C applied first" >&2
fi

# === Patch E: add ignored_packets=0 to report_results signature ===

if grep -qE "packet_writer=0, *ignored_packets=0, *short_header=False" "$LUCID"; then
    echo "  -  E: already applied (ignored_packets in report_results signature)"
elif grep -qE "packet_writer=0, *short_header=False" "$LUCID"; then
    sed -i 's/packet_writer=0, *short_header=False/packet_writer=0, ignored_packets=0, short_header=False/' "$LUCID"
    echo "  ✓  E: ignored_packets added to report_results signature"
else
    echo "  !  E: could not find report_results signature; manual check needed" >&2
fi

# === Patch F: fix polling-loop timer bug ===
# In the live prediction loop, `last_collect_time = round_time` is currently
# nested inside `if len(samples) > 0:`. When a round produces no samples,
# the timer never updates and the loop sprints at full Python+Thrift speed,
# thrashing the data plane's block-swap mechanism. We add an unconditional
# timer update right after process_live_traffic returns (before the samples
# check), so the 2-second cadence is maintained even on empty rounds.

if grep -qE "^                    last_collect_time = round_time$" "$LUCID"; then
    echo "  -  F: already applied (unconditional timer update in place)"
elif grep -qE "^                    if len\(samples\) > 0:$" "$LUCID"; then
    sed -i 's/^                    if len(samples) > 0:$/                    last_collect_time = round_time\n                    if len(samples) > 0:/' "$LUCID"
    echo "  ✓  F: added unconditional timer update before sample check"
else
    echo "  !  F: could not find 'if len(samples) > 0:' line; manual check needed" >&2
fi

# === Syntax verification ===

echo ""
echo "Verifying Python syntax..."
if python3 -c "import ast; ast.parse(open('$LUCID').read())" 2>/dev/null; then
    echo "  ✓ lucid_cnn.py parses OK"
else
    echo "  ! lucid_cnn.py syntax error — review patches" >&2
    exit 1
fi
if python3 -c "import ast; ast.parse(open('$LAUNCHER').read())" 2>/dev/null; then
    echo "  ✓ launcher.py parses OK"
else
    echo "  ! launcher.py syntax error — review patches" >&2
    exit 1
fi

echo ""
echo "All patches applied. Pipeline ready for both offline and live mode."
echo ""
echo "Note: the traffic_generator -d flag is NOT patched — it takes minutes,"
echo "not seconds (intentional but counterintuitive). Use small values."
