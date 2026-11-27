#!/usr/bin/env bash
# pipeline.sh — run the p4ddle preprocess+train+test cycle on a pcap folder.
#
#   --mode offline (default): pcaps → preprocessed/<name>/ → models/<name>/ → results/<name>/
#   --mode live:               replays a pcap through BMv2 and runs live prediction
#                              (requires a prior --mode offline run with the same --name)
#
# Set P4DDLE_ROOT if your p4ddle checkout is not at $HOME/p4ddle/p4-ddos.
# Requires apply_patches.sh to have been run.

set -euo pipefail

# === Configuration ===

DEFAULT_PPF=4
DEFAULT_TW=2
P4DDLE_ROOT="${P4DDLE_ROOT:-$HOME/p4ddle/p4-ddos}"

print_usage() {
    cat <<EOF
Usage:
  pipeline.sh --mode offline --pcaps <folder> --name <name> --dataset-type <type>
                             [--packets-per-flow N] [--time-window T] [--force]

  pipeline.sh --mode live    --pcaps <folder> --name <name> --dataset-type <type>
                             --replay-pcap <path> --duration-min N
                             --benign-pcap <path> [--benign-pps N] [--force]

Required (both modes):
  --mode {offline,live}    Pipeline mode (default: offline).
  --pcaps <folder>         Folder containing .pcap files.
  --name <name>            Run name (alphanumeric + underscore only).
  --dataset-type <type>    Key in DDOS_ATTACK_SPECS (lucid_dataset_parser.py).

Offline-only (optional):
  --packets-per-flow N     Max packets per flow (default: $DEFAULT_PPF).
  --time-window T          Time window in seconds (default: $DEFAULT_TW).

Live-only (required):
  --replay-pcap <path>     Path to a single pcap to replay through BMv2.
  --duration-min N         Replay duration in minutes (yes — minutes, not seconds).
  --benign-pcap <path>     Path to benign pcap for mixed replay. If omitted,
                           replay is attack-only (no benign process started).
  --benign-pps N           Packets/sec rate for benign replay. Required when
                           --benign-pcap is provided.

Both modes:
  --force                  Re-run even if output already exists.
  -h, --help               Show this help.

Environment:
  P4DDLE_ROOT              Defaults to \$HOME/p4ddle/p4-ddos.
EOF
}

# === Parse flags ===

MODE="offline"
PCAPS=""; NAME=""; DATASET_TYPE=""
PPF=$DEFAULT_PPF; TW=$DEFAULT_TW; FORCE=0
REPLAY_PCAP=""; DURATION_MIN=""
BENIGN_PCAP=""; BENIGN_PPS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)             MODE="$2"; shift 2 ;;
        --pcaps)            PCAPS="$2"; shift 2 ;;
        --name)             NAME="$2"; shift 2 ;;
        --dataset-type)     DATASET_TYPE="$2"; shift 2 ;;
        --packets-per-flow) PPF="$2"; shift 2 ;;
        --time-window)      TW="$2"; shift 2 ;;
        --replay-pcap)      REPLAY_PCAP="$2"; shift 2 ;;
        --duration-min)     DURATION_MIN="$2"; shift 2 ;;
        --benign-pcap)      BENIGN_PCAP="$2"; shift 2 ;;
        --benign-pps)       BENIGN_PPS="$2"; shift 2 ;;
        --force)            FORCE=1; shift ;;
        -h|--help)          print_usage; exit 0 ;;
        *) echo "Unknown flag: $1" >&2; print_usage >&2; exit 1 ;;
    esac
done

# === Common validation (both modes) ===

if [[ "$MODE" != "offline" && "$MODE" != "live" ]]; then
    echo "--mode must be 'offline' or 'live'" >&2; exit 1
fi

if [[ -z "$PCAPS" || -z "$NAME" || -z "$DATASET_TYPE" ]]; then
    echo "Missing required flag(s)." >&2; print_usage >&2; exit 1
fi

if [[ ! -d "$PCAPS" ]]; then
    echo "Pcap folder not found: $PCAPS" >&2; exit 1
fi
shopt -s nullglob
pcap_files=("$PCAPS"/*.pcap)
shopt -u nullglob
if [[ ${#pcap_files[@]} -eq 0 ]]; then
    echo "No .pcap files in $PCAPS" >&2; exit 1
fi

if [[ ! "$NAME" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Invalid name: '$NAME'. Use alphanumeric + underscore only." >&2; exit 1
fi

SPECS_FILE="$P4DDLE_ROOT/control-plane/lucid_dataset_parser.py"
if [[ ! -f "$SPECS_FILE" ]]; then
    echo "P4DDLE_ROOT does not point at a valid p4-ddos directory: $P4DDLE_ROOT" >&2; exit 1
fi

if ! grep -qE "'$DATASET_TYPE'(\s*:|\s*\])" "$SPECS_FILE"; then
    echo "dataset_type '$DATASET_TYPE' not found in DDOS_ATTACK_SPECS in $SPECS_FILE." >&2
    echo "Add an entry near line 55 of that file, e.g.:" >&2
    echo "  ${DATASET_TYPE}_FLOWS = {'attackers': ['1.2.3.4'], 'victims': ['5.6.7.8']}" >&2
    echo "  DDOS_ATTACK_SPECS['$DATASET_TYPE'] = ${DATASET_TYPE}_FLOWS" >&2
    exit 1
fi

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    echo "Python venv is not active. Run: source ~/p4ddle-venv/bin/activate" >&2; exit 1
fi

# === Mode-specific validation ===

if [[ "$MODE" == "live" ]]; then
    [[ -z "$REPLAY_PCAP" ]]   && { echo "Live mode requires --replay-pcap" >&2; exit 1; }
    [[ -z "$DURATION_MIN" ]]  && { echo "Live mode requires --duration-min" >&2; exit 1; }
    [[ ! -f "$REPLAY_PCAP" ]] && { echo "Replay pcap not found: $REPLAY_PCAP" >&2; exit 1; }
    if [[ ! "$DURATION_MIN" =~ ^[1-9][0-9]*$ ]]; then
        echo "--duration-min must be a positive integer (in minutes)" >&2; exit 1
    fi
    if [[ -n "$BENIGN_PCAP" ]]; then
        [[ ! -f "$BENIGN_PCAP" ]] && { echo "Benign pcap not found: $BENIGN_PCAP" >&2; exit 1; }
        if [[ -z "$BENIGN_PPS" ]]; then
            echo "--benign-pps is required when --benign-pcap is provided" >&2; exit 1
        fi
        if [[ ! "$BENIGN_PPS" =~ ^[1-9][0-9]*$ ]]; then
            echo "--benign-pps must be a positive integer" >&2; exit 1
        fi
    fi
fi

# === Path setup ===

PREPROCESSED_DIR="$PCAPS/preprocessed/$NAME"
MODELS_DIR="$PCAPS/models/$NAME"
RESULTS_DIR="$PCAPS/results/$NAME"
LIVE_RESULTS_DIR="$RESULTS_DIR/live"

# === Mode dispatch ===

run_offline() {
    # Idempotency: skip if a trained model already exists for this name.
    # We check the model file rather than the directory because a crashed
    # run may have left empty directories behind.
    local existing_model
    existing_model=$(ls "$MODELS_DIR"/*-LUCID*.h5 2>/dev/null | head -n1 || true)
    if [[ -n "$existing_model" && $FORCE -eq 0 ]]; then
        echo "Model for '$NAME' already exists: $existing_model" >&2
        echo "Use --force to re-train, or pick a different --name." >&2
        exit 2
    fi
    mkdir -p "$PREPROCESSED_DIR" "$MODELS_DIR" "$RESULTS_DIR"

    # === Phase 1: preprocess pcaps to .data ===
    echo "[1/4] Preprocessing pcaps..."
    python3 "$P4DDLE_ROOT/control-plane/lucid_dataset_parser.py" \
        --dataset_type "$DATASET_TYPE" \
        --dataset_folder "$PCAPS" \
        --output_folder "$PREPROCESSED_DIR" \
        --dataset_id "$NAME" \
        --packets_per_flow "$PPF" \
        --time_window "$TW" \
        --traffic_type all \
        --p4_compatible

    # Sanity check: both classes present
    local HISTORY_LOG="$PREPROCESSED_DIR/history.log"
    if [[ ! -f "$HISTORY_LOG" ]]; then
        echo "Sanity check failed: $HISTORY_LOG was not created by phase 1." >&2; exit 1
    fi
    local last_line counts ben ddos
    last_line=$(tail -n1 "$HISTORY_LOG")
    counts=$(echo "$last_line" | grep -oP 'flows \(tot,ben,ddos\):\(\K[0-9]+,[0-9]+,[0-9]+')
    if [[ -z "$counts" ]]; then
        echo "Sanity check failed: could not parse flow counts from history.log." >&2
        echo "Last line: $last_line" >&2; exit 1
    fi
    ben=$(echo "$counts" | cut -d, -f2)
    ddos=$(echo "$counts" | cut -d, -f3)
    echo "  → flows: ben=$ben ddos=$ddos"
    if [[ "$ben" == "0" || "$ddos" == "0" ]]; then
        echo "Sanity check FAILED: class counts ben=$ben ddos=$ddos." >&2
        echo "Verify that attackers/victims for '$DATASET_TYPE' actually appear in the pcaps." >&2
        exit 1
    fi

    # === Phase 2: consolidate to HDF5 ===
    echo "[2/4] Consolidating to HDF5..."
    python3 "$P4DDLE_ROOT/control-plane/lucid_dataset_parser.py" \
        --preprocess_folder "$PREPROCESSED_DIR" \
        --output_folder "$PREPROCESSED_DIR"

    # === Phase 3: train ===
    echo "[3/4] Training..."
    python3 "$P4DDLE_ROOT/control-plane/lucid_cnn.py" --train "$PREPROCESSED_DIR"

    # Move model + history CSV out of preprocessed/ into models/
    mv -f "$PREPROCESSED_DIR"/*-LUCID*.h5 "$MODELS_DIR/"
    mv -f "$PREPROCESSED_DIR"/*-LUCID*.csv "$MODELS_DIR/" 2>/dev/null || true

    # === Phase 4: offline predict ===
    echo "[4/4] Testing offline..."
    local model_file
    model_file=$(ls "$MODELS_DIR"/*-LUCID*.h5 2>/dev/null | head -n1 || true)
    if [[ -z "$model_file" || ! -f "$model_file" ]]; then
        echo "No trained model found in $MODELS_DIR" >&2; exit 1
    fi

    pushd "$RESULTS_DIR" >/dev/null
    python3 "$P4DDLE_ROOT/control-plane/lucid_cnn.py" \
        --predict "$PREPROCESSED_DIR" \
        --model "$model_file"
    if [[ -d log ]]; then
        mv -f log/predictions-*.csv . 2>/dev/null || true
        rmdir log 2>/dev/null || true
    fi
    popd >/dev/null

    echo ""
    echo "Run '$NAME' (offline) complete."
    echo "  Preprocessed: $PREPROCESSED_DIR"
    echo "  Model:        $MODELS_DIR"
    echo "  Results:      $RESULTS_DIR"
    echo ""
    echo "Final metrics row(s):"
    tail -n+1 "$RESULTS_DIR"/predictions-*.csv 2>/dev/null || echo "  (no results CSV found)"
}

run_live() {
    # Live mode requires a prior offline run (we need the trained model)
    local model_file
    model_file=$(ls "$MODELS_DIR"/*-LUCID*.h5 2>/dev/null | head -n1 || true)
    if [[ -z "$model_file" || ! -f "$model_file" ]]; then
        echo "No trained model found in $MODELS_DIR" >&2
        echo "Run with --mode offline --name $NAME first." >&2
        exit 1
    fi

    # Idempotency: refuse if a results CSV for THIS replay+benign combo already exists
    local replay_basename benign_suffix run_suffix
    replay_basename=$(basename "$REPLAY_PCAP" .pcap)
    if [[ -n "$BENIGN_PCAP" ]]; then
        benign_suffix="b${BENIGN_PPS}pps"
    else
        benign_suffix="attack_only"
    fi
    run_suffix="${replay_basename}_${benign_suffix}"
    if [[ $FORCE -eq 0 ]] && ls "$LIVE_RESULTS_DIR"/predictions-*"_${run_suffix}.csv" >/dev/null 2>&1; then
        echo "Live results for '${run_suffix}' already exist in $LIVE_RESULTS_DIR" >&2
        echo "Use --force to re-run." >&2
        exit 2
    fi
    mkdir -p "$LIVE_RESULTS_DIR"

    # === Step 1: compile P4 if needed ===
    echo "[1/4] Compiling P4 (if needed)..."
    local P4_DIR="$P4DDLE_ROOT/data-plane/p4ddle"
    local P4_JSON="$P4_DIR/p4_bloom_management.json"
    if [[ ! -f "$P4_JSON" || $FORCE -eq 1 ]]; then
        (cd "$P4_DIR" && p4c --target bmv2 --arch v1model --std p4-16 p4_bloom_management.p4)
        echo "  → compiled $P4_JSON"
    else
        echo "  → using existing $P4_JSON"
    fi

    # === Cleanup hook (runs on any exit) ===
    cleanup() {
        echo ""
        echo "Cleaning up subprocess and Mininet state..."
        sudo pkill -f "launcher.py --behavioral-exe simple_switch" 2>/dev/null || true
        sudo pkill -f "traffic_generator.py"                      2>/dev/null || true
        sudo pkill -f "simple_switch"                             2>/dev/null || true
        sudo mn -c                                                2>/dev/null || true
    }
    trap cleanup EXIT INT TERM

    # === Step 2: pre-cleanup of any stale Mininet state ===
    echo "[2/4] Pre-run Mininet cleanup..."
    sudo mn -c 2>/dev/null || true

    # === Step 3: launch switch in background ===
    # The `< <(tail -f /dev/null)` keeps Mininet's CLI from getting EOF on
    # stdin. Without it, the backgrounded process gets immediate EOF, CLI(net)
    # exits, net.stop() is called, and BMv2 is killed before the predictor
    # can connect.
    echo "[3/4] Launching switch..."
    local RUNNER_DIR="$P4DDLE_ROOT/data-plane/runner"
    (cd "$RUNNER_DIR" && sudo "$(which python3)" launcher.py \
        --behavioral-exe simple_switch \
        --json "$P4_JSON" \
        --cli simple_switch_CLI \
        < <(tail -f /dev/null) \
        > "$LIVE_RESULTS_DIR/switch.log" 2>&1) &

    # Wait for Thrift port 22222 (max 30s)
    echo "  → waiting for Thrift port 22222..."
    local waited=0
    while ! python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('localhost',22222))" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [[ $waited -ge 30 ]]; then
            echo "Timed out waiting for switch to start." >&2
            echo "See $LIVE_RESULTS_DIR/switch.log for details." >&2
            exit 1
        fi
    done
    echo "  → switch ready (allowing 2s for stabilization)"
    sleep 2

    # === Step 4: start traffic + run predictor ===
    echo "[4/4] Starting traffic + live prediction (${DURATION_MIN} min)..."
    local benign_args=()
    if [[ -n "$BENIGN_PCAP" ]]; then
        benign_args=("-b" "$BENIGN_PCAP" "-p" "$BENIGN_PPS")
    fi
    sudo "$(which python3)" "$P4DDLE_ROOT/helpers/traffic_generator.py" \
        -f "$REPLAY_PCAP" \
        -i s1-eth2 \
        -d "$DURATION_MIN" \
        "${benign_args[@]}" \
        > "$LIVE_RESULTS_DIR/traffic.log" 2>&1 &

    # Run predictor in foreground, bounded by timeout.
    # Predictor is an infinite loop; cap at duration + 30s buffer.
    local TIMEOUT_SEC=$((DURATION_MIN * 60 + 30))
    pushd "$LIVE_RESULTS_DIR" >/dev/null
    timeout --preserve-status "$TIMEOUT_SEC" python3 \
        "$P4DDLE_ROOT/control-plane/lucid_cnn.py" \
        --predict_live localhost:22222 \
        --model "$model_file" \
        --dataset_type "$DATASET_TYPE" \
        -r 14 -si p4ddle || true

    # Flatten log/ up one level and tag CSVs with the run suffix
    if [[ -d log ]]; then
        for f in log/predictions-*.csv; do
            [[ -f "$f" ]] || continue
            local newname
            newname="$(basename "${f%.csv}")_${run_suffix}.csv"
            mv -f "$f" "./$newname"
        done
        rmdir log 2>/dev/null || true
    fi
    popd >/dev/null

    # cleanup() runs automatically via trap

    echo ""
    echo "Run '$NAME' (live) complete."
    echo "  Live results: $LIVE_RESULTS_DIR"
    echo "  Run suffix:   $run_suffix"
    echo ""
    echo "Last 3 prediction rows:"
    tail -n3 "$LIVE_RESULTS_DIR"/predictions-*"_${run_suffix}.csv" 2>/dev/null || echo "  (no results CSV found)"
}

if [[ "$MODE" == "offline" ]]; then
    run_offline
else
    run_live
fi
