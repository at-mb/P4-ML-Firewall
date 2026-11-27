#!/usr/bin/env python3
"""
Aggregate p4ddle live predictions into a comparison table.

Each row is one live run (one replay pcap). Columns include the training
context (dataset name, training set size) so you can see what model was
used and how it performs across attack types.

Usage:
    aggregate_results.py <results_dir>

Where <results_dir> is a directory like:
    sample-dataset/results/<name>/
      predictions-*.csv               (offline result — used for "Offline F1" column)
      live/
        predictions-*_<pcap>.csv      (live results — one row per file in the table)

The training set size is read from <pcap_folder>/preprocessed/<name>/history.log
if available (the folder is inferred from sibling layout).
"""

import csv
import glob
import os
import re
import sys
from pathlib import Path


WARMUP_ROUNDS = 3  # for "Steady F1" metric


def parse_csv(path):
    """Read a predictions CSV. Returns list of dicts.

    Handles the upstream cosmetic bug where the live-mode header is missing
    a comma between 'total_packet_captured' and 'ignored_packets'.
    """
    rows = []
    with open(path) as f:
        lines = f.readlines()
    if not lines:
        return []

    header_line = lines[0].strip().replace(
        "total_packet_capturedignored_packets",
        "total_packet_captured,ignored_packets",
    )
    header = [h.strip() for h in header_line.split(",")]

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        values = [v.strip() for v in line.split(",")]
        if len(values) != len(header):
            continue
        rows.append(dict(zip(header, values)))
    return rows


def compute_metrics(rows):
    """Return (tp, fp, tn, fn, acc, precision, recall, f1) summed across rows."""
    if not rows:
        return None
    tp = sum(int(r["TP"]) for r in rows)
    fp = sum(int(r["FP"]) for r in rows)
    tn = sum(int(r["TN"]) for r in rows)
    fn = sum(int(r["FN"]) for r in rows)
    total = tp + fp + tn + fn
    if total == 0:
        return None
    acc = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return tp, fp, tn, fn, acc, precision, recall, f1


def extract_dataset_name(data_source):
    """From '<path>/2t-4n-<id>-dataset-p4-test.hdf5' extract '<id>'."""
    if not data_source:
        return ""
    stem = Path(data_source).stem
    if "-dataset-" in stem:
        prefix = stem.split("-dataset-")[0]
        parts = prefix.split("-", 2)
        if len(parts) >= 3:
            return parts[2]
    return stem


def read_offline_metrics(results_dir):
    """Find the offline predictions CSV at the root of results_dir.

    Returns (dataset_name, offline_f1) or (None, None) if not found.
    """
    for path in sorted(glob.glob(os.path.join(results_dir, "predictions-*.csv"))):
        rows = parse_csv(path)
        if not rows or "round_counter" in rows[0]:
            continue  # skip live-format files
        metrics = compute_metrics(rows)
        if metrics is None:
            continue
        _, _, _, _, _, _, _, f1 = metrics
        ds = extract_dataset_name(rows[0].get("Data Source", ""))
        return ds, f1
    return None, None


def read_training_size(results_dir, dataset_name):
    """Try to find the training set size from history.log.

    Looks for <pcap_folder>/preprocessed/<dataset_name>/history.log, where
    <pcap_folder> is inferred from the results_dir layout:
        <pcap_folder>/results/<dataset_name>/
                     /preprocessed/<dataset_name>/history.log

    Returns the training size as an int, or None.
    """
    if not dataset_name:
        return None
    # results_dir is e.g. .../sample-dataset/results/<name>
    pcap_folder = Path(results_dir).parent.parent
    history = pcap_folder / "preprocessed" / dataset_name / "history.log"
    if not history.exists():
        return None
    try:
        with open(history) as f:
            text = f.read()
    except OSError:
        return None
    # Match "Train/Val/Test sizes: (TRAIN,VAL,TEST)" — pick last (most recent)
    matches = re.findall(r"Train/Val/Test sizes:\s*\((\d+),(\d+),(\d+)\)", text)
    if matches:
        return int(matches[-1][0])
    return None


def read_pcaps_used_in_training(results_dir):
    """List the .pcap basenames present in the pcap folder."""
    pcap_folder = Path(results_dir).parent.parent
    return sorted(p.name for p in pcap_folder.glob("*.pcap"))


def aggregate_live(path):
    rows = parse_csv(path)
    if not rows:
        return None
    metrics_all = compute_metrics(rows)
    if metrics_all is None:
        return None
    tp, fp, tn, fn, acc, precision, recall, f1 = metrics_all

    samples = sum(int(r["SAMPLES"]) for r in rows)
    packets_seen = sum(int(r["total_packet_captured"]) for r in rows)
    ignored = sum(int(r["ignored_packets"]) for r in rows)
    saturation = ignored / packets_seen if packets_seen > 0 else 0.0

    steady = None
    if len(rows) > WARMUP_ROUNDS:
        m = compute_metrics(rows[WARMUP_ROUNDS:])
        if m is not None:
            steady = m[7]

    # Extract pcap names from filename.
    # Pattern: predictions-DATE-TIME_live_traffic_BITS_<attack>_b<N>pps
    # or legacy: predictions-DATE-TIME_live_traffic_BITS_<attack>
    stem = Path(path).stem
    parts = stem.split("_")
    suffix = "_".join(parts[4:]) if len(parts) >= 5 else "(live)"
    m = re.match(r"^(.+)_(b\d+pps)$", suffix)
    if m:
        attack_label = m.group(1)
        benign_label = m.group(2)
    else:
        attack_label = suffix
        benign_label = None

    return {
        "attack": attack_label,
        "benign": benign_label,
        "rows": len(rows),
        "samples": samples,
        "packets_seen": packets_seen,
        "saturation": saturation,
        "fp": fp,
        "acc": acc,
        "f1": f1,
        "steady_f1": steady,
    }


def print_table(results_dir, live_results, dataset_name, training_size, offline_f1, pcaps_in_training):
    if not live_results:
        print("No live results found.")
        return

    def fmt_pct(x):
        return f"{x * 100:5.1f}%" if x is not None else "-"

    def fmt_f(x):
        return f"{x:.4f}" if x is not None else "-"

    def fmt_int(x):
        return f"{x:,}" if x is not None else "-"

    ds_label = dataset_name or "?"
    ts_label = fmt_int(training_size)
    off_label = fmt_f(offline_f1)

    rows_out = [
        (
            r["attack"][:25],
            r["benign"] or "-",
            ds_label,
            ts_label,
            off_label,
            f"{r['rows']:>4}",
            fmt_int(r["samples"]),
            fmt_int(r["packets_seen"]),
            fmt_pct(r["saturation"]),
            fmt_int(r["fp"]),
            fmt_f(r["acc"]),
            fmt_f(r["f1"]),
            fmt_f(r["steady_f1"]),
        )
        for r in live_results
    ]

    header = (
        "Attack pcap",
        "Benign",
        "Trained as",
        "Train size",
        "Offline F1",
        "Rows",
        "Samples",
        "Pkts seen",
        "Sat%",
        "FP",
        "Acc",
        "F1",
        "Steady F1",
    )

    cols = list(zip(header, *rows_out))
    widths = [max(len(str(x)) for x in col) for col in cols]

    def line(items):
        return "  ".join(str(s).ljust(w) for s, w in zip(items, widths))

    print(line(header))
    print("  ".join("-" * w for w in widths))
    for row in rows_out:
        print(line(row))

    print()
    print(f"  Trained as: identifier of the training run (--name)")
    print(f"  Train size: number of training samples after class balancing")
    print(f"  Offline F1: F1 on held-out test split (no data plane)")
    print(f"  Sat% = ignored_packets / total_packet_captured")
    print(f"  Steady F1 = F1 over rounds {WARMUP_ROUNDS + 1}+ (excludes warm-up)")

    if pcaps_in_training:
        print()
        print(f"  Pcap files present in source folder (all contributed to training):")
        for p in pcaps_in_training:
            print(f"    - {p}")


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    results_dir = sys.argv[1]
    if not os.path.isdir(results_dir):
        print(f"Not a directory: {results_dir}", file=sys.stderr)
        sys.exit(1)

    dataset_name, offline_f1 = read_offline_metrics(results_dir)
    training_size = read_training_size(results_dir, dataset_name)
    pcaps = read_pcaps_used_in_training(results_dir)

    live_paths = sorted(glob.glob(os.path.join(results_dir, "live", "predictions-*.csv")))
    live_results = [r for r in (aggregate_live(p) for p in live_paths) if r]

    print_table(results_dir, live_results, dataset_name, training_size, offline_f1, pcaps)


if __name__ == "__main__":
    main()
