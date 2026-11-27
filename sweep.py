#!/usr/bin/env python3
"""
sweep.py — parameter sweep over p4ddle training configs and live replay scenarios.

Calls pipeline.sh for each (attack_dir, packets_per_flow, time_window) training
combination, then for each (model, attack_pcap, benign_pps) live combination.

Usage:
    sweep.py --config sweep.yaml [overrides...]

    sweep.py --config sweep.yaml --duration-min 3 --benign-pps 0,100,1000

Config file (YAML):
    duration_min: 6
    global_benign_pcap: ~/data/benign.pcap   # optional
    benign_pps: [0, 100, 1000]

    training:
      packets_per_flow: [4, 8]
      time_window: [2, 4]

    attack_dirs:
      - path: ~/data/dns/
        dataset_type: DOS2019
        benign_pcap: ~/data/dns/benign.pcap   # optional if global set
      - path: ~/data/syn/
        dataset_type: DOS2019

CLI flags override the corresponding config keys. benign_pps, packets_per_flow,
and time_window accept comma-separated lists on the CLI (e.g. --benign-pps 0,100).

benign_pps=0 means attack-only replay (no benign process started).
"""

import argparse
import glob
import os
import subprocess
import sys
import time
from itertools import product
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not found. Install with: pip install pyyaml --break-system-packages", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config loading + CLI override
# ---------------------------------------------------------------------------

def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}


def parse_int_list(value):
    """Parse '0,100,1000' or [0, 100, 1000] into a list of ints."""
    if isinstance(value, list):
        return [int(x) for x in value]
    return [int(x.strip()) for x in str(value).split(",")]


def resolve_config(config, args):
    """Merge CLI args into config. CLI wins over config."""

    def cli(attr):
        return getattr(args, attr, None)

    if cli("duration_min") is not None:
        config["duration_min"] = args.duration_min
    if cli("global_benign_pcap") is not None:
        config["global_benign_pcap"] = args.global_benign_pcap
    if cli("benign_pps") is not None:
        config["benign_pps"] = parse_int_list(args.benign_pps)
    if cli("packets_per_flow") is not None:
        config.setdefault("training", {})["packets_per_flow"] = parse_int_list(args.packets_per_flow)
    if cli("time_window") is not None:
        config.setdefault("training", {})["time_window"] = parse_int_list(args.time_window)
    if cli("pipeline") is not None:
        config["pipeline"] = args.pipeline
    if cli("force"):
        config["force"] = True
    if cli("skip_training"):
        config["skip_training"] = True

    return config


def validate_config(config):
    errors = []

    if "duration_min" not in config:
        errors.append("duration_min is required")
    if "benign_pps" not in config:
        errors.append("benign_pps is required (use [0] for attack-only)")
    if "attack_dirs" not in config or not config["attack_dirs"]:
        errors.append("attack_dirs must be a non-empty list")

    training = config.get("training", {})
    if "packets_per_flow" not in training:
        errors.append("training.packets_per_flow is required")
    if "time_window" not in training:
        errors.append("training.time_window is required")

    if errors:
        for e in errors:
            print(f"  Config error: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def expand(path):
    return str(Path(path).expanduser().resolve())


def model_name(attack_dir_path, ppf, tw):
    """Generate a stable run name from dir + training params."""
    stem = Path(attack_dir_path).name
    # sanitise: keep alphanumeric + underscore
    stem = "".join(c if c.isalnum() or c == "_" else "_" for c in stem)
    return f"{stem}_p{ppf}_tw{tw}"


def find_attack_pcaps(folder, benign_pcap):
    """Return all .pcap files in folder that are not the benign pcap."""
    all_pcaps = sorted(glob.glob(os.path.join(folder, "*.pcap")))
    benign_resolved = str(Path(benign_pcap).resolve()) if benign_pcap else None
    result = []
    for p in all_pcaps:
        if benign_resolved and str(Path(p).resolve()) == benign_resolved:
            continue
        result.append(p)
    return result


def run(cmd, dry_run=False):
    """Run a shell command, streaming output. Returns exit code."""
    print(f"\n>>> {' '.join(cmd)}")
    if dry_run:
        print("    [dry-run, skipping]")
        return 0
    result = subprocess.run(cmd)
    return result.returncode


def separator(title):
    width = 72
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


# ---------------------------------------------------------------------------
# Main sweep logic
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parameter sweep over p4ddle training + live replay combinations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", required=True, help="Path to sweep YAML config file")
    parser.add_argument("--duration-min", type=int, help="Override: replay duration in minutes")
    parser.add_argument("--global-benign-pcap", help="Override: global benign pcap path")
    parser.add_argument("--benign-pps", help="Override: comma-separated benign pps values (0=attack-only)")
    parser.add_argument("--packets-per-flow", help="Override: comma-separated packets-per-flow values")
    parser.add_argument("--time-window", help="Override: comma-separated time-window values")
    parser.add_argument("--pipeline", default="pipeline.sh", help="Path to pipeline.sh (default: pipeline.sh)")
    parser.add_argument("--force", action="store_true", help="Pass --force to pipeline.sh for all runs")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    parser.add_argument("--skip-training", action="store_true", help="Skip offline training phase (models must exist)")
    parser.add_argument("--skip-live", action="store_true", help="Skip live replay phase")
    args = parser.parse_args()

    # --- Load and resolve config ---
    config = load_config(args.config)
    config = resolve_config(config, args)
    validate_config(config)

    _pipeline_raw = config.get("pipeline", args.pipeline)
    if not os.path.isabs(_pipeline_raw) and not _pipeline_raw.startswith("~"):
        # resolve relative to the directory containing sweep.py
        _sweep_dir = Path(__file__).parent
        pipeline_sh = str((_sweep_dir / _pipeline_raw).resolve())
    else:
        pipeline_sh = expand(_pipeline_raw)
    duration_min  = int(config["duration_min"])
    benign_pps_list = parse_int_list(config["benign_pps"])
    global_benign = config.get("global_benign_pcap")
    if global_benign:
        global_benign = expand(global_benign)
    force         = config.get("force", False)
    skip_training = config.get("skip_training", False)
    dry_run       = args.dry_run

    ppf_list      = parse_int_list(config["training"]["packets_per_flow"])
    tw_list       = parse_int_list(config["training"]["time_window"])
    attack_dirs   = config["attack_dirs"]

    force_flag = ["--force"] if force else []

    # --- Summarise plan ---
    n_train = len(attack_dirs) * len(ppf_list) * len(tw_list)
    n_live  = sum(
        len(find_attack_pcaps(
            expand(d["path"]),
            global_benign or (expand(d["benign_pcap"]) if d.get("benign_pcap") else None)
        )) for d in attack_dirs
    ) * len(ppf_list) * len(tw_list) * len(benign_pps_list)

    print(f"Sweep plan:")
    print(f"  Attack dirs:       {len(attack_dirs)}")
    print(f"  packets_per_flow:  {ppf_list}")
    print(f"  time_window:       {tw_list}")
    print(f"  benign_pps:        {benign_pps_list}")
    print(f"  duration_min:      {duration_min}")
    print(f"  Training runs:     {n_train}")
    print(f"  Live runs:         {n_live}")
    est_minutes = n_live * duration_min
    print(f"  Est. live time:    ~{est_minutes} min ({est_minutes/60:.1f} h), sequential")
    if dry_run:
        print("  [DRY RUN — no commands will execute]")

    # --- Training phase ---
    if not (args.skip_training or skip_training):
        separator("TRAINING PHASE")
        for dir_cfg, ppf, tw in product(attack_dirs, ppf_list, tw_list):
            folder      = expand(dir_cfg["path"])
            ds_type     = dir_cfg["dataset_type"]
            name        = model_name(folder, ppf, tw)

            print(f"\n--- Train: {name}  (ppf={ppf}, tw={tw}, dir={folder})")
            cmd = [
                pipeline_sh,
                "--mode", "offline",
                "--pcaps", folder,
                "--name", name,
                "--dataset-type", ds_type,
                "--packets-per-flow", str(ppf),
                "--time-window", str(tw),
            ] + force_flag

            rc = run(cmd, dry_run)
            if rc == 2:
                print(f"  SKIP: model for {name} already exists.")
            elif rc != 0:
                print(f"  ERROR: training failed for {name} (exit {rc}). Skipping live runs for this model.", file=sys.stderr)
                dir_cfg.setdefault("_failed_models", set()).add((ppf, tw))

    # --- Live phase ---
    if not args.skip_live:
        separator("LIVE PHASE")

        stats = {"ok": 0, "skipped": 0, "error": 0}

        for dir_cfg, ppf, tw in product(attack_dirs, ppf_list, tw_list):
            folder   = expand(dir_cfg["path"])
            ds_type  = dir_cfg["dataset_type"]
            name     = model_name(folder, ppf, tw)

            if (ppf, tw) in dir_cfg.get("_failed_models", set()):
                print(f"\nSkipping live runs for {name} (training failed).")
                continue

            # Resolve benign pcap: global > per-dir > None
            if global_benign:
                benign_pcap = global_benign
            elif dir_cfg.get("benign_pcap"):
                benign_pcap = expand(dir_cfg["benign_pcap"])
            else:
                benign_pcap = None

            attack_pcaps = find_attack_pcaps(folder, benign_pcap)
            if not attack_pcaps:
                print(f"\nWARNING: no attack pcaps found in {folder}, skipping.", file=sys.stderr)
                continue

            for attack_pcap, pps in product(attack_pcaps, benign_pps_list):
                attack_name = Path(attack_pcap).stem
                print(f"\n--- Live: model={name}  attack={attack_name}  pps={pps}")

                if benign_pcap is None and pps != 0:
                    print(f"  WARNING: no benign pcap for {folder} and pps={pps} requested. Skipping.")
                    stats["skipped"] += 1
                    continue

                cmd = [
                    pipeline_sh,
                    "--mode", "live",
                    "--pcaps", folder,
                    "--name", name,
                    "--dataset-type", ds_type,
                    "--replay-pcap", attack_pcap,
                    "--duration-min", str(duration_min),
                ]
                if pps != 0 and benign_pcap:
                    cmd += ["--benign-pcap", benign_pcap, "--benign-pps", str(pps)]
                cmd += force_flag

                rc = run(cmd, dry_run)
                if rc == 0:
                    stats["ok"] += 1
                elif rc == 2:
                    print(f"  SKIP: results already exist for {attack_name} / b{pps}pps.")
                    stats["skipped"] += 1
                else:
                    print(f"  ERROR: live run failed (exit {rc}).", file=sys.stderr)
                    stats["error"] += 1

                # Brief pause between runs to let BMv2 fully release
                if not dry_run:
                    time.sleep(5)

        separator("SWEEP COMPLETE")
        print(f"  Live runs — ok: {stats['ok']}  skipped: {stats['skipped']}  errors: {stats['error']}")

        # Print aggregate table per attack dir
        print()
        for dir_cfg in attack_dirs:
            folder = expand(dir_cfg["path"])
            for ppf, tw in product(ppf_list, tw_list):
                name = model_name(folder, ppf, tw)
                results_dir = os.path.join(folder, "results", name)
                if os.path.isdir(results_dir):
                    print(f"\n{'='*60}")
                    print(f"  Results: {name}")
                    print(f"{'='*60}")
                    subprocess.run([sys.executable, "aggregate_results.py", results_dir])


if __name__ == "__main__":
    main()
