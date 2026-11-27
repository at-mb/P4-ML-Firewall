# P4DDLe Reproduction — Handover

## Installation

Two files cover setup, both from a prior session:

- **`INSTALL.md`** — step-by-step guide to bring `daisyfbk/p4ddle` onto the P4-tutorials Ubuntu 24.04 VM. Key points: the VM ships Python 3.12 but LUCID needs Python 3.10 + TensorFlow 2.13, so it installs 3.10 via pyenv into a venv (`~/p4ddle-venv`), rebuilds BMv2's Python bindings against that venv, installs the Python stack (don't pin protobuf — let TF resolve it), and installs tshark/tcpreplay. Includes a network-troubleshooting appendix for the VM's flaky NAT. Note the `sudo $(which python3)` pattern for commands needing both root and the venv.
- **`apply_patches.sh`** — idempotent script applying six upstream fixes (A–F) to `launcher.py` and `lucid_cnn.py`. Most important is **Patch F** (polling-loop timer bug: the loop sprinted at ~5 iter/sec instead of 0.5/sec, thrashing the data-plane block-swap and crippling packet capture). Also documents that `traffic_generator.py`'s `-d` flag is in **minutes, not seconds** — not a bug, just counterintuitive. Run this once after cloning.

## The four experiment scripts

- **`pipeline.sh`** — the core driver. Two modes. **Offline**: `--pcaps <folder> --name <n> --dataset-type <type>` runs preprocess → consolidate → train → predict, producing a model under `<folder>/models/<name>/`. **Live**: reuses that model, starts BMv2, replays an attack pcap through the switch, and writes per-time-window predictions. Live supports mixed benign replay via `--benign-pcap`/`--benign-pps` (both required together; omit for attack-only). Idempotent — skips completed runs unless `--force`. Output filenames encode the replay pcap and benign rate so runs coexist.
- **`aggregate_results.py`** — reads a `results/<name>/` directory and prints one row per live run: attack pcap, benign rate, train size, offline F1, and online metrics (F1, Steady F1 excluding warm-up rounds, saturation %, FP). This is how you read results. **Run it from `p4ddle_experiments/` or with its full path** — if run from the wrong directory it errors "file not found," which is silent if stderr is suppressed.
- **`sweep.py`** + **`sweep.yaml`** — automates the full matrix: trains one model per `(folder × packets-per-flow × time-window)`, then runs live replay for each `(model × attack pcap × benign_pps)`. Config-driven via `sweep.yaml`, with CLI overrides. Idempotent/resumable. Run under **tmux** — it's a multi-hour job. Config has per-folder `attack_dirs` (path, dataset_type, benign_pcap) plus global `benign_pps`, `duration_min`, and the training grid.

## What went wrong, and how to continue

The failure was **data labelling**, and it's the critical thing to understand before trusting any CICIDS2017 result.

Labelling is IP-based via `DDOS_ATTACK_SPECS` in `lucid_dataset_parser.py`: flows matching an attacker→victim IP pair get label 1, all others label 0 — and it **fails silently** (everything labelled benign) if the IPs don't match. When that happens, ground-truth attack samples ≈ 0, so F1 is mechanically 0 even though the model and pipeline are fine. Watch for the signature: high accuracy + F1=0.0 + FN=0 means the attack was never labelled, not that detection failed.

Two specific pitfalls we hit with CICIDS2017:

1. **Post-NAT addressing.** The documented attacker (external Kali `205.174.165.73`) never appears in the captures — traffic is captured inside the NAT, so the attacker shows as the firewall interface `172.16.0.1` (or `192.168.10.8` for the port scan). We added `IDS2017` (`172.16.0.1 → 192.168.10.50`) and `IDS2017_PORTSCAN` (`192.168.10.8 → 192.168.10.0/24`) to `DDOS_ATTACK_SPECS`.

2. **Unreliable published attack times.** The UNB schedule times don't reconcile with the pcap timestamps (timezone offsets were inconsistent — FTP appeared at +5h, SSH at +3h). **Locate attacks by signature, not clock** — use per-minute SYN histograms in tcpdump filtered on the attacker IP and port to find the actual burst window, then slice with `editcap`.

The DDoS baseline (CIC-DDoS-2019 sample-dataset) works end-to-end with confirmed labelling and is the reliable reference — offline F1 ~0.96, online ~0.88–0.91.
