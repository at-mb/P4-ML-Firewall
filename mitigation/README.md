# P4DDLe extension: multi-class detection + mitigation

LUCID classifies every flow as **benign, DNS, SYN flood, UDPLag or WebDDoS**. The control plane then installs a drop rule in the switch, which discards later packets of the attack.

```
P4 switch (features, Bloom filter) --2 s--> LUCID CNN (5 classes) --> drop rule --> P4 switch drops
```

## Files

| File | Purpose |
|---|---|
| `mitigation.patch` | P4 drop tables, rule installation and expiry, Bloom filter reset, port 1 <-> 2 forwarding, baseline-mode fix |
| `multiclass.patch` | Multi-class LUCID, attack type in the logs, `--min_flows` (apply after `mitigation.patch`) |
| `VM_TEST.md` | Step-by-step checklist for testing in the VM |
| `split_pcaps.sh` | Splits each pcap 70% train / 30% test by time |
| `run_test.sh` | Live test in Mininet: modes off / src / src5 / 5tuple, writes `summary.csv` |
| `test_mitigation.py` | Unit tests for the rule logic |
| `dev/` | Held-out evaluation (`heldout.py`) and a switch-free live test (`fakeswitch.py`, `live_run.py`) |

## What changed in P4DDLe

**ML (`multiclass.patch`)**
- New dataset type `DOS2019_MC`. Attack flows are found by IP, as before, and get the class named in the pcap file (`ATTACK_CLASSES` in `lucid_dataset_parser.py`).
- Softmax output with 5 neurons, class-weighted loss, and model selection by macro-F1. Binary datasets work as before.
- Offline `--predict` also writes a per-class report and confusion matrix: `results/<name>/log/classes-*.txt`.
- Live mode logs predicted types per round (`log/classes-*.csv`) and the type behind each rule (`log/mitigation-*.csv`).
- Pcaps are parsed without IP reassembly, as the switch sees them. Without this, the DNS attack (92% fragments) became one pseudo-flow per window.
- `--feature_set rich` (default for `DOS2019_MC`) encodes TCP/IP flags as bits and lengths on a log scale. The ablation below shows it does not improve results; `--feature_set lucid` keeps the original encoding.

**Firewall (`mitigation.patch`)**
- `blocked_src` and `blocked_flows` tables run before forwarding and feature capture, with drop counters.
- `--mitigate {src,5tuple}`, `--block_timeout 60`, `--protect <CIDR>` (never blocked), and `--min_flows N` (block a source only if it has at least N flagged flows in one round).
- Fixes: the Bloom filter is now reset every round as in the paper, and replayed traffic is forwarded.

## Run (in the P4 VM, after INSTALL.md)

```bash
source ~/p4ddle-venv/bin/activate
cd <this project folder>
./apply_patches.sh
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/mitigation.patch    # skip if already applied
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/multiclass.patch
python3 mitigation/test_mitigation.py ~/p4ddle/p4-ddos/control-plane

mitigation/split_pcaps.sh ~/p4ddle/p4-ddos/sample-dataset ~/split
./pipeline.sh --mode offline --pcaps ~/split/train --name mc --dataset-type DOS2019_MC     # ~20 min
mitigation/run_test.sh ~/split/train/models/mc/*.h5 \
    ~/split/test/CIC-DDoS-2019-SynFlood.pcap ~/split/test/CIC-DDoS-2019-Benign.pcap ~/results_syn   # ~8 min
```

Repeat the last command with `DNS` or `UDPLag` in place of `SynFlood`. In the `off` row, nothing should be blocked or lost.

## Results so far (sample pcaps, tested on this machine without BMv2)

Trained with the real `pipeline.sh` and TensorFlow 2.16 (legacy Keras); your VM uses 2.13. Tested on the last 30% of each pcap, which training never saw (6,881 flow samples).

**Classification**

| Model | Macro-F1 | Benign | DNS | SYN | UDPLag | WebDDoS | Benign flagged |
|---|---|---|---|---|---|---|---|
| Binary LUCID (original) | - | - | detects 96.3% | 99.96% | 100% | **55.1%** | 0.15% |
| 5-class, rich features | 0.984 | 0.982 | 0.992 | 1.000 | 0.997 | 0.946 | 3.0% |
| 5-class, LUCID features* | 0.986 | 0.988 | 0.984 | 1.000 | 0.996 | 0.962 | 2.1% |

Class columns are F1 for the 5-class models, and detection rate for binary.
\* Best model after 11 of 16 grid configurations.

**Live loop.** The real `lucid_cnn.py` and `mitigation.py` ran against `dev/fakeswitch.py`, a Python model of the patched P4 program. Settings: held-out traffic, attack at 100 pps for 60 s (WebDDoS at 10 pps), benign at 50 pps.

| Attack | Mitigation | Attack blocked | Benign lost | Rules | First rule after |
|---|---|---|---|---|---|
| SYN flood | off | 0% | 0% | 0 | - |
| SYN flood | src | 96.9% | 6.9% | 5 | 1.8 s |
| SYN flood | **src, min_flows 5** | **98.6%** | **0%** | 1 | 0.8 s |
| SYN flood | 5tuple | 0% | 2.9% | 2,172 | 0.8 s |
| UDPLag | src | 99.2% | 10.2% | 6 | 0.5 s |
| UDPLag | src, min_flows 5 | 96.5% | 4.9% | 2 | 2.1 s |
| UDPLag | 5tuple | 22.8% | 1.5% | 2,313 | 1.3 s |
| DNS | src | 87.7% | 6.9% | 5 | 2.0 s |
| DNS | src, min_flows 5 | 90.6% | 0% | 1 | 1.5 s |
| WebDDoS | src | 89.4% | 11.5% | 6 | 6.1 s |
| WebDDoS | src, min_flows 5 | 0% | 0% | 0 | - |

Predicted type, without mitigation, of all flows flagged during the attack (benign false positives included): SYN flood run 2,140 of 2,192 typed SYN; UDPLag run 2,931 of 2,968 typed UDPLag; DNS run 807 of 841 typed DNS. WebDDoS was mostly classed benign live, although offline it was detected 99%: the 10 pps replay changes its timing.

## Findings to report
- **5-tuple rules are useless against floods:** each flow is over before its rule arrives, and thousands of rules are installed.
- **Source rules stop 88-99% of the attack within about 2 s,** but also block benign DNS resolvers (8.8.8.8, 4.2.2.4). The model confuses their replies with the DNS reflection attack, so 7-11% of benign packets are lost.
- **Requiring 5 flagged flows per source and round** removes almost all of that loss. It misses low-rate attacks such as WebDDoS (around 10 flows per round).
- **Multi-class training improves detection itself:** WebDDoS detection rose from 55% to 99%, at the cost of more benign flows flagged (2-3% against 0.15%).
- **The feature encoding barely matters:** the original LUCID features score the same as the rich ones (macro-F1 0.986 vs 0.984).

## Limits
- Only the 5 classes of the sample pcaps (CIC-DDoS2019), all attacks from one IP, small and repetitive traffic: the scores are optimistic.
- Reaction needs one detection round (2 s) plus inference; traffic before that passes.
- `src` also blocks benign hosts sharing the address and does not work with spoofed sources. Protected networks are set by the operator.
- Blocked packets are not stored, so LUCID's F1 covers unblocked traffic only.
- Replay is paced with `--pps`, which changes packet timing; 5-tuples are never looped.
- Live numbers come from a Python model of the switch, not BMv2; run `run_test.sh` in the VM for the real ones.

## dev/: testing without the switch
```bash
export PYTHONPATH=mitigation/dev/stubs TF_USE_LEGACY_KERAS=1   # TF_USE_LEGACY_KERAS only for TF >= 2.16
# held-out evaluation: preprocess the test pcaps, then score one or more models
python3 <cp>/lucid_dataset_parser.py --dataset_type DOS2019_MC --dataset_folder ~/split/test --output_folder ~/ho \
    --dataset_id ho --packets_per_flow 4 --time_window 2 --p4_compatible
python3 mitigation/dev/heldout.py <cp> ~/ho/2t-4n-ho-p4-preprocess.data <model.h5> ...
# live loop on the fake switch: packets as csv
tshark -r test.pcap -n -o ip.defragment:FALSE -Y ip -T fields -E separator=, -E occurrence=f -e ip.src -e ip.dst \
    -e ip.proto -e ip.len -e ip.flags -e ip.frag_offset -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.ack_raw \
    -e tcp.flags -e tcp.window_size_value -e udp.srcport -e udp.dstport -e udp.length -e icmp.type > test.csv
MINF=5 python3 mitigation/dev/live_run.py <cp> <model.h5> attack.csv benign.csv src out/ 100 50 60
```
`<cp>` is `~/p4ddle/p4-ddos/control-plane` with both patches applied. Do not keep the stubs on `PYTHONPATH` when using the real switch.
