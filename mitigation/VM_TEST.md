# Testing in the P4 VM: checklist

About 1 hour, most of it waiting. Background and results so far are in `README.md`.

**Never run on BMv2 so far:** P4 compilation, the switch, Mininet, and TensorFlow 2.13. Steps 3 and 6 are the first real test of those, so report any failure there exactly.

## 0. Prerequisites
- P4DDLe installed in the VM as in `../INSTALL.md`: venv `~/p4ddle-venv`, checkout at `~/p4ddle`.
- `p4c`, `simple_switch`, `tcpreplay`, `tshark`, `tcpdump` on the PATH.
- This project folder copied into the VM (the folder containing `apply_patches.sh`, `pipeline.sh` and `mitigation/`).

Start from a clean checkout so that the patches apply:
```bash
cd ~/p4ddle && git status --short          # should print nothing
# if it shows changes: git stash   (or: git checkout -- .)
```

## 1. Record versions
```bash
source ~/p4ddle-venv/bin/activate
python3 -c "import sys,tensorflow as tf,sklearn,h5py,numpy as np; print(sys.version.split()[0], tf.__version__, sklearn.__version__, h5py.__version__, np.__version__)"
pip show pyshark | grep Version; tshark --version | head -1; p4c --version; simple_switch --version
```

## 2. Apply the code
```bash
cd <project folder>
./apply_patches.sh
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/mitigation.patch
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/multiclass.patch
python3 mitigation/test_mitigation.py ~/p4ddle/p4-ddos/control-plane      # expect: Ran 10 tests ... OK
```

## 3. Compile the P4 program
```bash
cd ~/p4ddle/p4-ddos/data-plane/p4ddle && p4c --target bmv2 --arch v1model --std p4-16 p4_bloom_management.p4
grep -c 'MyIngress.blocked' p4_bloom_management.json                       # expect a number > 0
cd -
```

## 4. Split the data and train (~20-30 min)
```bash
mitigation/split_pcaps.sh ~/p4ddle/p4-ddos/sample-dataset ~/split
./pipeline.sh --mode offline --pcaps ~/split/train --name mc --dataset-type DOS2019_MC
cat ~/split/train/results/mc/log/classes-*.txt                              # per-class report
```
Expect 5 classes (benign, dns, synflood, udplag, webddos) with F1 around 0.95 or higher. If the run stops with `ben=0` or `ddos=0`, labelling failed: send the output.

## 5. Quick smoke test (~2 min)
```bash
MODES=off DURATION=20 mitigation/run_test.sh ~/split/train/models/mc/*.h5 \
    ~/split/test/CIC-DDoS-2019-SynFlood.pcap ~/split/test/CIC-DDoS-2019-Benign.pcap ~/smoke
```
The `off` row should show `attack_blocked_pct` 0.0 and `benign_lost_pct` 0.0, i.e. every packet reaches h2. If not, stop and send `~/smoke/off/switch.log` and `~/smoke/off/predictor.log`.

## 6. Full test (~8-10 min per attack)
```bash
for a in SynFlood UDPLag DNS; do
  mitigation/run_test.sh ~/split/train/models/mc/*.h5 \
      ~/split/test/CIC-DDoS-2019-$a.pcap ~/split/test/CIC-DDoS-2019-Benign.pcap ~/results_$a
done
```
Each run prints a table with 4 rows: off, src, src5, 5tuple.

Expected roughly, from the switch-free test:
- **src** blocks about 90-99% of the attack and loses about 5-10% of benign traffic.
- **src5** blocks about 90-99% with little benign loss.
- **5tuple** blocks little.

## 7. Send back
- The output of step 1.
- `~/split/train/results/mc/log/classes-*.txt`
- `~/results_*/summary.csv`
- For any failure: the error text plus `switch.log` / `predictor.log` from that mode's folder (e.g. `~/results_SynFlood/src/`).

## Troubleshooting
- Stale Mininet after a crash: `sudo mn -c`
- `sudo` prompts during the run: the sudo password timed out. Rerun; each attack takes about 10 min.
- Switch not ready: check that `simple_switch` and `simple_switch_CLI` are on the PATH inside the venv.
