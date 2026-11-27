# ML firewall in P4: multi-class detection and mitigation on P4DDLe

This project extends [P4DDLe](https://github.com/daisyfbk/p4ddle). The P4 switch (BMv2) collects per-flow features. Every 2 s the LUCID CNN in the control plane sorts each flow into one of 5 classes: **benign, DNS, SYN flood, UDPLag or WebDDoS**. When it finds an attack, the control plane installs a drop rule in the switch, and the switch then discards the attacker's packets.

This README walks you from an empty machine to the results, in the P4 tutorials VM. For background, the design, and the results so far, see [`mitigation/README.md`](mitigation/README.md).

> **Status.** The patches apply cleanly to upstream commit `94d36a1`, and the unit tests pass. Training and the held-out evaluation were run outside the VM. **The live test on BMv2 + Mininet (steps 6–8) has not been run yet.** The live numbers in `mitigation/README.md` come from a Python model of the switch (`mitigation/dev/`). If one of steps 6–8 fails, see [Reporting results](#reporting-results).

---

## Contents

| Path | What it is |
|---|---|
| `INSTALL.md` | Detailed VM setup guide, with explanations and network troubleshooting |
| `apply_patches.sh` | Fixes six upstream P4DDLe bugs (A–F). Idempotent |
| `pipeline.sh` | Preprocess → train → offline test (`--mode offline`), or a live replay with the original P4DDLe (`--mode live`) |
| `sweep.py`, `sweep.yaml`, `aggregate_results.py` | Hyper-parameter sweep and result table for the original binary P4DDLe |
| `mitigation/mitigation.patch` | Drop tables in P4, rule installation/expiry, Bloom filter reset, forwarding fix |
| `mitigation/multiclass.patch` | 5-class LUCID, dataset type `DOS2019_MC`, `--min_flows` |
| `mitigation/test_mitigation.py` | Unit tests for the rule logic (no switch needed) |
| `mitigation/split_pcaps.sh` | Splits each pcap by time: first 70% for training, last 30% for testing |
| `mitigation/run_test.sh` | Live test in Mininet. Compares mitigation modes and writes `summary.csv` |
| `mitigation/VM_TEST.md` | Short checklist version of steps 5–9 below |
| `mitigation/dev/` | Tests without BMv2: held-out scoring and a Python switch model |

---

## Requirements

- VirtualBox on the host, plus about 30 GB of free disk.
- The VM needs **8 GB RAM** (4 GB minimum) and 2–4 vCPUs.
- Internet access inside the VM (for apt, pip, and git).
- About **2–3 hours** in total. Most of that is compiling Python and BMv2 (steps 1–3, done once) and the live tests (about 10 min per attack).

All commands below run **inside the VM** as user `p4`, password `p4`, unless a step says otherwise.

---

## 1. Get the VM

1. Download the **Ubuntu 24.04 P4 tutorials OVA** from the table in
   <https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md>
   and import it with **File → Import Appliance**.
2. Before you boot: **Settings → System**: set 8 GB RAM and 2–4 CPUs.
3. Boot and log in (`p4` / `p4`). Check that the P4 toolchain is there:

   ```bash
   source ~/p4setup.bash 2>/dev/null; which p4c simple_switch simple_switch_CLI mn
   ```

   All four commands should print a path. If `p4c` is missing, add `source ~/p4setup.bash` to `~/.bashrc`.

If apt or pip cannot reach the network, see *Troubleshooting* in [`INSTALL.md`](INSTALL.md#troubleshooting).

## 2. Copy this project into the VM

The scripts expect this folder in the VM, here at `~/ml-firewall`. Use either option.

**Option A: shared folder.** Requires VirtualBox Guest Additions, which the tutorials VM normally has.
VM **Settings → Shared Folders → +**: pick this project folder, tick *Auto-mount*, then reboot the VM. Inside the VM:

```bash
sudo usermod -aG vboxsf p4          # once, then log out and back in
cp -r /media/sf_<folder name> ~/ml-firewall
```

**Option B: scp.**
VM **Settings → Network → Adapter 1 → Port Forwarding**: add host port `2222` → guest port `22`. Then:

```bash
# inside the VM
sudo apt install -y openssh-server
# on the host, from the folder that contains this project
scp -P 2222 -r <project folder> p4@localhost:ml-firewall
```

Copy the folder instead of working inside the shared mount: scripts must be executable, and `vboxsf` mounts can lose the executable bit. Then:

```bash
cd ~/ml-firewall && chmod +x *.sh mitigation/*.sh
```

## 3. Install the Python environment (once, 30–90 min)

LUCID needs Python 3.10 and TensorFlow 2.13, but the VM ships Python 3.12. The steps below put Python 3.10 in a venv at `~/p4ddle-venv` and rebuild the BMv2 Python bindings for it. [`INSTALL.md`](INSTALL.md) explains each step.

```bash
# 3a. Build dependencies and pyenv
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
  libsqlite3-dev libncurses-dev libffi-dev liblzma-dev tk-dev git curl
curl https://pyenv.run | bash
cat >> ~/.bashrc <<'EOF'

export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
EOF
exec $SHELL

# 3b. Python 3.10 and the venv (5-15 min)
pyenv install 3.10.14
pyenv shell 3.10.14
python -m venv ~/p4ddle-venv
source ~/p4ddle-venv/bin/activate
python --version                                   # Python 3.10.14

# 3c. Rebuild BMv2 so that its Python bindings land in the venv (15-30 min)
sudo apt install -y libthrift-dev libnanomsg-dev libboost-dev libboost-test-dev \
  libboost-program-options-dev libboost-system-dev libboost-filesystem-dev \
  libboost-thread-dev libevent-dev libtool flex bison pkg-config libgmp-dev \
  libpcap-dev autoconf automake libxxhash-dev libjsoncpp-dev
cd ~ && git clone https://github.com/p4lang/behavioral-model.git bmv2-for-p4ddle
cd bmv2-for-p4ddle && ./autogen.sh
./configure --with-python_prefix=$VIRTUAL_ENV --with-pi --with-thrift
make -j$(nproc) && sudo make install && sudo ldconfig
cd ~ && rm -rf bmv2-for-p4ddle

# 3d. Python packages and capture tools
pip install --upgrade pip
pip install tensorflow==2.13.0 scikit-learn h5py pyshark mininet thrift psutil   # do not pin protobuf
sudo apt install -y tshark tcpreplay tcpdump       # answer "Yes" to non-root capture

# 3e. Check
python -c "import tensorflow as tf, bm_runtime.standard, bmpy_utils, pyshark; print('OK, TF', tf.__version__)"
```

The last command should print `OK, TF 2.13.0`.

**Every new shell** needs `source ~/p4ddle-venv/bin/activate`. All the scripts below refuse to run without it.

## 4. Get P4DDLe and apply the patches

Use upstream commit `94d36a1`. The patches were checked against that commit, and later commits may not apply cleanly.

```bash
source ~/p4ddle-venv/bin/activate
cd ~ && git clone https://github.com/daisyfbk/p4ddle.git
cd ~/p4ddle && git checkout 94d36a1

cd ~/ml-firewall
./apply_patches.sh                                              # bug fixes A-F
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/mitigation.patch     # firewall
patch -p1 -d ~/p4ddle/p4-ddos < mitigation/multiclass.patch     # 5-class LUCID
```

The order matters: `apply_patches.sh`, then `mitigation.patch`, then `multiclass.patch`. Each `patch` command should print only `patching file ...` lines. If you see `Reversed (or previously applied) patch detected`, the checkout is not clean. Reset it and start this step again:

```bash
cd ~/p4ddle && git checkout -- . && git clean -fd p4-ddos/control-plane/
```

The scripts assume P4DDLe is at `~/p4ddle/p4-ddos`. If it is somewhere else, `export P4DDLE_ROOT=/path/to/p4-ddos`.

## 5. Test 1: unit tests (seconds)

```bash
cd ~/ml-firewall
python3 mitigation/test_mitigation.py ~/p4ddle/p4-ddos/control-plane
```

Expected: `Ran 10 tests ... OK`. These tests check the rule logic: source and 5-tuple rules, protected networks, timeouts, a full table, and `--min_flows`.

## 6. Test 2: compile the P4 program (about 1 min)

```bash
cd ~/p4ddle/p4-ddos/data-plane/p4ddle
p4c --target bmv2 --arch v1model --std p4-16 p4_bloom_management.p4
grep -c 'MyIngress.blocked' p4_bloom_management.json      # must print a number > 0
cd ~/ml-firewall
```

The repository ships an old JSON without the drop tables, so this step is required. `run_test.sh` also recompiles every time.

## 7. Test 3: train and evaluate offline (20–30 min)

First split each sample pcap by time, so that no test packet was seen during training:

```bash
cd ~/ml-firewall
mitigation/split_pcaps.sh ~/p4ddle/p4-ddos/sample-dataset ~/split
```

Expected output:

```
CIC-DDoS-2019-Benign.pcap: train 19407, test 8318
CIC-DDoS-2019-DNS.pcap: train 3687, test 1581
CIC-DDoS-2019-SynFlood.pcap: train 18421, test 7895
CIC-DDoS-2019-UDPLag.pcap: train 15750, test 6751
CIC-DDoS-2019-WebDDoS.pcap: train 2172, test 932
```

Then train the 5-class model:

```bash
./pipeline.sh --mode offline --pcaps ~/split/train --name mc --dataset-type DOS2019_MC
cat ~/split/train/results/mc/log/classes-*.txt          # per-class report + confusion matrix
ls ~/split/train/models/mc/*.h5                         # the trained model
```

Expected: the report lists 5 classes (benign, dns, synflood, udplag, webddos), each with an F1 of about 0.95 or higher. If the run stops with `Sanity check FAILED: ... ben=0` or `ddos=0`, labelling failed. Check that you used `--dataset-type DOS2019_MC` and that `multiclass.patch` applied.

`pipeline.sh` will not overwrite an existing model. To retrain, add `--force` or pick another `--name`.

## 8. Test 4: live smoke test on BMv2 (about 2 min)

This is the first step that uses the switch, Mininet, and `sudo`.

```bash
sudo -v      # cache the sudo password (p4)
MODES=off DURATION=20 mitigation/run_test.sh ~/split/train/models/mc/*.h5 \
    ~/split/test/CIC-DDoS-2019-SynFlood.pcap ~/split/test/CIC-DDoS-2019-Benign.pcap ~/smoke
```

With mitigation `off`, the switch should forward everything. The `off` row must show `attack_blocked_pct` **0.0** and `benign_lost_pct` **0.0**. If it does not, stop and check `~/smoke/off/switch.log` and `~/smoke/off/predictor.log`.

## 9. Test 5: full live test (8–10 min per attack)

Each run replays held-out traffic through the switch four times, once per mitigation mode:

| Mode | Behaviour |
|---|---|
| `off` | Detection only (baseline) |
| `src` | Block the attacker's source IP |
| `src5` | Block a source only if it has ≥ 5 flagged flows in one round |
| `5tuple` | Block only the flagged flow (5-tuple) |

```bash
sudo -v
for a in SynFlood UDPLag DNS; do
  mitigation/run_test.sh ~/split/train/models/mc/*.h5 \
      ~/split/test/CIC-DDoS-2019-$a.pcap ~/split/test/CIC-DDoS-2019-Benign.pcap ~/results_$a
done
column -s, -t ~/results_SynFlood/summary.csv
```

Columns in `summary.csv`:

| Column | Meaning |
|---|---|
| `attack_offered` / `attack_received` | Attacker packets sent by h1 / that reached h2 |
| `attack_blocked_pct` | Share of attack packets dropped by the switch |
| `benign_offered` / `benign_received` / `benign_lost_pct` | The same for benign traffic (collateral damage) |
| `rules` | Drop rules installed during the run |
| `seconds_to_first_rule` | Time from attack start to the first rule against the attacker |
| `predicted_attack_flows` | Attack types LUCID predicted, e.g. `synflood=2140 dns=12 ...` |

Expected ranges, taken from the test without the switch (see `mitigation/README.md`):

- `src`: blocks about 88–99% of the attack, but loses about 5–10% of benign traffic, because benign DNS resolvers get flagged.
- `src5`: blocks about 90–99%, with little or no benign loss.
- `5tuple`: blocks little, and installs thousands of rules.
- `off`: 0% blocked, 0% lost.

Per-mode details are in `~/results_<attack>/<mode>/`: `switch.log`, `predictor.log`, `h2.pcap` (what reached the victim), `log/mitigation-*.csv` (every rule, with its attack type and dropped-packet count), and `log/classes-*.csv` (predicted types per round).

**Options** for `run_test.sh`, as environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `MODES` | `off src src5 5tuple` | Modes to run (`srcN` for any N) |
| `ATTACK_PPS` / `BENIGN_PPS` | `100` / `50` | Replay rates |
| `DURATION` | `60` | Attack duration in seconds (benign starts 10 s earlier) |
| `ATTACKER` | `172.16.0.5` | Attacker IP used to count packets |
| `PROTECT` | `192.168.50.0/24` | Network that is never blocked (the victims) |

WebDDoS is not in the loop because its test split is short. To try it anyway, use `ATTACK_PPS=10 DURATION=60 mitigation/run_test.sh ... CIC-DDoS-2019-WebDDoS.pcap ...`.

---

## Optional: tests without the switch

`mitigation/dev/` runs the real `lucid_cnn.py` and `mitigation.py` against a Python model of the patched P4 program. It needs no root, Mininet, or BMv2, so it also works outside the VM. The commands are in the *dev/* section of [`mitigation/README.md`](mitigation/README.md#dev-testing-without-the-switch).

## Optional: original binary P4DDLe baseline

The patches leave the original binary mode working:

```bash
./pipeline.sh --mode offline --pcaps ~/p4ddle/p4-ddos/sample-dataset --name base --dataset-type DOS2019
./pipeline.sh --mode live --pcaps ~/p4ddle/p4-ddos/sample-dataset --name base --dataset-type DOS2019 \
    --replay-pcap ~/p4ddle/p4-ddos/sample-dataset/CIC-DDoS-2019-SynFlood.pcap --duration-min 1 \
    --benign-pcap ~/p4ddle/p4-ddos/sample-dataset/CIC-DDoS-2019-Benign.pcap --benign-pps 100
python3 aggregate_results.py ~/p4ddle/p4-ddos/sample-dataset/results/base
```

Note that `--duration-min` is in **minutes**. This baseline trains and replays the same pcaps, so its live scores are optimistic. `sweep.py` (configured by `sweep.yaml`) runs this pair over a grid and takes hours, so start it inside `tmux`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Activate the venv first` / `Python venv is not active` | `source ~/p4ddle-venv/bin/activate` |
| `patch` reports *Reversed or previously applied* | Reset the checkout (step 4) and apply again in order |
| `switch not ready after 60 s` or `Mininet hosts h1/h2 not found` | `sudo mn -c`, then rerun. Check the `switch.log` of that mode |
| `sudo` asks for a password mid-run | The cached password expired. Run `sudo -v` and rerun that attack |
| `simple_switch_CLI` not found inside the venv | `source ~/p4setup.bash` before activating the venv |
| `ImportError: bm_runtime` | BMv2 was built without the venv active. Redo step 3c with the venv active |
| Disk filling up | Check `df -h /`. Delete `~/results_*/*/h2.pcap` from old runs |
| No network in the VM | See *Troubleshooting* in [`INSTALL.md`](INSTALL.md#troubleshooting) |

## Reporting results

Please send back:

1. Versions:
   ```bash
   python3 -c "import sys,tensorflow as tf,sklearn,numpy as np; print(sys.version.split()[0], tf.__version__, sklearn.__version__, np.__version__)"
   p4c --version; simple_switch --version; tshark --version | head -1
   ```
2. `~/split/train/results/mc/log/classes-*.txt`
3. `~/results_*/summary.csv`
4. For any failure: the exact error, plus `switch.log` and `predictor.log` from that mode's folder.
