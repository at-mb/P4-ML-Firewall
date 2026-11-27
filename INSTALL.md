# Installing p4ddle on the P4 tutorials Ubuntu 24.04 VM

This document walks through bringing the `daisyfbk/p4ddle` repository onto the
official P4 tutorials Ubuntu 24.04 VM, working around the version incompatibilities
between p4ddle (Python 3.10 / TensorFlow 2.13) and the VM's default Python 3.12.

The end state: a working Python 3.10 venv with TensorFlow 2.13, BMv2 Python
bindings, and the p4ddle source ready to run.

Estimated time: 30–90 minutes (most of it waiting on a BMv2 rebuild and pip
installs).

---

## Prerequisites

- A host running Linux, Windows, or macOS with VirtualBox installed.
- Internet connectivity inside the VM (see "Network setup" below if you have
  trouble reaching Launchpad mirrors).
- ~30 GB free disk space in the VM.

---

## Step 1: Get the VM running

Download a pre-built Ubuntu 24.04 OVA from the appliance table maintained by
Andy Fingerhut:

<https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md>

If no 24.04 OVA is available there, fall back to the Vagrant build (takes 1–3
hours of compilation):

```bash
git clone https://github.com/p4lang/tutorials.git
cd tutorials/vm-ubuntu-24.04
vagrant up
```

Before booting, in VirtualBox: **VM Settings → System**: set RAM to 8 GB (4 GB
minimum) and 2–4 vCPUs.

Default login: `p4` / `p4`.

---

## Step 2: Verify the existing P4 toolchain

The tutorials VM should already have `p4c`, `simple_switch`, and Mininet
installed, plus a venv at `~/p4dev/p4dev-python-venv/` containing BMv2's
Python bindings (compiled against Python 3.12).

```bash
which p4c simple_switch simple_switch_CLI
source ~/p4dev/p4dev-python-venv/bin/activate
python3 -c "import bm_runtime.standard, bmpy_utils; print('VM bindings OK')"
deactivate
```

If `p4c` isn't on PATH, source the setup file: `source ~/p4setup.bash` (and
add this to `~/.bashrc`).

We won't use this venv directly — we need Python 3.10 for p4ddle — but it's
worth confirming the VM is healthy before going further.

---

## Step 3: Install Python 3.10 via pyenv

Ubuntu 24.04 ships Python 3.12, but TensorFlow 2.13 (required by LUCID) only
has wheels up to Python 3.11. We install Python 3.10 alongside the system
Python using pyenv.

> **Note:** The deadsnakes PPA is the more common route, but on some networks
> Launchpad's content CDN is unreachable. pyenv downloads from python.org and
> sidesteps that issue.

Install build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev libncurses-dev libffi-dev liblzma-dev tk-dev git
```

Install pyenv:

```bash
curl https://pyenv.run | bash
```

Add pyenv to your shell config:

```bash
cat >> ~/.bashrc <<'EOF'

export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
EOF

exec $SHELL
```

Install Python 3.10 (compiles from source, takes 5–15 minutes):

```bash
pyenv install 3.10.14
```

---

## Step 4: Create the p4ddle venv

```bash
pyenv shell 3.10.14
python --version    # should print Python 3.10.14
python -m venv ~/p4ddle-venv
source ~/p4ddle-venv/bin/activate
python --version    # 3.10.14 inside the venv
```

Your shell prompt should now show `(p4ddle-venv)`.

---

## Step 5: Rebuild BMv2 Python bindings for Python 3.10

The VM's existing BMv2 bindings are for Python 3.12 and can't be imported from
the 3.10 venv. We rebuild BMv2 from source with its Python output redirected
into our new venv.

Install BMv2's build dependencies:

```bash
sudo apt install -y libthrift-dev libnanomsg-dev libboost-dev \
  libboost-test-dev libboost-program-options-dev libboost-system-dev \
  libboost-filesystem-dev libboost-thread-dev libevent-dev libtool \
  flex bison pkg-config libgmp-dev libpcap-dev autoconf automake \
  libxxhash-dev libjsoncpp-dev
```

Most of these are already on the VM and apt will skip them.

Build and install (with the p4ddle venv still active):

```bash
echo $VIRTUAL_ENV    # must print /home/p4/p4ddle-venv before continuing

cd ~
git clone https://github.com/p4lang/behavioral-model.git bmv2-for-p4ddle
cd bmv2-for-p4ddle
./autogen.sh
./configure --with-python_prefix=$VIRTUAL_ENV --with-pi --with-thrift
make -j$(nproc)
sudo make install
sudo ldconfig
```

Compile time: 15–30 minutes.

The `--with-python_prefix=$VIRTUAL_ENV` flag drops the Python bindings into
`~/p4ddle-venv/lib/python3.10/site-packages/`. The compiled `simple_switch`
binary at `/usr/local/bin/simple_switch` overwrites the VM's existing one with
functionally identical code.

After installation, the cloned source tree (~3.8 GB) can be removed:

```bash
cd ~ && rm -rf bmv2-for-p4ddle
```

---

## Step 6: Install the p4ddle Python stack

With the p4ddle venv still active:

```bash
pip install --upgrade pip
pip install tensorflow==2.13.0 scikit-learn h5py pyshark mininet thrift psutil
```

> **Note:** p4ddle's README says `protobuf==3.19.6`, but TensorFlow 2.13 requires
> protobuf ≥ 3.20.3. Don't pin protobuf — let pip resolve it (TF will install a
> compatible 4.x version, which works fine with BMv2 since BMv2's bindings use
> Thrift, not protobuf).

Also install tshark and tcpreplay (needed by p4ddle's helpers):

```bash
sudo apt install -y tshark tcpreplay
```

When tshark prompts about non-root capture, answer **Yes**. If you missed the
prompt (or it didn't appear), run `sudo dpkg-reconfigure wireshark-common`
and answer Yes — this creates the `wireshark` group. Then:

```bash
sudo usermod -aG wireshark $USER
```

If the group still doesn't exist after reconfiguring, you can safely skip this
step — p4ddle's live-prediction path uses BMv2's Thrift interface and doesn't
invoke tshark directly.

Log out and back in for the group change to take effect (or `newgrp wireshark`
for the current shell).

Verify everything imports cleanly:

```bash
python -c "import tensorflow, bm_runtime.standard, bmpy_utils, pyshark; print('all good')"
```

---

## Step 7: Clone p4ddle

```bash
cd ~
git clone https://github.com/daisyfbk/p4ddle.git
cd p4ddle
```

---

## Step 8: Apply known fixes

The p4ddle repo has several bugs that need patching before the pipeline works
end-to-end. Rather than editing files by hand, use the `apply_patches.sh`
script:

```bash
./apply_patches.sh
```

The script is **idempotent** — safe to run multiple times. It will skip patches
that are already applied (e.g. if you've manually edited one already).

It applies five fixes:

- **Patch A** (`launcher.py`): `log_console = True` → `False`. Without this,
  BMv2's per-packet trace fills the disk during traffic capture.

- **Patch B** (`lucid_cnn.py` line 475): captures `ignored_packets` from
  `process_live_traffic`. Upstream unpacks 8 values but the function returns
  9 in p4ddle mode, causing `ValueError: too many values to unpack`.

- **Patch C** (`lucid_cnn.py` line 501): converts a positional argument to
  a keyword argument in the `report_results` call so `switch_impl` lands in
  the correct parameter slot. Without this, the live-mode metrics silently
  fall back to offline format (`PREDICTION_HEADER_LIVE` instead of
  `PREDICTION_HEADER_FLOWS`) because `args.switch_impl` was accidentally
  being assigned to `short_header`.

- **Patch D** (`lucid_cnn.py` line 501): passes `ignored_packets` as a
  keyword argument to `report_results`. Required for live mode to write
  the Bloom filter saturation metric to the results CSV.

- **Patch E** (`lucid_cnn.py` line 515): adds `ignored_packets=0` to the
  `report_results` function signature so the variable resolves. Without
  this, live mode crashes with `NameError: name 'ignored_packets' is not
  defined`.

- **Patch F** (`lucid_cnn.py` line ~482): fixes the polling-loop timer bug.
  `last_collect_time = round_time` was nested inside `if len(samples) > 0:`,
  so empty polling rounds didn't update the timer and the loop sprinted at
  full Python+Thrift speed (~5 iterations/sec instead of the intended 0.5/sec).
  This thrashed the data plane's block-swap mechanism, dramatically reducing
  packet capture. The patch adds an unconditional timer update right after
  `process_live_traffic` returns.

### About the `traffic_generator` `-d` flag

This is **not** patched — it's a behavioral quirk, not a bug: the value is
in **minutes**, not seconds, despite the upstream README's examples making it
look like seconds. Use small values when invoking it manually: `-d 1` is one
minute, `-d 2` is two minutes.

---

## Step 9: Sanity test

Quick test that the model file exists and the venv can load everything:

```bash
ls ~/p4ddle/p4-ddos/sample-dataset/
python -c "
import tensorflow as tf
from tensorflow.keras.models import load_model
import bm_runtime.standard
import bmpy_utils
print('TensorFlow:', tf.__version__)
print('All imports work')
"
```

If you see no errors and TensorFlow 2.13.0 prints, the environment is ready.

---

## Activating the environment in future sessions

Every new shell needs:

```bash
source ~/p4ddle-venv/bin/activate
```

For commands that need `sudo` (the BMv2 launcher and traffic generator), use:

```bash
sudo $(which python3) <script.py> <args>
```

The `$(which python3)` resolves to the venv's Python; plain `sudo python3` uses
root's system Python and won't see the venv's packages.

---

## Notes and gotchas

- **BMv2 source tree size.** The cloned `bmv2-for-p4ddle` directory is ~3.8 GB
  after build. Step 6 deletes it after install. Keep it if you want to rebuild
  later; otherwise it's safe to remove.

- **Disk space during runs.** Even with `log_console=False`, plan for ~1 GB
  of write activity per minute of traffic generation. Watch `df -h /` during
  runs.

- **Cleanup between runs.** Mininet leaves stale namespaces between runs.
  Always run `sudo mn -c` after killing a switch session before starting a
  new one.

- **The pre-trained model.** `sample-dataset/4t-10n-DOS2019-LUCID-p4.h5` may
  already exist in the repo. If so, the training step in Step 4 of the
  upstream README can be skipped for a first test.

- **VM resources.** 4 GB RAM minimum; under 4 GB, TensorFlow will swap heavily
  during training and inference may time out. 8 GB is comfortable.

---

## Troubleshooting

**Network errors during apt/pip (`Could not resolve host`, `Connection refused`):**
The VM's default NAT networking can occasionally land in a state where DNS or
specific HTTPS endpoints are unreachable. If a clean VM exhibits this, switch
the adapter to **NAT Network** mode:

1. `sudo poweroff` the VM.
2. In VirtualBox: **File → Tools → Network Manager → NAT Networks → Create** (accept defaults).
3. **VM Settings → Network → Adapter 1**: change "Attached to" from **NAT** to **NAT Network**, select the new network.
4. Boot the VM.
5. If DNS still fails, override it at runtime: `sudo resolvectl dns enp0s3 8.8.8.8 1.1.1.1`.

To persist DNS, edit `/etc/netplan/*.yaml` and add a `nameservers` block, then
`sudo netplan apply`.
