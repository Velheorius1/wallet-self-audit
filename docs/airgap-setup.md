# Airgap Setup — Tails USB

> **TL;DR:** the only configuration where compromise of your host machine does not compromise the audit. Recommended for any audit involving > $1k of funds.

## What is "airgap"?

A computer that has **never** been connected to a network during the audit. No Wi-Fi, no Ethernet, no Bluetooth, no LTE modem.

## Why Tails?

- **Amnesic by design** — nothing is written to the host disk; everything lives in RAM and is wiped on shutdown.
- **No network by default** — must be explicitly enabled.
- **Verified releases** — Tails ISOs are signed; verify before flashing.
- **Includes Python, uv, Sparrow Wallet** — almost everything you need.

## Setup walkthrough

### 1. Download and verify Tails

On a **separate, trusted** machine:

```bash
# Download from https://tails.boum.org/install/download/
# Verify signature:
gpg --keyserver keys.openpgp.org --recv-keys 0xDBB802B258ACD84F
gpg --verify tails-amd64-*.img.sig tails-amd64-*.img
```

### 2. Flash to USB

```bash
# Linux/macOS — replace /dev/diskN with your USB device
sudo dd if=tails-amd64-*.img of=/dev/diskN bs=4M status=progress
```

Use a USB stick that you will **destroy** after the audit.

### 3. Boot into Tails

- Insert USB → boot menu (typically F12 / F2 / Esc on most machines).
- Select USB device.
- At the welcome screen, set an admin password (random, you'll forget it).
- **Do NOT enable network access.**

### 4. Install wallet-self-audit (offline)

Pre-pack on a second USB:

```bash
# On your trusted machine (online):
mkdir -p wsa-airgap
cd wsa-airgap

# Download wheels for all deps (Linux x86_64)
uv pip download wallet-self-audit \
    --python-version 3.11 \
    --platform manylinux2014_x86_64 \
    --no-deps -d wheels/

# Bundle the script + sentinel + corpus
cp -r ../wallet-self-audit/{src,tests,pyproject.toml,uv.lock} .
```

Copy `wsa-airgap/` to a second USB (not the Tails one).

On the Tails machine:

```bash
# Insert second USB → mount it
sudo mkdir -p /mnt/wsa
sudo mount /dev/sdc1 /mnt/wsa  # adjust device

cd /mnt/wsa/wsa-airgap

# Install offline
uv venv --python 3.11
source .venv/bin/activate
uv pip install --no-index --find-links=wheels/ wallet-self-audit

# Verify install
wsa doctor
```

### 5. Run the audit

```bash
# Disable network (paranoia check)
sudo systemctl stop NetworkManager

# Run prng-audit (interactive, mnemonic via getpass)
wsa prng-audit
```

Type your mnemonic when prompted. The screen shows nothing (getpass). Press Enter.

### 6. Read the verdict

The output is `SAFE / SUSPICIOUS / VULNERABLE`. **Write it on paper.** Do not photograph.

If `VULNERABLE`:
1. **Do not** transfer your full balance to the same wallet.
2. Generate a fresh wallet on a different airgapped machine using a verified wallet binary.
3. From your normal (online) machine, send funds from the vulnerable address to the new fresh address. Use a different output amount than the original to break heuristic clustering.

### 7. Destroy the USB

After shutting down Tails:

```bash
# On a different machine, overwrite the USB
sudo dd if=/dev/urandom of=/dev/diskN bs=4M status=progress
```

Then physically destroy the USB stick (snip it with pliers, microwave it for 10 seconds, etc.).

## What if I can't airgap?

Use the [Acceptable: Trusted Mac](../README.md#-acceptable-trusted-mac) configuration from the README. It is **less safe** but still much better than running on a cloud VM or shared machine.

## FAQ

### Q: Can I just disconnect Wi-Fi instead of using Tails?

**No.** Modern OSes have many other vectors: Bluetooth (Apple Continuity, AirDrop), LTE modems on Macs with cellular, persistent system services that buffer activity for sync. Tails amnesia + network stack disabled is qualitatively different.

### Q: Why not a Linux VM on my Mac?

The hypervisor has full RAM access. If your Mac is compromised, the VM is compromised.

### Q: Can I use a Raspberry Pi?

Yes, Pi 4 / 5 with Tails-equivalent (e.g. Heads, Whonix) works. The cost is buying a dedicated device. Pi has no Bluetooth/Wi-Fi to disable in BIOS — keep that in mind.

### Q: I don't trust the BIP-322 signing on Tails.

You can sign on your trusted machine, copy the signed-message file via USB to Tails, then run `wsa nonce-audit <address> --proof signed.txt` on Tails. The signing happens on a trusted machine, the audit on the airgap.

## See also

- [Tails official guide](https://tails.boum.org/doc/index.en.html)
- [Threat model](threat-model.md) — what airgap defends against
