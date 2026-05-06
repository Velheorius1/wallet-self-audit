# How to sign a BIP-322 challenge

`wsa nonce-audit` requires you to prove you control the address before it
will fetch your spending signatures from the chain. The proof is a
[BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
signed message — your wallet signs a challenge string we generate, and we
verify the signature locally with `libsecp256k1`. No private key leaves
your wallet.

## End-to-end walkthrough

### 1. Generate a challenge

```sh
wsa nonce-audit bc1qexampleaddress... --print-challenge
```

This prints a string of the form

```
wallet-self-audit::bc1qexampleaddress...::2026-05-06::<random-nonce>
```

The challenge is bound to the **UTC date** so it can only be used today.
Copy it.

### 2. Sign it in your wallet

#### Sparrow Wallet

`Tools → Sign/Verify Message → Sign`. Paste the challenge into *Message*,
select your address, click *Sign*. Sparrow uses BIP-322 by default for
`bc1q...` and BIP-137 for legacy `1...`; both work — `wsa` auto-detects.

#### Bitcoin Core 25+

```text
bitcoin-cli signmessage "<address>" "<challenge>"
```

Returns a base64 signature. (Bitcoin Core 25.0+ supports BIP-322 signing
for segwit addresses; older versions only support BIP-137 / legacy.)

#### Electrum

`Tools → Sign/Verify Message`. Same idea. Electrum's BIP-322 support
shipped in 4.5.

#### Hardware wallets

| Vendor   | Firmware     | Supports BIP-322 |
| -------- | ------------ | ---------------- |
| Trezor   | 2.7.0+       | ✅                |
| Ledger   | App 2.x +    | ✅                |
| Coldcard | 5.1.5+       | ✅ (signed text)  |
| BitBox02 | 9.16+        | ✅                |

If your firmware is older, fall back to a *self-spend* — send a 1-sat
input back to your own address. The on-chain transaction proves
ownership; `wsa` will accept its txid in `--proof` mode.

### 3. Save the signature

`wsa` expects a tiny JSON file:

```json
{
  "challenge": "wallet-self-audit::bc1q...::2026-05-06::abc123",
  "signature": "<base64-signature-from-your-wallet>"
}
```

Save it as `proof.json` (anywhere on disk; it's public).

### 4. Run the audit

```sh
wsa nonce-audit bc1qexampleaddress... --proof proof.json
```

If the proof verifies, `wsa` proceeds to fetch the address's spending
signatures from `mempool.space` and runs r-collision + lattice/HNP
analysis. If it fails (wrong signature, expired challenge, replayed
challenge), the audit aborts with `proof rejected`.

## Replay protection

Challenges include a 24-hour UTC-day window and a random nonce. Once a
challenge has been used, it is appended to a per-host replay store and
rejected on every subsequent call (Phase 1, `ownership.py`).

## "Informational" mode

If you don't want to sign anything — for example, you're checking
*someone else's* address from public information — use:

```sh
wsa nonce-audit bc1q... --informational
```

That returns counts only (number of outgoing tx, number of `(pubkey, r)`
collision groups). It never tells you whether the wallet is recoverable;
it only tells you whether further auditing would be productive.
