"""Integration tests for Phase 3 nonce audit on a real historical vector.

The synthetic orchestrator tests in ``tests/unit/`` validate Phase 3 logic
against keypairs we generate ourselves. This file does the opposite — it
exercises the same modules against a *real* on-chain transaction with a
documented r-value collision.

Test vector
-----------
- **Address:** ``1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm`` (P2PKH).
- **Tx:** ``9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1``,
  block 170 399 (2012-03-09 UTC). The transaction has two inputs that
  spend back to the same address; both signatures share the same
  ``r``-value (the underlying private key was effectively published the
  moment this tx was mined).
- **Public reference:** Nils Schneider's 2013 proof-of-concept,
  rediscovered in the daedalus/bitcoin-recover-privkey repository and the
  Ishaana "Deep Dive Into Nonce-Reuse" blog series. Address has been
  drained for over a decade — funds are zero.

What we assert
--------------
1. **Strict-DER guard** — Phase 3's DER parser rejects the lax pre-BIP-66
   encoding used here (``r`` has its high bit set without a leading
   ``0x00`` padding byte). This is *intended* — strict DER is
   mainnet-mandatory after BIP-66 (block ~363 724, 2015) and refusing it
   here protects modern callers from malleability surprises.
2. **Sighash math** — ``legacy_sighash_all`` produces *distinct* z-values
   for the two inputs (each input signs a different message commitment
   even though the surrounding transaction is the same).
3. **Collision detection** — given the recovered ``(r, s, z, pubkey)``
   tuples, ``find_collisions`` groups them and ``CollisionGroup.is_real_collision``
   returns ``True``.
4. **Verify-by-pubkey-projection (the headline)** —
   ``collision_recovers_pubkey`` returns ``True`` when projecting both
   signatures against the address' on-chain public key. *No private key
   is materialised at any step* (the projection happens through coincurve
   group ops on libsecp256k1 in C).
5. **Per-signature consistency** — each signature individually projects
   to the address' public key via ``consistent_with_pubkey``. This is the
   building block of (4) and verifies that the uncompressed-pubkey
   coercion path inside ``recovery_detector`` works.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from tests.fixtures.nonce.static_client import StaticMempoolClient
from wallet_self_audit.crypto.recovery_detector import (
    collision_recovers_pubkey,
    consistent_with_pubkey,
    fingerprint,
)
from wallet_self_audit.crypto.sighash import legacy_sighash_all
from wallet_self_audit.nonce.collision import find_collisions
from wallet_self_audit.nonce.extractor import (
    SignatureRecord,
    _parse_raw_tx,
    extract_outgoing_signatures,
)

# ---------------------------------------------------------------------------
# Public chain constants (all from the mempool.space JSON fixture).
# tests/fixtures/.* is gitleaks-allowlisted because every value here is
# already on the public Bitcoin blockchain.
# ---------------------------------------------------------------------------
_FIXTURE_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "nonce"
    / "historical_2012_nils_schneider.json"
)
_HISTORICAL_ADDRESS: Final[str] = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"
_COLLISION_TXID: Final[str] = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"

# Both inputs of _COLLISION_TXID share this r-value (the bug).
_R: Final[int] = 0xD47CE4C025C35EC440BC81D99834A624875161A26BF56EF7FDC0F5D52F843AD1

# Distinct s-values, paired with distinct z-values per input.
_S_A: Final[int] = 0x44E1FF2DFD8102CF7A47C21D5C9FD5701610D04953C6836596B4FE9DD2F53E3E
_S_B: Final[int] = 0x9A5F1C75E461D7CEB1CF3CAB9013EB2DC85B6D0DA8C3C6E27E3A5A5B3FAA5BAB

# 65-byte uncompressed pubkey controlling 1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm.
_PUBKEY_UNCOMPRESSED: Final[bytes] = bytes.fromhex(
    "04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81"
    "ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff"
)

# Standard P2PKH scriptPubKey for both prevouts (OP_DUP OP_HASH160 <h160>
# OP_EQUALVERIFY OP_CHECKSIG).
_PREV_SCRIPT_PUBKEY: Final[bytes] = bytes.fromhex(
    "76a91470792fb74a5df745bac07df6fe020f871cbb293b88ac",
)


@pytest.fixture
def static_client() -> StaticMempoolClient:
    return StaticMempoolClient.from_path(_FIXTURE_PATH)


def _z_for_each_input() -> tuple[int, int]:
    """Re-derive both z-values from the raw tx in the fixture."""
    client = StaticMempoolClient.from_path(_FIXTURE_PATH)
    raw_hex = client.get_raw_tx_hex(_COLLISION_TXID)
    tx = _parse_raw_tx(raw_hex)
    z_a = legacy_sighash_all(tx, 0, _PREV_SCRIPT_PUBKEY)
    z_b = legacy_sighash_all(tx, 1, _PREV_SCRIPT_PUBKEY)
    return z_a, z_b


def _hand_built_records() -> list[SignatureRecord]:
    """Construct SignatureRecord(s) directly from public chain data.

    We bypass ``extract_outgoing_signatures`` here because the historical
    encoding is lax-DER and Phase 3 (correctly) refuses it — see
    ``test_extractor_rejects_lax_der_pre_bip66``. The math under test is
    independent of the DER framing.
    """
    z_a, z_b = _z_for_each_input()
    return [
        SignatureRecord(
            txid=_COLLISION_TXID,
            vin_index=0,
            pubkey_compressed=_PUBKEY_UNCOMPRESSED,
            r=_R,
            s=_S_A,
            z=z_a,
            sighash_type=0x01,
            script_type="p2pkh",
        ),
        SignatureRecord(
            txid=_COLLISION_TXID,
            vin_index=1,
            pubkey_compressed=_PUBKEY_UNCOMPRESSED,
            r=_R,
            s=_S_B,
            z=z_b,
            sighash_type=0x01,
            script_type="p2pkh",
        ),
    ]


# ---------------------------------------------------------------------------
# 1. Strict DER guard (anti-regression)
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_extractor_rejects_lax_der_pre_bip66(static_client: StaticMempoolClient) -> None:
    """Phase 3 DER parser refuses pre-BIP-66 lax-encoded ``r`` (MSB set, no 0x00 pad).

    BIP-66 made strict DER mandatory at activation height ~363 724
    (Jul 2015). Modern wallets always produce strict DER — refusing
    anything else is the right default for a self-audit tool. This test
    locks the behaviour against accidental relaxation.
    """
    records = extract_outgoing_signatures(_HISTORICAL_ADDRESS, static_client)
    assert records == [], (
        "extractor should refuse lax pre-BIP-66 DER; if this fails, the parser was relaxed"
    )


# ---------------------------------------------------------------------------
# 2. Sighash math
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_legacy_sighash_distinct_per_input() -> None:
    """``legacy_sighash_all`` must produce different z for different inputs.

    Even though both inputs share scriptPubKey and pubkey, BIP-143's
    pre-segwit legacy sighash mixes in input-specific data via the
    serialised tx prefix. The two z values must differ — if they were
    equal, identical (r, s) pairs would be expected for non-vulnerable
    signing too.
    """
    z_a, z_b = _z_for_each_input()
    assert z_a != z_b, "z must differ between inputs of the same tx"
    # Each z must be a valid scalar < n (else recovery_detector would
    # reject it). Non-zero is also required.
    assert 0 < z_a < 1 << 256
    assert 0 < z_b < 1 << 256


# ---------------------------------------------------------------------------
# 3. Collision detection
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_find_collisions_groups_two_inputs() -> None:
    """``find_collisions`` must find one real-collision group on this tx."""
    groups = find_collisions(_hand_built_records())
    assert len(groups) == 1, f"expected exactly 1 collision group, got {len(groups)}"
    cg = groups[0]
    assert cg.is_real_collision()
    assert cg.r == _R
    assert cg.pubkey_compressed == _PUBKEY_UNCOMPRESSED
    assert len(cg.records) == 2
    # The records are exactly the two inputs of the historical tx.
    txids_in_group = {r.txid for r in cg.records}
    assert txids_in_group == {_COLLISION_TXID}


# ---------------------------------------------------------------------------
# 4. Verify-by-pubkey-projection (THE headline assertion)
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_collision_recovers_pubkey_on_real_chain_data() -> None:
    """The math: both signatures project to the on-chain pubkey ⇒ VULNERABLE.

    This is the load-bearing claim of Phase 3:
    ``Q = (s * R - z * G) / r mod n``. We compute it for both
    ``(s_a, z_a)`` and ``(s_b, z_b)``; both must match the wallet's known
    public key. The private key ``d`` is *never* materialised — the
    projection happens through ``coincurve`` group ops on libsecp256k1.
    If this assertion ever fails, Phase 3's recovery_detector is broken.
    """
    z_a, z_b = _z_for_each_input()
    recovered = collision_recovers_pubkey(
        r=_R,
        s_a=_S_A,
        z_a=z_a,
        s_b=_S_B,
        z_b=z_b,
        known_pubkey_compressed=_PUBKEY_UNCOMPRESSED,
    )
    assert recovered is True, (
        "verify-by-pubkey-projection failed on a known r-collision — Phase 3 math is broken"
    )


# ---------------------------------------------------------------------------
# 5. Per-signature consistency (and uncompressed-pubkey coercion)
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_each_signature_consistent_with_pubkey() -> None:
    """Each signature alone must project to the known pubkey.

    Also exercises the ``len(known_pubkey_compressed) != 33`` coercion
    branch in ``consistent_with_pubkey`` — the historical tx uses a
    65-byte uncompressed pubkey, which the function must internally
    re-compress through coincurve before comparison.
    """
    z_a, z_b = _z_for_each_input()
    assert consistent_with_pubkey(_R, _S_A, z_a, _PUBKEY_UNCOMPRESSED) is True
    assert consistent_with_pubkey(_R, _S_B, z_b, _PUBKEY_UNCOMPRESSED) is True


# ---------------------------------------------------------------------------
# Bonus: fingerprint determinism
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_fingerprint_is_deterministic_and_public() -> None:
    """The 16-hex fingerprint of this finding is reproducible by any auditor.

    Inputs are all public chain data (pubkey + r + two txids of the same
    tx — vin_index disambiguates). The fingerprint is *not* derived from
    ``d``; it's a domain-separated SHA-256 of public bytes.
    """
    fp = fingerprint(
        pubkey_compressed=_PUBKEY_UNCOMPRESSED,
        r=_R,
        txid_a=_COLLISION_TXID,
        txid_b=_COLLISION_TXID,
    )
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)
    # Identical re-computation must produce identical output.
    fp2 = fingerprint(
        pubkey_compressed=_PUBKEY_UNCOMPRESSED,
        r=_R,
        txid_a=_COLLISION_TXID,
        txid_b=_COLLISION_TXID,
    )
    assert fp == fp2
