-- wallet-self-audit per-audit cache schema (Phase 6)
--
-- One SQLite file per audit, located at:
--   ~/.local/share/wsa/audits/<audit_id>/cache.db
--
-- Schema is hand-rolled (PRAGMA user_version) rather than alembic to keep
-- the install footprint small. Migrations live in storage/db.py.

PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS audits (
    audit_id            TEXT PRIMARY KEY,
    address             TEXT NOT NULL,
    started_at          INTEGER NOT NULL,
    finished_at         INTEGER,
    toolkit_version     TEXT NOT NULL,
    ownership_proof_hash TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('running','safe','suspicious','vulnerable','error'))
);

CREATE TABLE IF NOT EXISTS transactions (
    txid         TEXT PRIMARY KEY,
    block_height INTEGER,
    raw_hex      BLOB,
    fetched_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signatures (
    txid         TEXT NOT NULL,
    vin_index    INTEGER NOT NULL,
    pubkey_hex   TEXT NOT NULL,
    r            BLOB NOT NULL,        -- 32 bytes
    s            BLOB NOT NULL,        -- 32 bytes
    z            BLOB,
    sighash_type INTEGER NOT NULL,
    script_type  TEXT NOT NULL,
    PRIMARY KEY (txid, vin_index),
    FOREIGN KEY (txid) REFERENCES transactions(txid)
) WITHOUT ROWID;

-- Hot path: r-collision detection scans this index, not the table.
CREATE INDEX IF NOT EXISTS idx_sig_pubkey_r ON signatures(pubkey_hex, r);

CREATE TABLE IF NOT EXISTS address_pubkeys (
    address          TEXT NOT NULL,
    pubkey_hex       TEXT NOT NULL,
    first_seen_txid  TEXT NOT NULL,
    PRIMARY KEY (address, pubkey_hex)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS findings (
    finding_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id        TEXT NOT NULL REFERENCES audits(audit_id) ON DELETE CASCADE,
    severity        TEXT NOT NULL,
    kind            TEXT NOT NULL,
    pubkey_hex      TEXT,
    payload_json    TEXT NOT NULL
);
