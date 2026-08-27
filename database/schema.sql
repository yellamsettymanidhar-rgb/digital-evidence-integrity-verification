-- ============================================================================
-- Digital Evidence Integrity Verification System — Database Schema
-- ============================================================================
-- Written in portable SQL (SQLite by default). To port to MySQL, see the
-- notes in README.md — the main changes are AUTOINCREMENT -> AUTO_INCREMENT
-- and DATETIME defaults, everything else is standard SQL and unchanged.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- users: system accounts. Two roles — admin (manages users, can archive
-- evidence) and investigator (uploads/verifies evidence, read-only on users).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,          -- werkzeug generate_password_hash output, never plaintext
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'investigator')),
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       INTEGER NOT NULL DEFAULT 1
);

-- ----------------------------------------------------------------------------
-- evidence: one row per uploaded evidence file. sha256_hash is the ORIGINAL
-- hash captured at registration time and is never overwritten — that
-- immutability is what makes later verification meaningful.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_uid        TEXT NOT NULL UNIQUE,     -- human-facing ID, e.g. EVD-2026-0001
    original_filename   TEXT NOT NULL,
    stored_filename      TEXT NOT NULL UNIQUE,     -- randomized name on disk (prevents path traversal / collisions)
    file_type           TEXT NOT NULL,
    file_size_bytes     INTEGER NOT NULL,
    hash_algorithm      TEXT NOT NULL DEFAULT 'SHA-256',
    sha256_hash         TEXT NOT NULL,             -- original hash at registration, immutable
    description         TEXT,
    case_reference       TEXT,
    uploaded_by          INTEGER NOT NULL,
    uploaded_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    last_verified_status TEXT CHECK (last_verified_status IN ('VERIFIED', 'COMPROMISED', NULL)),
    last_verified_at     DATETIME,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_uid ON evidence(evidence_uid);

-- ----------------------------------------------------------------------------
-- verification_logs: every time someone runs an integrity check, one row
-- is written here — regardless of whether it passed or failed.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER NOT NULL,
    verified_by     INTEGER NOT NULL,
    original_hash   TEXT NOT NULL,
    current_hash    TEXT NOT NULL,
    result          TEXT NOT NULL CHECK (result IN ('MATCH', 'MISMATCH')),
    verified_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes           TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (verified_by) REFERENCES users(id)
);

-- ----------------------------------------------------------------------------
-- audit_logs: system-wide action trail (login, upload, verify, download,
-- archive, user management, failed access attempts). Broader than
-- verification_logs, which is specifically about hash checks.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER,                       -- nullable: some actions (e.g. login) aren't evidence-specific
    user_id         INTEGER,
    action          TEXT NOT NULL,
    details         TEXT,
    result          TEXT NOT NULL DEFAULT 'SUCCESS' CHECK (result IN ('SUCCESS', 'FAILURE')),
    ip_address      TEXT,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ----------------------------------------------------------------------------
-- chain_of_custody: narrative timeline per evidence item. Project-level
-- implementation — see README "Limitations" for what this is NOT.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER NOT NULL,
    user_id         INTEGER NOT NULL,
    action          TEXT NOT NULL,   -- Registered / Uploaded / Accessed / Verified / Downloaded / Archived
    remarks         TEXT,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_audit_evidence ON audit_logs(evidence_id);
