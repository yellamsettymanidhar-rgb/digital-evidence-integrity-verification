# EvidenceGuard — Digital Evidence Integrity Verification System

A B.Tech mini-project that lets an investigator register digital evidence
files, generate a SHA-256 cryptographic fingerprint for each one, and later
verify whether a file has been altered since registration — with a full
audit trail and chain-of-custody log behind every action.

> **What this proves, precisely:** a SHA-256 match confirms a file is
> byte-for-byte identical to what was registered — that is *integrity*, not
> absolute authenticity. This system does not, and does not claim to, prove
> where a file originally came from, who authored it, or anything about its
> handling before it was registered here. See **Limitations** below.

---

## 1. Problem Statement

Digital evidence (photos, documents, videos, audio, logs) can be altered —
intentionally or accidentally — at any point after it's collected. Without a
reliable way to detect such changes, evidence loses credibility in an
investigation. Manually comparing files byte-by-byte doesn't scale and
produces nothing you can store, share, or cite later.

## 2. Objectives

- Let an investigator register evidence and immediately capture a
  cryptographic fingerprint (SHA-256) of the exact bytes uploaded.
- Let anyone re-check a file later and get an unambiguous
  **VERIFIED** / **COMPROMISED** answer, with both hashes shown.
- Keep an audit trail of every action taken on every piece of evidence.
- Keep the system honest about what hashing can and cannot prove.

## 3. Existing System vs. Proposed System

**Existing (manual) approach:** investigators rely on file timestamps,
manual notes, or trust, with no cryptographic proof that a file wasn't
altered after collection — and no centralized, timestamped record of who
touched what, when.

**Proposed system:** every evidence file gets a SHA-256 fingerprint at the
moment of registration; that fingerprint is immutable and stored alongside
metadata (uploader, time, case reference). Verification recomputes the hash
on demand and compares it, with the result and both hashes logged
permanently — turning "I think this file is unchanged" into a provable,
auditable claim.

## 4. Methodology

1. Investigator uploads a file → system streams it through SHA-256 while
   saving it under a randomized filename (never trusting the original name).
2. The resulting hash, file metadata, and uploader identity are stored;
   a chain-of-custody entry is written automatically.
3. To verify, the investigator uploads a current copy of the file. The
   system hashes it the same way and compares against the stored hash using
   a constant-time comparison.
4. The result (MATCH/MISMATCH), both hashes, and the verifier's identity are
   logged in `verification_logs`; a broader `audit_logs` entry and a
   `chain_of_custody` entry are also written.
5. A one-page PDF report can be generated from any verification result for
   inclusion in a case file.

## 5. System Architecture

```
Browser (Bootstrap UI)
      │
      ▼
Flask application (app.py)
      │
      ├── routes/auth.py        — login, logout, user management (admin-only)
      ├── routes/dashboard.py   — live statistics
      ├── routes/evidence.py    — upload, list, detail, download, archive
      ├── routes/verify.py      — hash comparison workflow
      ├── routes/audit.py       — audit log + chain-of-custody views
      ├── routes/reports.py     — PDF report generation
      │
      ├── models.py             — data access layer (plain SQL, no ORM)
      ├── database.py           — SQLite connection handling
      ├── utils/hashing.py      — SHA-256 (streamed/chunked)
      ├── utils/security.py     — upload validation, safe filenames, RBAC decorators
      ├── utils/pdf_report.py   — ReportLab report builder
      │
      ▼
SQLite database (database/evidence.db)
      users | evidence | verification_logs | audit_logs | chain_of_custody
```

## 6. Modules

| Module | Responsibility |
|---|---|
| Authentication & RBAC | Session-based login, `admin` / `investigator` roles, no public self-registration |
| Evidence Management | Upload, search/filter, detail view, download, archive |
| Hash Generation | Streamed SHA-256, so large files never load fully into memory |
| Integrity Verification | Recompute + compare hashes, constant-time comparison |
| Audit Log | Every login, upload, view, download, verification, and admin action |
| Chain of Custody | Per-evidence timeline: Registered → Uploaded → Accessed → Verified → Downloaded → Archived |
| Report Generation | One-page PDF per verification, via ReportLab |

## 7. Technologies Used

- **Backend:** Python 3, Flask
- **Database:** SQLite (default) via Python's built-in `sqlite3` — see [Switching to MySQL](#12-switching-to-mysql) to change this
- **Hashing:** `hashlib` (SHA-256), streamed in 64 KB chunks
- **Auth:** Flask sessions + `werkzeug.security` (scrypt password hashing)
- **PDF Reports:** ReportLab
- **Frontend:** HTML, Bootstrap 5, vanilla JS, custom CSS

No AI/ML is used or claimed anywhere in this system — see [AI/ML Note](#13-aiml-note) if your course requires one.

---

## 8. Installation

```bash
# 1. Clone / unzip the project, then move into it
cd evidenceguard

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your environment file
cp .env.example .env
# Open .env and replace SECRET_KEY with a real random value:
python3 -c "import secrets; print(secrets.token_hex(32))"
# paste the output as SECRET_KEY= in .env
```

## 9. Database Setup

```bash
export FLASK_APP=app.py         # Windows (cmd): set FLASK_APP=app.py
flask init-db
```

This creates `database/evidence.db` from `database/schema.sql`. Safe to
re-run — it only creates tables that don't already exist.

## 10. Create Your First Admin Account

```bash
flask create-admin
```

You'll be prompted for a username, full name, and password (min. 8
characters) interactively — no credentials are ever hardcoded in the
source. Once logged in as admin, use **Manage Users** in the sidebar to
create investigator accounts (there is no public self-registration page —
that's a deliberate access-control choice for a forensic tool).

## 11. Run the Project

```bash
flask run
```

Visit **http://127.0.0.1:5000** and log in with the admin account you just created.

## 12. Switching to MySQL

The project ships with SQLite by default (zero server setup — good for a
demo). The SQL in `database/schema.sql` and `models.py` is plain, portable
SQL, so moving to MySQL is mechanical:

1. `pip install pymysql`
2. In `database.py`, replace the `sqlite3.connect(...)` call with a PyMySQL
   connection (host/user/password/db from environment variables).
3. In `database/schema.sql`, change `INTEGER PRIMARY KEY AUTOINCREMENT` to
   `INT AUTO_INCREMENT PRIMARY KEY`, and `DATETIME NOT NULL DEFAULT
   CURRENT_TIMESTAMP` stays valid in MySQL as-is.
4. `row_factory = sqlite3.Row` → use `pymysql.cursors.DictCursor` so
   `row["column"]` access in `models.py` keeps working unchanged.

Everything else — routes, templates, hashing, PDF generation — is
database-agnostic and needs no changes.

## 13. AI/ML Note

**This system does not use or claim to use AI or machine learning.**
SHA-256 hashing is a deterministic cryptographic function, not a trained
model — there's nothing being "learned" or predicted. If your college
specifically requires an AI/ML component for this course, a realistic
*separate* extension would be: a supervised classifier trained on file
metadata/embeddings to flag evidence files that are anomalous in some way
(e.g., unusual file-type-vs-content mismatches), presented clearly as a
complementary, best-effort screening tool — not as something that proves or
disproves integrity. Hashing remains the integrity mechanism either way.

---

## 14. Testing

```bash
python -m unittest discover tests -v
# or, if pytest is installed:
python -m pytest tests/ -v
```

`tests/test_app.py` covers all 12 required scenarios against a real Flask
test client and an isolated temporary database (your real data is never
touched by running tests):

1. Upload valid evidence
2. SHA-256 hash generated correctly (cross-checked against `hashlib` directly)
3. Evidence metadata stored correctly
4. Verifying an unchanged file returns MATCH / "INTEGRITY VERIFIED"
5–6. Modifying a file and re-verifying returns MISMATCH / "INTEGRITY COMPROMISED"
7. Disallowed file types are rejected before storage
8. Oversized files are rejected (HTTP 413)
9. Unauthenticated and under-privileged requests are blocked (302 / 403)
10. Login succeeds/fails correctly; logout ends the session
11. Every key action writes an audit log entry, including failed logins
12. PDF verification report is generated and is a valid PDF

Plus three extra checks: passwords are never stored in plaintext, a
path-traversal filename is neutralized, and chain-of-custody entries are
written on upload.

---

## 15. Demo Script (3 reliable demonstrations)

Use the file at `sample_evidence/case_notes.txt` for a clean, repeatable demo.

**Demo 1 — Register evidence & generate hash**
1. Log in → **Upload Evidence**.
2. Choose `sample_evidence/case_notes.txt`, add a case reference, submit.
3. You land on the evidence detail page showing the Evidence ID and the
   full SHA-256 hash in the mono "evidence tag" box.

**Demo 2 — Verify an unchanged file (should PASS)**
1. **Verify Integrity** → select the evidence you just registered.
2. Upload the *same, untouched* `case_notes.txt` file again.
3. Result page shows a green **✓ INTEGRITY VERIFIED** stamp with both
   hashes identical.

**Demo 3 — Tamper and verify again (should FAIL)**
1. Open `sample_evidence/case_notes.txt` in any text editor, change a
   single character, save it (e.g. as `case_notes_modified.txt` so the
   original stays intact for re-runs).
2. **Verify Integrity** → same evidence record, but upload the modified file.
3. Result page shows a red **✗ INTEGRITY COMPROMISED** stamp — the two
   hashes are highlighted character-by-character where they diverge, making
   the avalanche effect visible.
4. Click **Download PDF Report** to show the generated report.

Tip: run through this once yourself before the real demo so the Evidence ID
numbering (`EVD-2026-0001`, etc.) is what you expect on stage.

---

## 16. Limitations

- This is a project-level chain-of-custody implementation: it proves what
  happened *inside this system* (who uploaded/viewed/verified what, and
  when), not a legally admissible forensic chain of custody, which would
  also require physical evidence handling, tamper-evident storage, and
  procedural/legal controls outside this application's scope.
- A hash match proves the file wasn't altered *after registration*; it says
  nothing about the file's authenticity or origin *before* that point.
- Single-server SQLite by default is fine for a demo/course project, not
  for concurrent multi-investigator production use (see §12 for MySQL).
- There's no encryption at rest for stored evidence files in this version —
  a natural next step (see below).

## 17. Future Enhancements

- Encrypt evidence files at rest; encrypt the database.
- Multi-factor authentication for admin accounts.
- Configurable retention/legal-hold policies per case.
- Exportable, digitally-signed audit log bundles (so the log itself can be
  hash-verified).
- Optional integration with an external timestamping authority (RFC 3161)
  for stronger provenance claims.
- Realistic AI/ML extension: anomaly screening on evidence metadata (see §13).

---

## 18. Project Structure

```
evidenceguard/
├── app.py                  # App factory, CLI commands, error handlers
├── config.py                # Environment-driven configuration
├── database.py               # SQLite connection handling
├── models.py                 # Data access layer
├── requirements.txt
├── .env.example
├── .gitignore
│
├── routes/
│   ├── auth.py               # Login, logout, user management
│   ├── dashboard.py
│   ├── evidence.py           # Upload, list, detail, download, archive
│   ├── verify.py             # Hash verification workflow
│   ├── audit.py               # Audit log + chain of custody
│   └── reports.py             # PDF report generation
│
├── utils/
│   ├── hashing.py             # SHA-256
│   ├── security.py            # Validation, safe filenames, RBAC decorators
│   └── pdf_report.py          # ReportLab report builder
│
├── templates/                 # Jinja2 templates (Bootstrap-based UI)
├── static/css/style.css       # Design system
├── static/js/main.js          # Copy-to-clipboard, hash diff, dropzone, confirms
│
├── database/schema.sql        # Table definitions
├── sample_evidence/           # Demo file(s)
├── tests/test_app.py           # Automated test suite (12 required scenarios)
├── uploads/                    # Stored evidence files (gitignored)
└── reports/                    # Generated PDF reports (gitignored)
```

See `VIVA_QA.md` for a prepared set of viva questions and answers.
#   d i g i t a l - e v i d e n c e - i n t e g r i t y - v e r i f i c a t i o n  
 