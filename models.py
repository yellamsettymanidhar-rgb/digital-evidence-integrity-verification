"""
Data access layer. Every function takes a `db` connection (from
database.get_db()) and does one clear job — this is the layer routes talk to
instead of writing raw SQL inline everywhere.
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------

def create_user(db, username, password, full_name, role):
    password_hash = generate_password_hash(password)
    cur = db.execute(
        "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
        (username, password_hash, full_name, role),
    )
    db.commit()
    return cur.lastrowid


def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def verify_password(db, username, password):
    """Return the user row if credentials are valid and the account is
    active, otherwise None. Never compares plaintext passwords."""
    user = get_user_by_username(db, username)
    if user is None or not user["is_active"]:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def list_users(db):
    return db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()


def username_exists(db, username):
    return db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is not None


def set_user_active(db, user_id, is_active):
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
    db.commit()


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------

def generate_evidence_uid(db):
    """Human-facing ID like EVD-2026-0001, sequential within the current year."""
    year = datetime.now().year
    row = db.execute(
        "SELECT COUNT(*) AS n FROM evidence WHERE evidence_uid LIKE ?", (f"EVD-{year}-%",)
    ).fetchone()
    seq = row["n"] + 1
    return f"EVD-{year}-{seq:04d}"


def create_evidence(db, *, original_filename, stored_filename, file_type, file_size_bytes,
                     sha256_hash, description, case_reference, uploaded_by):
    evidence_uid = generate_evidence_uid(db)
    cur = db.execute(
        """INSERT INTO evidence
           (evidence_uid, original_filename, stored_filename, file_type, file_size_bytes,
            hash_algorithm, sha256_hash, description, case_reference, uploaded_by)
           VALUES (?, ?, ?, ?, ?, 'SHA-256', ?, ?, ?, ?)""",
        (evidence_uid, original_filename, stored_filename, file_type, file_size_bytes,
         sha256_hash, description, case_reference, uploaded_by),
    )
    db.commit()
    return cur.lastrowid, evidence_uid


def get_evidence(db, evidence_id):
    return db.execute(
        """SELECT e.*, u.full_name AS uploaded_by_name, u.username AS uploaded_by_username
           FROM evidence e JOIN users u ON u.id = e.uploaded_by
           WHERE e.id = ?""",
        (evidence_id,),
    ).fetchone()


def list_evidence(db, search=None, status=None, file_type=None):
    query = """SELECT e.*, u.full_name AS uploaded_by_name
               FROM evidence e JOIN users u ON u.id = e.uploaded_by WHERE 1=1"""
    params = []
    if search:
        query += " AND (e.evidence_uid LIKE ? OR e.original_filename LIKE ? OR e.sha256_hash LIKE ?)"
        like = f"%{search}%"
        params += [like, like, like]
    if status:
        query += " AND e.status = ?"
        params.append(status)
    if file_type:
        query += " AND e.file_type = ?"
        params.append(file_type)
    query += " ORDER BY e.uploaded_at DESC"
    return db.execute(query, params).fetchall()


def set_evidence_status(db, evidence_id, status):
    db.execute("UPDATE evidence SET status = ? WHERE id = ?", (status, evidence_id))
    db.commit()


def update_last_verification(db, evidence_id, result):
    db.execute(
        "UPDATE evidence SET last_verified_status = ?, last_verified_at = ? WHERE id = ?",
        (result, _now(), evidence_id),
    )
    db.commit()


def dashboard_stats(db):
    total = db.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
    verified = db.execute(
        "SELECT COUNT(*) AS n FROM evidence WHERE last_verified_status = 'VERIFIED'"
    ).fetchone()["n"]
    compromised = db.execute(
        "SELECT COUNT(*) AS n FROM evidence WHERE last_verified_status = 'COMPROMISED'"
    ).fetchone()["n"]
    unverified = total - verified - compromised
    recent_uploads = db.execute(
        """SELECT e.*, u.full_name AS uploaded_by_name FROM evidence e
           JOIN users u ON u.id = e.uploaded_by
           ORDER BY e.uploaded_at DESC LIMIT 5"""
    ).fetchall()
    recent_verifications = db.execute(
        """SELECT v.*, e.evidence_uid, e.original_filename, u.full_name AS verified_by_name
           FROM verification_logs v
           JOIN evidence e ON e.id = v.evidence_id
           JOIN users u ON u.id = v.verified_by
           ORDER BY v.verified_at DESC LIMIT 5"""
    ).fetchall()
    return {
        "total": total,
        "verified": verified,
        "compromised": compromised,
        "unverified": unverified,
        "recent_uploads": recent_uploads,
        "recent_verifications": recent_verifications,
    }


# ---------------------------------------------------------------------------
# verification_logs
# ---------------------------------------------------------------------------

def create_verification_log(db, *, evidence_id, verified_by, original_hash, current_hash, result, notes=None):
    cur = db.execute(
        """INSERT INTO verification_logs
           (evidence_id, verified_by, original_hash, current_hash, result, notes)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, verified_by, original_hash, current_hash, result, notes),
    )
    db.commit()
    return cur.lastrowid


def list_verification_logs(db, evidence_id=None):
    query = """SELECT v.*, e.evidence_uid, e.original_filename, u.full_name AS verified_by_name
               FROM verification_logs v
               JOIN evidence e ON e.id = v.evidence_id
               JOIN users u ON u.id = v.verified_by"""
    params = []
    if evidence_id:
        query += " WHERE v.evidence_id = ?"
        params.append(evidence_id)
    query += " ORDER BY v.verified_at DESC"
    return db.execute(query, params).fetchall()


def get_verification_log(db, log_id):
    return db.execute(
        """SELECT v.*, e.evidence_uid, e.original_filename, e.file_type, e.file_size_bytes,
                  e.description, e.case_reference, u.full_name AS verified_by_name
           FROM verification_logs v
           JOIN evidence e ON e.id = v.evidence_id
           JOIN users u ON u.id = v.verified_by
           WHERE v.id = ?""",
        (log_id,),
    ).fetchone()


# ---------------------------------------------------------------------------
# audit_logs
# ---------------------------------------------------------------------------

def log_audit(db, *, action, user_id=None, evidence_id=None, details=None, result="SUCCESS", ip_address=None):
    db.execute(
        """INSERT INTO audit_logs (evidence_id, user_id, action, details, result, ip_address)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, user_id, action, details, result, ip_address),
    )
    db.commit()


def list_audit_logs(db, search=None, action=None, result=None):
    query = """SELECT a.*, u.full_name AS user_name, e.evidence_uid
               FROM audit_logs a
               LEFT JOIN users u ON u.id = a.user_id
               LEFT JOIN evidence e ON e.id = a.evidence_id WHERE 1=1"""
    params = []
    if search:
        query += " AND (u.full_name LIKE ? OR e.evidence_uid LIKE ? OR a.details LIKE ?)"
        like = f"%{search}%"
        params += [like, like, like]
    if action:
        query += " AND a.action = ?"
        params.append(action)
    if result:
        query += " AND a.result = ?"
        params.append(result)
    query += " ORDER BY a.timestamp DESC LIMIT 500"
    return db.execute(query, params).fetchall()


# ---------------------------------------------------------------------------
# chain_of_custody
# ---------------------------------------------------------------------------

def add_custody_entry(db, *, evidence_id, user_id, action, remarks=None):
    db.execute(
        """INSERT INTO chain_of_custody (evidence_id, user_id, action, remarks)
           VALUES (?, ?, ?, ?)""",
        (evidence_id, user_id, action, remarks),
    )
    db.commit()


def get_custody_trail(db, evidence_id):
    return db.execute(
        """SELECT c.*, u.full_name AS user_name, u.role
           FROM chain_of_custody c JOIN users u ON u.id = c.user_id
           WHERE c.evidence_id = ? ORDER BY c.timestamp ASC""",
        (evidence_id,),
    ).fetchall()
