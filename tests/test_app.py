"""
Automated tests for the Digital Evidence Integrity Verification System.

Run with:  python -m pytest tests/ -v
       or:  python -m unittest discover tests -v

Each test gets a fresh, isolated SQLite database and upload/report folders
in a temp directory, so running tests never touches your real demo data.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from config import Config
import database
import models


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False


class EvidenceSystemTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        TestConfig.DATABASE_PATH = os.path.join(self.tmp_dir, "test.db")
        TestConfig.UPLOAD_FOLDER = os.path.join(self.tmp_dir, "uploads")
        TestConfig.REPORTS_FOLDER = os.path.join(self.tmp_dir, "reports")
        TestConfig.MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB for oversized-file test

        self.app = create_app(TestConfig)
        self.app.testing = True
        database.init_db(self.app)

        with self.app.app_context():
            db = database.get_db()
            models.create_user(db, "admin_test", "AdminPass123", "Test Admin", "admin")
            models.create_user(db, "investigator_test", "InvestPass123", "Test Investigator", "investigator")

        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------

    def login(self, username="investigator_test", password="InvestPass123"):
        return self.client.post(
            "/login", data={"username": username, "password": password}, follow_redirects=True
        )

    def upload_file(self, content=b"Original evidence content for testing.", filename="evidence.txt", **extra):
        data = {"evidence_file": (io.BytesIO(content), filename)}
        data.update(extra)
        return self.client.post("/evidence/upload", data=data, content_type="multipart/form-data", follow_redirects=True)

    # -- 1. Upload valid evidence --------------------------------------------

    def test_01_upload_valid_evidence(self):
        self.login()
        resp = self.upload_file()
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"registered", resp.data.lower())

    # -- 2. Generate SHA-256 hash ---------------------------------------------

    def test_02_sha256_hash_generated_correctly(self):
        import hashlib
        content = b"Hash verification content."
        self.login()
        self.upload_file(content=content)

        with self.app.app_context():
            db = database.get_db()
            items = models.list_evidence(db)
            stored_hash = items[0]["sha256_hash"]

        expected_hash = hashlib.sha256(content).hexdigest()
        self.assertEqual(stored_hash, expected_hash)
        self.assertEqual(len(stored_hash), 64)

    # -- 3. Store evidence metadata -------------------------------------------

    def test_03_evidence_metadata_stored(self):
        self.login()
        self.upload_file(filename="metadata_test.txt", case_reference="CASE-001", description="Test description")

        with self.app.app_context():
            db = database.get_db()
            item = models.list_evidence(db)[0]

        self.assertEqual(item["original_filename"], "metadata_test.txt")
        self.assertEqual(item["case_reference"], "CASE-001")
        self.assertEqual(item["description"], "Test description")
        self.assertTrue(item["evidence_uid"].startswith("EVD-"))
        self.assertIsNotNone(item["uploaded_at"])

    # -- 4. Verify unchanged evidence (should MATCH) --------------------------

    def test_04_verify_unchanged_evidence(self):
        content = b"Unchanged file content."
        self.login()
        self.upload_file(content=content)

        with self.app.app_context():
            evidence_id = models.list_evidence(database.get_db())[0]["id"]

        resp = self.client.post(
            "/verify/run",
            data={"evidence_id": str(evidence_id), "check_file": (io.BytesIO(content), "evidence.txt")},
            content_type="multipart/form-data", follow_redirects=True,
        )
        self.assertIn(b"INTEGRITY VERIFIED", resp.data)

    # -- 5 & 6. Modify evidence, verify again, detect mismatch ----------------

    def test_05_06_modified_evidence_detected_as_mismatch(self):
        original = b"Content before tampering."
        tampered = b"Content before tamPering."  # one character changed
        self.login()
        self.upload_file(content=original)

        with self.app.app_context():
            evidence_id = models.list_evidence(database.get_db())[0]["id"]

        resp = self.client.post(
            "/verify/run",
            data={"evidence_id": str(evidence_id), "check_file": (io.BytesIO(tampered), "evidence.txt")},
            content_type="multipart/form-data", follow_redirects=True,
        )
        self.assertIn(b"INTEGRITY COMPROMISED", resp.data)

        with self.app.app_context():
            logs = models.list_verification_logs(database.get_db(), evidence_id=evidence_id)
            self.assertEqual(logs[0]["result"], "MISMATCH")
            self.assertNotEqual(logs[0]["original_hash"], logs[0]["current_hash"])

    # -- 7. Invalid file upload (disallowed extension) ------------------------

    def test_07_invalid_file_type_rejected(self):
        self.login()
        resp = self.upload_file(content=b"MZ fake binary", filename="virus.exe")
        self.assertIn(b"not permitted", resp.data.lower())

        with self.app.app_context():
            items = models.list_evidence(database.get_db())
            self.assertEqual(len(items), 0)

    # -- 8. Oversized file ------------------------------------------------------

    def test_08_oversized_file_rejected(self):
        self.login()
        oversized_content = b"X" * (6 * 1024 * 1024)  # 6 MB > 5 MB test limit
        resp = self.client.post(
            "/evidence/upload",
            data={"evidence_file": (io.BytesIO(oversized_content), "huge.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 413)

    # -- 9. Unauthorized access ---------------------------------------------

    def test_09_unauthorized_access_redirects_to_login(self):
        resp = self.client.get("/", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

        resp2 = self.client.get("/evidence/", follow_redirects=False)
        self.assertEqual(resp2.status_code, 302)

    def test_09b_investigator_cannot_access_admin_routes(self):
        self.login()
        resp = self.client.get("/users")
        self.assertEqual(resp.status_code, 403)

    # -- 10. Login / logout ---------------------------------------------------

    def test_10_login_logout(self):
        resp = self.login()
        self.assertIn(b"Welcome back", resp.data)

        resp_logout = self.client.get("/logout", follow_redirects=True)
        self.assertIn(b"logged out", resp_logout.data.lower())

        resp_after = self.client.get("/", follow_redirects=False)
        self.assertEqual(resp_after.status_code, 302)

        resp_bad = self.client.post(
            "/login", data={"username": "investigator_test", "password": "WrongPassword"}, follow_redirects=True
        )
        self.assertIn(b"Invalid username or password", resp_bad.data)

    # -- 11. Audit log creation -------------------------------------------------

    def test_11_audit_log_created_for_actions(self):
        self.login()
        self.upload_file()

        with self.app.app_context():
            db = database.get_db()
            logs = models.list_audit_logs(db, action="EVIDENCE_UPLOADED")
            self.assertEqual(len(logs), 1)

            login_logs = models.list_audit_logs(db, action="LOGIN")
            self.assertGreaterEqual(len(login_logs), 1)

    def test_11b_failed_login_is_audited(self):
        self.client.post("/login", data={"username": "investigator_test", "password": "wrong"}, follow_redirects=True)
        with self.app.app_context():
            db = database.get_db()
            logs = models.list_audit_logs(db, action="LOGIN_FAILED")
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]["result"], "FAILURE")

    # -- 12. Report generation ---------------------------------------------------

    def test_12_pdf_report_generated(self):
        content = b"Report generation test content."
        self.login()
        self.upload_file(content=content)

        with self.app.app_context():
            evidence_id = models.list_evidence(database.get_db())[0]["id"]

        self.client.post(
            "/verify/run",
            data={"evidence_id": str(evidence_id), "check_file": (io.BytesIO(content), "evidence.txt")},
            content_type="multipart/form-data",
        )

        with self.app.app_context():
            log_id = models.list_verification_logs(database.get_db())[0]["id"]

        resp = self.client.get(f"/reports/verification/{log_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "application/pdf")
        self.assertTrue(resp.data.startswith(b"%PDF"))

    # -- extra: password never stored in plaintext ----------------------------

    def test_13_passwords_are_hashed_not_plaintext(self):
        with self.app.app_context():
            db = database.get_db()
            user = models.get_user_by_username(db, "admin_test")
            self.assertNotIn("AdminPass123", user["password_hash"])
            self.assertTrue(
                user["password_hash"].startswith("scrypt:") or user["password_hash"].startswith("pbkdf2:")
            )

    # -- extra: path traversal in filename is neutralised ----------------------

    def test_14_path_traversal_filename_neutralised(self):
        self.login()
        self.upload_file(content=b"traversal test", filename="../../../etc/passwd.txt")
        with self.app.app_context():
            item = models.list_evidence(database.get_db())[0]
            self.assertNotIn("..", item["stored_filename"])
            self.assertNotIn("/", item["stored_filename"])

    # -- extra: chain of custody entries recorded ------------------------------

    def test_15_chain_of_custody_recorded(self):
        self.login()
        self.upload_file()
        with self.app.app_context():
            db = database.get_db()
            evidence_id = models.list_evidence(db)[0]["id"]
            trail = models.get_custody_trail(db, evidence_id)
            actions = [t["action"] for t in trail]
        self.assertIn("Registered", actions)
        self.assertIn("Uploaded", actions)


if __name__ == "__main__":
    unittest.main()
